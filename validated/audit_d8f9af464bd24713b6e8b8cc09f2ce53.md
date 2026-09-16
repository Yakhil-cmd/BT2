### Title
Null Pointer Dereference in `getAllAuthorsAndOutputAddresses` via Missing-Payload `definition` Message - (File: network.js)

### Summary
`network.js` builds the set of addresses to notify about a newly broadcast unit by calling `getAllAuthorsAndOutputAddresses(objUnit)`. For `payment` messages the code explicitly checks that `payload` is truthy before dereferencing it, but for `definition` messages it does not, unconditionally accessing `payload.definition[1].base_aa`. An ordinary, unprivileged unit poster can create a unit containing a `definition` message whose `payload_location` is not `"inline"` (e.g. `"none"` or `"uri"`), which leaves `message.payload` `undefined` on the object that reaches this function after validation/storage. This is directly analogous to CVE-2016-2198 (QEMU EHCI), where writing to a register whose backing structure pointer was never initialized/validated caused a null pointer dereference and process crash — here, an unvalidated-for-null `payload` field triggers the same crash pattern in unit-processing code reachable from any posted unit.

### Finding Description
In `network.js`, the helper that computes addresses affected by a unit is: [1](#0-0) 

Note line 1694 guards the `payment` branch with `payload` truthiness (`message.app === "payment" && payload`), but the `else if` branch for `definition` messages has no such guard:
```
else if (message.app === 'definition' && payload.definition[1].base_aa)
```
If `payload` is `undefined` (e.g., a `definition` message posted with `payload_location: "uri"` or `"none"`, or any state where the message's inline payload was not populated), this line throws a `TypeError: Cannot read properties of undefined (reading 'definition')`.

This function is called unconditionally from `notifyWatchers`, which runs for every newly accepted/relayed unit: [2](#0-1) 

`validateInlinePayload`/`validateMessage` in `validation.js` validate the *content* of an inline `definition` payload when present, but the general message-level check only requires `payload_location` to be one of `"inline"`, `"none"`, `"uri"` and, for non-inline messages, that `payload` be absent — there is no per-app restriction forcing `definition` messages to be `inline`-only: [3](#0-2) 

Since `app` values are validated against a fixed name list but `payload_location` is generic across all apps, an attacker can post/relay a unit with `{app: "definition", payload_location: "uri", payload_hash: <valid-hash>}` (no `payload` key), which passes payload-hash/format validation for non-inline messages, gets accepted, and then crashes any node's `notifyWatchers` path when it processes/relays the unit.

### Impact Explanation
Triggering the null-property-access crashes the Node.js process (unhandled `TypeError` thrown synchronously inside a `db.query` callback / event-emission chain), taking down the node instance. If propagated across the network via ordinary relaying of a validly-hashed unit, multiple/most full nodes processing this unit would crash in the same code path, degrading network availability and confirmation of new units — the same denial-of-service outcome as the QEMU EHCI null-pointer analog (crash of the emulator process on an application-triggerable write).

### Likelihood Explanation
Any unprivileged actor able to post a unit (author of a serial unit) can include a `definition` message with `payload_location` set to `"none"` or `"uri"` while leaving `payload` absent — this requires no special privilege, hub/peer collusion, or race condition, and the payload-hash checks for non-inline messages do not require the payload to exist locally. This makes the crash trivially and repeatably reachable through the standard unit validation and relay code path.

### Recommendation
Add the same defensive check used for `payment` messages to the `definition` branch in `getAllAuthorsAndOutputAddresses`, e.g.:
```
else if (message.app === 'definition' && payload && payload.definition && payload.definition[1] && payload.definition[1].base_aa)
```
Additionally, consider validating in `validation.js` that `definition` messages must always use `payload_location: "inline"`, closing off the possibility of a `definition` message reaching downstream processing without a `payload`.

### Proof of Concept
1. Construct a unit with a message: `{ app: "definition", payload_location: "uri", payload_hash: "<valid 44-char base64 hash>" }` (omit `payload`), correctly signed/hashed so it passes `validate()` in `validation.js`.
2. Broadcast/relay the unit so it is accepted and processed by `network.js`.
3. When `notifyWatchers(objJoint, ...)` is invoked for the accepted unit, `getAllAuthorsAndOutputAddresses` iterates the messages; for the `definition` message, `payload` is `undefined`, and `payload.definition[1].base_aa` throws `TypeError`, crashing the node process.

### Citations

**File:** network.js (L1685-1703)
```javascript
function getAllAuthorsAndOutputAddresses(objUnit){
	var arrAuthorAddresses = objUnit.authors.map(function(author){ return author.address; });
	if (!objUnit.messages) // voided unit
		return null;
	var arrOutputAddresses = [];
	var arrBaseAAAddresses = [];
	for (var i=0; i<objUnit.messages.length; i++){
		var message = objUnit.messages[i];
		var payload = message.payload;
		if (message.app === "payment" && payload) {
			for (var j = 0; j < payload.outputs.length; j++) {
				var address = payload.outputs[j].address;
				if (arrOutputAddresses.indexOf(address) === -1)
					arrOutputAddresses.push(address);
			}
		}
		else if (message.app === 'definition' && payload.definition[1].base_aa)
			arrBaseAAAddresses.push(payload.definition[1].base_aa);
	}
```

**File:** network.js (L1713-1721)
```javascript
// if any of the watched addresses are affected, notifies:  1. own UI  2. light clients
function notifyWatchers(objJoint, bGoodSequence, source_ws){
	var bAA = objJoint.new_aa;
	delete objJoint.new_aa;
	var objUnit = objJoint.unit;
	var objAddresses = getAllAuthorsAndOutputAddresses(objUnit);
	if (!objAddresses) // voided unit
		return;
	var arrAddresses = objAddresses.addresses;
```

**File:** validation.js (L219-233)
```javascript
		// validate payload hashes early to make sure payloads were not tampered with
		for (let m of objUnit.messages) {
			if (typeof m.payload_location !== "string")
				return callbacks.ifUnitError("bad payload_location");
			if (!["inline", "none", "uri"].includes(m.payload_location))
				return callbacks.ifUnitError("invalid payload_location: " + m.payload_location);
			if (!isStringOfLength(m.payload_hash, constants.HASH_LENGTH))
				return callbacks.ifUnitError("wrong payload hash size");
			if (m.payload_location !== "inline") {
				if ("payload" in m)
					return callbacks.ifJointError("payload must be absent when payload_location is not inline");
				continue;
			};
			if (!("payload" in m) || m.payload === null)
				return callbacks.ifJointError("missing payload");
```
