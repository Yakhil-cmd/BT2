### Title
Null pointer dereference (crash) when processing a unit with `app: "definition"` and a non-inline payload - ([File: network.js])

### Summary
`getAllAuthorsAndOutputAddresses()` in `network.js` dereferences `message.payload.definition` for any message whose `app` is `"definition"` without first checking that `payload` is defined, unlike the sibling `"payment"` branch which explicitly guards with `payload &&`. A message of app `"definition"` can be posted with `payload_location: "none"` (payload omitted), which passes unit validation without ever invoking the payload-shape checks for that app, then crashes any node that later calls this function on the accepted unit.

### Finding Description
`network.js` builds the set of addresses affected by a unit like this: [1](#0-0) 

Note the asymmetry: the `"payment"` branch is guarded with `payload &&`, but the `"definition"` branch (`payload.definition[1].base_aa`) is not guarded at all.

In `validation.js`, whether the `"definition"` payload is validated at all depends entirely on `payload_location`. The payload-shape checks (including the `case "definition":` handler that requires a non-empty object payload) live inside `validateInlinePayload`, which is only reached when `payload_location === "inline"`: [2](#0-1) [3](#0-2) 

Earlier, generic per-message checks only require a valid `payload_hash` length and, for non-inline locations, that no `payload` field is present at all — they never restrict which `app` values may use `payload_location: "none"`: [4](#0-3) 

So a unit poster can craft a message `{ app: "definition", payload_location: "none", payload_hash: <any 44-char base64> }` with no `payload` field. This message never reaches the `case "definition":` validator (which requires `isNonemptyObject(payload)`), so it sails through `validateMessage`/`validateMessages` unrejected as long as some other message in the unit satisfies the "must have a base payment message" requirement.

Once such a unit is accepted (or even just received/forwarded as a joint, since `getAllAuthorsAndOutputAddresses` operates on `objJoint.unit` after acceptance), any code path that calls `getAllAuthorsAndOutputAddresses`/`notifyWatchers` on it — e.g. after saving/forwarding a newly posted unit — will execute `payload.definition[1].base_aa` where `payload` is `undefined`, throwing an uncaught `TypeError: Cannot read properties of undefined (reading 'definition')`.

### Impact Explanation
This is a synchronous, unhandled `TypeError` triggered by processing an ordinary, syntactically-accepted unit content. Because there is no surrounding try/catch on this call path, the exception propagates as an uncaught exception, which in Node.js by default crashes the whole process. Any node (hub, full node, or peer) that reaches this code while handling a unit posted by an unprivileged party is taken down, matching the "node unable to confirm new units" / DoS impact class analogous to the reported HTTP/2 fuzzing null-pointer crash.

### Likelihood Explanation
The trigger requires only a single, unprivileged unit post: attacker needs to include one message with `app: "definition"` and `payload_location: "none"` (and a syntactically valid, arbitrary `payload_hash`) alongside a normal base payment message to satisfy `bHasBasePayment`. No special role, no AA execution, no light/hub-only trust boundary is needed. The bug is purely a missing null-check that is trivially reachable via crafted but otherwise well-formed unit content.

### Recommendation
Add the same defensive guard used for the `"payment"` case to the `"definition"` branch in `getAllAuthorsAndOutputAddresses`, e.g. change the condition to `message.app === 'definition' && payload && payload.definition && payload.definition[1] && payload.definition[1].base_aa`. Additionally, consider rejecting `app: "definition"` messages with `payload_location !== "inline"` at validation time (since a definition-app message with no payload has no semantic meaning) to close off any other place in the codebase that may assume `payload.definition` is present whenever `app === "definition"`.

### Proof of Concept
1. Craft a unit with two messages:
   - message 1: `{ app: "payment", payload_location: "inline", payload: { outputs: [...], inputs: [...] }, payload_hash: <correct hash> }` (normal valid payment, to satisfy base-payment requirement).
   - message 2: `{ app: "definition", payload_location: "none", payload_hash: "<any 44-char base64 string>" }` — no `payload` field.
2. Sign and post this unit as a normal, unprivileged unit poster.
3. `validateMessage` accepts message 2 without ever calling the `case "definition":` handler (it is bypassed because `payload_location !== "inline"`), so the unit passes validation and is broadcast/saved.
4. When any node subsequently invokes `getAllAuthorsAndOutputAddresses(objUnit)` (e.g., via `notifyWatchers`) on this unit, `message.payload` is `undefined` for message 2, and `payload.definition[1].base_aa` throws `TypeError: Cannot read properties of undefined (reading 'definition')`, crashing the process.

### Citations

**File:** network.js (L1691-1703)
```javascript
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

**File:** validation.js (L1707-1711)
```javascript
function validateInlinePayload(conn, objMessage, message_index, objUnit, objValidationState, callback){
	var payload = objMessage.payload;
	if (typeof payload === "undefined")
		return callback("no inline payload");

```

**File:** validation.js (L1747-1758)
```javascript
		case "definition": // for AAs only
			if (!isNonemptyObject(payload))
				return callback("payload must be a non empty object");
			if (hasFieldsExcept(payload, ["address", "definition"])) // AA definition cannot be changed and its address is also its definition_chash
				return callback("unknown fields in app definition");
			try{
				if (payload.address !== objectHash.getChash160(payload.definition))
					return callback("definition doesn't match the chash");
			}
			catch(e){
				return callback("bad definition");
			}
```
