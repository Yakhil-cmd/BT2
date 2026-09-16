### Title
Null-dereference DoS in `getAllAuthorsAndOutputAddresses()` via `definition` message with non-inline payload - ([File: network.js])

### Summary
`network.js`'s `getAllAuthorsAndOutputAddresses()` dereferences `message.payload.definition` for `app === 'definition'` messages without first checking that `payload` is truthy, mirroring the radare2 `bin_dyldcache.c` `load()` bug class (CVE-2025-63744) where a crafted structure is processed without a required null check before pointer dereference, crashing the process. Here, a normal unit author can post a valid, fully-signed unit whose `definition` message uses `payload_location: "none"` (payload omitted, only `payload_hash` present) — legal per `validate()` — and get an unhandled `TypeError` when the unit is processed for watcher notifications, crashing the whole node process via the global `uncaughtException` re-throw.

### Finding Description
In `validate()`, for any message whose `payload_location` is not `"inline"`, `payload` is required to be **absent**: [1](#0-0) 
This applies uniformly to all `app` values, including `"definition"` — there is no special-case requirement that a `definition` message must carry an inline payload. Consequently, a unit with a message like `{ app: "definition", payload_location: "none", payload_hash: <44-char base64> }` passes joint-level structural validation; the app-specific inline-payload checks in `validateInlinePayload` are only invoked when a payload is actually present.

Later, when the unit is accepted/saved and broadcast, `notifyWatchers()` calls `getAllAuthorsAndOutputAddresses(objUnit)`: [2](#0-1) 
Note line 1693-1701: `var payload = message.payload;` is used unguarded for `app === 'definition'`:
```
else if (message.app === 'definition' && payload.definition[1].base_aa)
```
Unlike the `payment` branch just above it (which explicitly checks `payload` truthiness: `if (message.app === "payment" && payload) {...}`), the `definition` branch dereferences `payload.definition` directly. If `payload` is `undefined` (payload_location `"none"`/`"uri"`), this throws `TypeError: Cannot read properties of undefined (reading 'definition')`.

This exception is not caught anywhere in the synchronous call chain from unit processing to `notifyWatchers`, so it propagates to Node's global handler: [3](#0-2) 
which explicitly re-throws (`throw err; // crash the process to avoid ending up in an inconsistent state`), terminating the entire node process — full nodes and hubs alike, since `notifyWatchers` runs on every newly processed/broadcast unit.

### Impact Explanation
Any single unprivileged unit poster can craft and broadcast a unit containing a `definition`-app message with `payload_location` set to `"none"` or `"uri"` (no inline payload). Once this unit reaches a node's `notifyWatchers` path (triggered for units affecting watched addresses, which is broad), the node crashes. This is a network-wide availability impact: repeated posting of such units can be used to crash any full node/hub processing them, preventing the network from confirming new units — matching the "Accept" criteria of "a network unable to confirm new units."

### Likelihood Explanation
Likelihood is high: constructing a unit with a non-payment `payload_location: "none"` message requires no special privilege — any author with byte balance can build and sign such a unit, since the joint/unit structural validation explicitly permits omitting `payload` for non-inline `payload_location`. No malicious peer, hub, or catchup/sync-specific behavior is required — a normally validated, ordinary posted unit suffices.

### Recommendation
Guard the `definition` branch in `getAllAuthorsAndOutputAddresses()` the same way the `payment` branch is guarded, e.g.:
```js
else if (message.app === 'definition' && payload && payload.definition && payload.definition[1] && payload.definition[1].base_aa)
```
Audit other call sites that assume `message.payload` is always present for a given `app` (especially any that skip the payment branch's existing null-check pattern) and add equivalent guards.

### Proof of Concept
1. Author a unit with `authors`, valid signature, a valid base payment message, and an additional message:
```json
{
  "app": "definition",
  "payload_location": "none",
  "payload_hash": "<44-char valid base64 hash of some payload never disclosed>"
}
```
2. Ensure `payload_commission`/hashes match (no `payload` field present, consistent with `payload_location: "none"`), and unit passes `validate()` (per `validation.js:220-233`, no `payload` is required for non-inline location — including for `definition`).
3. Broadcast/post this unit to a full node.
4. When the node processes the unit and calls `notifyWatchers(objJoint, ...)` → `getAllAuthorsAndOutputAddresses(objUnit)`, the `definition` branch executes `payload.definition[1].base_aa` with `payload === undefined`, throwing a `TypeError`.
5. The uncaught exception hits `process.on('uncaughtException', ...)` in `network.js:4530-4543`, which re-throws, crashing the node process.

### Citations

**File:** validation.js (L220-233)
```javascript
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

**File:** network.js (L1685-1711)
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
	var arrAddresses = _.union(arrAuthorAddresses, arrOutputAddresses, arrBaseAAAddresses);
	return {
		author_addresses: arrAuthorAddresses,
		output_addresses: arrOutputAddresses,
		base_aa_addresses: arrBaseAAAddresses,
		addresses: arrAddresses,
	};
}
```

**File:** network.js (L4530-4543)
```javascript
process.on('uncaughtException', (err) => {
	console.log('Uncaught exception:', err);
	console.error('Uncaught exception:', err);
	if (!conf.bLight) {
		let hosts = [...Object.keys(messagesInWork), ...Object.keys(requestsInWork)];
		if (currentJointHost)
			hosts.push(currentJointHost);
		console.log('Clients with pending requests/messages at the time of uncaught exception:', hosts);
		const fs = require('fs');
		const app_data_dir = require('./desktop_app.js').getAppDataDir();
		fs.writeFileSync(`${app_data_dir}/uncaught_exception_clients.txt`, hosts.concat(Object.keys(assocBlockedPeers)).join('\n'), 'utf8');
	}
	throw err; // crash the process to avoid ending up in an inconsistent state
});
```
