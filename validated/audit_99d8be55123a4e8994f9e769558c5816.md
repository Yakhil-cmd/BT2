### Title
Null pointer dereference / crash on `private_payment` message missing `payload` field - ([File: network.js])

### Summary
`handleOnlinePrivatePayment()` in `network.js` dereferences `arrPrivateElements[0].payload.denomination` before verifying that `payload` exists on the element, mirroring the libsoup CVE-2025-32912 pattern where an expected protocol field ("nonce"/here "payload") is assumed present and accessed unconditionally, causing a crash.

### Finding Description
`handleOnlinePrivatePayment` is invoked when a peer (a private-payment counterparty, an explicitly in-scope actor) sends a `private_payment` justsaying/message containing `arrPrivateElements`. The only validation performed before touching the element's contents is that the array itself is non-empty: [1](#0-0) 

```
function handleOnlinePrivatePayment(ws, arrPrivateElements, bViaHub, callbacks){
	if (!ValidationUtils.isNonemptyArray(arrPrivateElements))
		return callbacks.ifError("private_payment content must be non-empty array");
	
	var unit = arrPrivateElements[0].unit;
	var message_index = arrPrivateElements[0].message_index;
	var output_index = arrPrivateElements[0].payload.denomination ? arrPrivateElements[0].output_index : -1;
```

There is no check that `arrPrivateElements[0].payload` is a non-empty object (unlike the stricter validation performed elsewhere for the same kind of data, e.g. `handlePrivatePaymentChains` in `wallet.js`, which explicitly requires `isNonemptyObject(e.payload)` for every chain element before use). If an attacker sends an element such as `{unit: "<44-char base64>", message_index: 0}` with no `payload` property at all, `arrPrivateElements[0].payload` is `undefined`, and accessing `.denomination` on it throws `TypeError: Cannot read properties of undefined (reading 'denomination')`.

This is precisely the bug class described in the external report: the client (here, the ocore full node) trusts a peer-supplied structure to contain an expected sub-field and dereferences it without a presence check, causing an uncaught exception rather than validation returning a graceful error.

Because this happens inside the network message-handling call stack (not wrapped by a try/catch that converts it into a `callbacks.ifError`), the exception propagates as an uncaught exception. The application installs a global handler that deliberately re-throws to crash the process: [2](#0-1) 

```
process.on('uncaughtException', (err) => {
	console.log('Uncaught exception:', err);
	console.error('Uncaught exception:', err);
	...
	throw err; // crash the process to avoid ending up in an inconsistent state
});
```

So a single malformed `private_payment` message from a counterparty (or hub-relayed) crashes the receiving node's process.

### Impact Explanation
A node (full node or wallet) receiving a single, trivially malformed `private_payment` message from any private-payment counterparty (or via the hub) crashes its entire process. This is a remotely triggerable, unauthenticated (no signature/validation required before the crash point) denial-of-service against any wallet or node that processes private payments, satisfying the "network unable to confirm new units" / node-disagreement class of impact if repeated against multiple nodes, and directly disables the victim's ability to operate (process crash) — analogous in severity to the libsoup DoS.

### Likelihood Explanation
Likelihood is high: the attacker only needs to be a correspondent capable of sending a private payment (a normal, low-privilege interaction pattern in Obyte — pairing with any wallet is sufficient to become a "private-payment counterparty"), and the payload requires no valid signatures, hashes, or prior state — just an object lacking the `payload` field. No proof-of-work, no waiting for stabilization, and no special network position is required.

### Recommendation
Add an explicit structural check before touching `arrPrivateElements[0].payload`, e.g.:
```js
if (!ValidationUtils.isNonemptyObject(arrPrivateElements[0].payload))
    return callbacks.ifError("no payload in private element");
```
placed immediately after the `isNonemptyArray` check and before line 2382, mirroring the stricter checks already used in `wallet.js`'s `handlePrivatePaymentChains`. More generally, wrap network message dispatch (or at minimum this handler) in try/catch that reports `ifError` instead of letting exceptions propagate to `uncaughtException`.

### Proof of Concept
1. Pair with (or otherwise become a correspondent of) a target wallet/node so it will accept `private_payment` justsayings from you.
2. Send a `private_payment` justsaying with body:
```json
[
  { "unit": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "message_index": 0 }
]
```
(note: no `payload` field at all).
3. On the target, `handleOnlinePrivatePayment` executes `arrPrivateElements[0].payload.denomination`, throwing `TypeError: Cannot read properties of undefined (reading 'denomination')`.
4. The exception is not caught along this call path, reaches the global `uncaughtException` handler in `network.js`, which re-throws, crashing the node process.

### Citations

**File:** network.js (L2376-2388)
```javascript
function handleOnlinePrivatePayment(ws, arrPrivateElements, bViaHub, callbacks){
	if (!ValidationUtils.isNonemptyArray(arrPrivateElements))
		return callbacks.ifError("private_payment content must be non-empty array");
	
	var unit = arrPrivateElements[0].unit;
	var message_index = arrPrivateElements[0].message_index;
	var output_index = arrPrivateElements[0].payload.denomination ? arrPrivateElements[0].output_index : -1;
	if (!ValidationUtils.isValidBase64(unit, constants.HASH_LENGTH))
		return callbacks.ifError("invalid unit");
	if (!ValidationUtils.isNonnegativeInteger(message_index))
		return callbacks.ifError("invalid message_index");
	if (!(ValidationUtils.isNonnegativeInteger(output_index) || output_index === -1))
		return callbacks.ifError("invalid output_index");
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
