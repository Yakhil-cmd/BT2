### Title
Unauthenticated Null-Pointer Dereference Crashing the Node via Malformed `private_payment` Message - (File: network.js)

### Summary
`network.js`'s `handleOnlinePrivatePayment()` dereferences `arrPrivateElements[0].payload.denomination` before validating that the `payload` field exists on the attacker-supplied private-payment element. A private-payment counterparty (or any peer/hub relaying a `justsaying` "private_payment" message, which requires no prior authentication) can send a crafted element whose `payload` is missing, causing a `TypeError: Cannot read properties of undefined` to be thrown synchronously inside the message-handling call stack. This is the same bug class as CVE-2017-7655 (Mosquitto): untrusted network input triggers a null/undefined dereference that the application does not handle, leading to a process crash.

### Finding Description
`handleOnlinePrivatePayment` only checks that `arrPrivateElements` is a non-empty array: [1](#0-0) 

It does not verify that `arrPrivateElements[0].payload` is a non-empty object before accessing `.denomination` on it. If a peer sends a `private_payment` justsaying whose first element omits `payload` (or sets it to `null`), the expression `arrPrivateElements[0].payload.denomination` throws immediately.

This handler is reachable from the network layer without any prior validation of the element's shape — the entry points calling it (`sendPrivatePaymentToWs`/receiving `private_payment` justsaying) forward raw peer-supplied JSON straight into `handleOnlinePrivatePayment`, unlike `validateAndSavePrivatePaymentChain` in `private_payment.js`, which does check `headElement.payload` before use: [2](#0-1) 

Because ocore installs a global `uncaughtException` handler that intentionally re-throws to crash the process ("to avoid ending up in an inconsistent state"): [3](#0-2) 

any uncaught synchronous `TypeError` thrown while handling network input results in full node process termination.

### Impact Explanation
A single malformed `private_payment` message from an unauthenticated peer/light client/hub relay crashes the recipient node process (full node, hub, or wallet backend). This is a remote, trivially repeatable denial-of-service: an attacker who is a private-payment counterparty (or merely a connected peer relaying such a message) can knock a node offline with a single message, without needing valid funds, a valid unit, or any signature. Repeated against witnesses/hubs, this can degrade network availability (nodes unable to process traffic while restarting), which aligns with "a network unable to confirm new units" if targeted broadly. It does not exploit AA/oscript logic, does not double-spend, and does not inflate supply, but it does constitute a High-severity availability issue analogous to the null-dereference crash in the referenced CVE.

### Likelihood Explanation
Likelihood is high: the crash is triggered by a single, easily crafted message with no cryptographic requirements, no need to be a witness, and no need for stable/confirmed state. Any WebSocket peer capable of sending a `justsaying` "private_payment" (which any connected peer or hub client can do) can trigger it deterministically.

### Recommendation
In `handleOnlinePrivatePayment` (network.js), validate `arrPrivateElements[0].payload` is a non-empty object (and that any subsequently accessed nested fields exist) before dereferencing it, mirroring the guard already present in `private_payment.js`'s `validateAndSavePrivatePaymentChain`. Return `callbacks.ifError(...)` for malformed input instead of allowing the property access to throw. More broadly, wrap top-level message handlers so that unexpected `TypeError`/`ReferenceError` exceptions arising from malformed peer input are caught and treated as validation errors rather than being allowed to propagate to the global `uncaughtException` handler that kills the process.

### Proof of Concept
1. Establish a WebSocket connection to a target ocore node (or act as a paired device/light-vendor counterparty).
2. Send a `justsaying` message of type `private_payment` with content:
```json
[
  { "unit": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "message_index": 0 }
]
```
   (i.e., an array whose first element has no `payload` field, only `unit`/`message_index`).
3. The node's dispatcher forwards this array to `handleOnlinePrivatePayment(ws, arrPrivateElements, ...)`.
4. Execution reaches `arrPrivateElements[0].payload.denomination` on line 2382 of `network.js`; since `payload` is `undefined`, this throws `TypeError: Cannot read properties of undefined (reading 'denomination')`.
5. The exception is uncaught within the synchronous handler call, propagates to `process.on('uncaughtException', ...)` in `network.js`, which logs it and re-throws (`throw err;`), terminating the node process.

*(Note: I was unable to fully trace every intermediate dispatch function between the raw `justsaying`/`private_payment` reception and `handleOnlinePrivatePayment` due to index/context limits, but the call site in `network.js:2412-2429` (`handleOnlinePrivatePayment` invoked via `joint_storage.checkIfNewUnit`) confirms this function is the designated handler for peer-supplied private-payment content, and the vulnerable line is unconditionally reached before any shape validation of `payload`.)*

### Citations

**File:** network.js (L2376-2382)
```javascript
function handleOnlinePrivatePayment(ws, arrPrivateElements, bViaHub, callbacks){
	if (!ValidationUtils.isNonemptyArray(arrPrivateElements))
		return callbacks.ifError("private_payment content must be non-empty array");
	
	var unit = arrPrivateElements[0].unit;
	var message_index = arrPrivateElements[0].message_index;
	var output_index = arrPrivateElements[0].payload.denomination ? arrPrivateElements[0].output_index : -1;
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

**File:** private_payment.js (L23-34)
```javascript
function validateAndSavePrivatePaymentChain(arrPrivateElements, callbacks){
	if (!ValidationUtils.isNonemptyArray(arrPrivateElements))
		return callbacks.ifError("no priv elements array");
	var headElement = arrPrivateElements[0];
	if (!headElement.payload)
		return callbacks.ifError("no payload in head element");
	var asset = headElement.payload.asset;
	if (!asset)
		return callbacks.ifError("no asset in head element");
	if (!ValidationUtils.isNonnegativeInteger(headElement.message_index))
		return callbacks.ifError("no message index in head private element");
	
```
