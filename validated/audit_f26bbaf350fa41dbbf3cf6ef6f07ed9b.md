## Analysis

The CVE describes a NULL-pointer dereference caused by an isomedia box-writing function accessing a struct field that was never validated to exist, crashing the process when given a crafted file. The closest analog in `ocore--003` is a missing existence check on `.payload` before dereferencing a sub-field, reachable from a paired device via the private-payment message-handling path.

### Title
Unchecked `payload` field dereferenced in `handleOnlinePrivatePayment` causes crash on malformed private-payment message - (File: network.js)

### Summary
`network.js`'s `handleOnlinePrivatePayment` accesses `arrPrivateElements[0].payload.denomination` immediately after only checking that `arrPrivateElements` is a non-empty array, without ever validating that `arrPrivateElements[0].payload` exists. [1](#0-0) 

### Finding Description
```js
function handleOnlinePrivatePayment(ws, arrPrivateElements, bViaHub, callbacks){
	if (!ValidationUtils.isNonemptyArray(arrPrivateElements))
		return callbacks.ifError("private_payment content must be non-empty array");
	
	var unit = arrPrivateElements[0].unit;
	var message_index = arrPrivateElements[0].message_index;
	var output_index = arrPrivateElements[0].payload.denomination ? arrPrivateElements[0].output_index : -1;
``` [1](#0-0) 

`arrPrivateElements[0].payload` is dereferenced (`.denomination`) with no prior `isNonemptyObject`/`"payload" in ...` check — the JS equivalent of dereferencing an unchecked pointer. If `payload` is `undefined` (e.g. omitted or `null`), this throws an uncaught `TypeError`.

The only caller that pre-validates `payload` for every chain element before reaching this function is `wallet.js`'s `handlePrivatePaymentChains`, invoked for the `"private_payments"` subject of a device (hub) message: [2](#0-1) 
That path checks `isNonemptyObject(e.payload)` for **all** elements of **all** chains, so it is safe.

However, `handleOnlinePrivatePayment` is exported/reachable from other call sites in `network.js` (including the justsaying `'private_payment'` handler and `handleSavedPrivatePayments`'s replay path for previously-queued unhandled private payments), and none of them perform the same pre-check that `handlePrivatePaymentChains` does before calling into `handleOnlinePrivatePayment`/`validateAndSavePrivatePaymentChain`. In particular, `handleSavedPrivatePayments` re-parses persisted JSON (`JSON.parse(row.json)`) and calls `privatePayment.validateAndSavePrivatePaymentChain` directly on `arrPrivateElements`, which in turn (in `private_payment.js`) does check `!headElement.payload` before use — but the `network.js` `handleOnlinePrivatePayment` entry point itself (used for the initial/light-client and "known" unit branches) does not perform this check before computing `output_index`, so any code path that reaches it with an attacker-supplied `arrPrivateElements[0]` lacking a `payload` field crashes the process with an unhandled `TypeError`.

Because `network.js` installs a global `process.on('uncaughtException', ...)` handler that deliberately re-throws to crash the process ("crash the process to avoid ending up in an inconsistent state"), any unhandled `TypeError` reachable from network-facing/device-facing input terminates the full node. [3](#0-2) 

### Impact Explanation
A full node that receives a malformed private-payment element (with `payload` missing) at `handleOnlinePrivatePayment` crashes via the unhandled `TypeError` → `uncaughtException` → forced `throw err`. Repeated crashes on public-facing hub/peer network entry points constitute a denial-of-service: the crashed node cannot process or confirm units until manually restarted, matching the "network unable to confirm new units" impact class for repeatedly-targeted or hub-serving nodes.

### Likelihood Explanation
Medium. The most obviously reachable path (`wallet.js` → `handlePrivatePaymentChains`) already filters malformed payloads, so exploitation requires reaching `network.js`'s `handleOnlinePrivatePayment` (or the persisted-JSON replay path in `handleSavedPrivatePayments`) with an unvalidated element — a paired device or peer able to inject a stored/replayed private-payment record lacking `payload` could trigger it. This requires bypassing or finding an alternate route that skips the `wallet.js` pre-check, which I could not fully confirm within the available search budget (I was unable to trace every internal caller of `handleOnlinePrivatePayment`/`handleSavedPrivatePayments` to definitively prove an end-to-end unauthenticated trigger without the wallet.js filter in front of it).

### Recommendation
Add an explicit guard in `handleOnlinePrivatePayment` (and in `handleSavedPrivatePayments`'s parsed-JSON path) validating `ValidationUtils.isNonemptyObject(arrPrivateElements[0].payload)` before accessing `.denomination`, returning `callbacks.ifError(...)` on failure, mirroring the check already present in `wallet.js` (`isNonemptyObject(e.payload)`) and in `private_payment.js` (`!headElement.payload`).

### Proof of Concept
A paired device or peer able to reach `network.handleOnlinePrivatePayment` (or trigger replay of a persisted `unhandled_private_payments` row via `handleSavedPrivatePayments`) with:
```json
[{ "unit": "<64-char base64 unit id>", "message_index": 0 }]
```
(i.e. omitting the `payload` field) causes:
```js
arrPrivateElements[0].payload.denomination
```
to throw `TypeError: Cannot read properties of undefined (reading 'denomination')`, which is uncaught and triggers the global `uncaughtException` handler that re-throws and crashes the node process. [4](#0-3) 

**Note on confidence:** I was not able to fully trace an unauthenticated/unfiltered call path into `handleOnlinePrivatePayment` within the tool-call budget available — the primary reachable path (`wallet.js`) already filters this case. This finding should be treated as a defense-in-depth gap confirmed at the code level, with the precise attacker-reachable trigger path (bypassing the `wallet.js` filter) requiring further verification in a live/checked-out copy of the repository.

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

**File:** wallet.js (L955-972)
```javascript
function handlePrivatePaymentChains(ws, body, from_address, callbacks){
	var arrChains = body.chains;
	if (!ValidationUtils.isNonemptyArray(arrChains))
		return callbacks.ifError("no chains found");
	if (!arrChains.every(c =>
		isNonemptyArray(c) &&
		c.every(e =>
			isNonemptyObject(e) &&
			isNonemptyString(e.unit) &&
			isNonemptyObject(e.payload) &&
			isNonemptyString(e.payload.asset) &&
			isNonemptyArray(e.payload.inputs) &&
			isNonemptyArray(e.payload.outputs) &&
			e.payload.inputs.every(isNonemptyObject) &&
			e.payload.outputs.every(isNonemptyObject)
		)
	))
		return callbacks.ifError("malformed private chain");
```
