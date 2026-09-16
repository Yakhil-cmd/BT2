### Title
Missing validation of chain length/count consistency in indivisible private-payment chain allows an unauthenticated peer to crash a full node - ([File: indivisible_asset.js])

### Summary
`parsePrivatePaymentChain()` in `indivisible_asset.js` assumes that a private-payment chain sent to it always has a consistent, well-formed shape (the last array element is a valid "issue" element, and each intermediate element correctly cross-references its neighbor). Several of these structural assumptions are unchecked before the code dereferences fields, mirroring the TensorFlow `SparseReshape` class of bug where a data structure's advertised shape/consistency is never validated before it's relied upon by downstream code, leading to a `CHECK`-style crash (in Node.js terms, an uncaught `TypeError`/`Error` that reaches the top-level `process.on('uncaughtException')` handler, which deliberately rethrows to kill the process).

### Finding Description
`private_payment.js:validateAndSavePrivatePaymentChain()` validates only that `arrPrivateElements` is a non-empty array and inspects the head element [1](#0-0) . It then calls into `indivisibleAsset.validateAndSavePrivatePaymentChain(conn, arrPrivateElements, transaction_callbacks)` for fixed-denomination (indivisible) assets [2](#0-1) .

Inside `indivisible_asset.js`, `validateAndSavePrivatePaymentChain()` calls `parsePrivatePaymentChain()`, which does:
```
var issuePrivateElement = arrPrivateElements[arrPrivateElements.length-1];
if (!issuePrivateElement.payload || !issuePrivateElement.payload.inputs || !issuePrivateElement.payload.inputs[0])
    return callbacks.ifError("invalid issue private element");
``` [3](#0-2) 

This code never checks that `issuePrivateElement` (the last array element) is actually a non-empty object before dereferencing `.payload`. Because the only prior check (in `private_payment.js`) validates the *head* element (`arrPrivateElements[0]`), not the tail, an attacker can send `arrPrivateElements` where the last element is `null`, a primitive, or otherwise malformed while the head element still passes the shallow checks in `private_payment.js` (non-empty array, head has `.payload.asset`, `.message_index`, etc.). When `arrPrivateElements.length === 1`, the head and tail are the same object, so that specific case is covered — but chains of length ≥ 2 only have the head validated; nothing enforces that the tail element (`arrPrivateElements[length-1]`) is a well-formed object at all before `issuePrivateElement.payload` is read.

Further down, inside the `async.forEachOfSeries` loop, `prevElement = arrPrivateElements[i+1]` is dereferenced (`prevElement.unit`, `.message_index`, `.output_index`) without first confirming `prevElement` is a non-empty object [4](#0-3) . If any non-terminal chain element is not an object (e.g. `null`, a number, or a string), this throws a synchronous `TypeError` that is not caught by any `try/catch`, propagating out of the `async.forEachOfSeries` iterator.

This is the exact bug class described in the report: the code accepts a chain of elements (analogous to a sparse tensor's `shape`/`indices`/`values`) without validating internal structural consistency (element types/lengths matching what downstream indexing code expects), and then indexes into it, causing an unhandled crash instead of a graceful validation error.

### Impact Explanation
Private-payment chains are attacker/counterparty controlled data delivered over the wallet layer — via `network.js:handleOnlinePrivatePayment()` (peer-to-peer "private_payment" message) or via chains rebuilt from `unhandled_private_payments` in `handleSavedPrivatePayments()` [5](#0-4) , and via device-to-device private payment delivery in the wallet flow. `handleOnlinePrivatePayment` only checks that `arrPrivateElements` is a non-empty array [6](#0-5)  — it does not validate the shape of the individual elements, deferring that to `private_payment.js` / `indivisible_asset.js`, where (as shown above) the tail element and intermediate `prevElement` references are not fully validated before being dereferenced.

An uncaught exception thrown synchronously inside this code path is not caught by `validation.validate`'s own error handling (this is a completely separate module invoked from network message handling), so it propagates to the process-level `uncaughtException` handler, which explicitly rethrows to crash the process by design [7](#0-6) . Any wallet/light client or full node that processes a maliciously crafted private-payment chain sent by a counterparty (recipient of a private payment, or a cosigner/device peer) can be crashed remotely — a denial of service against the affected node, consistent with the "Medium" severity assigned to the analogous `SparseReshape` CHECK-failure DoS.

### Likelihood Explanation
This is reachable by any counterparty in a private-payment transaction (private assets are commonly used, e.g. blackbytes) — no special privileges, hub/network position, or key compromise is required; simply sending/receiving a private payment message with a crafted chain is enough. The head-element validation in `private_payment.js` gives false confidence that the chain is well-formed, while the tail/intermediate elements consumed deeper in `indivisible_asset.js` are not equivalently checked, making the malformed-chain path easy to trigger by any wallet peer that composes a non-standard JSON payload for a `private_payment` message.

### Recommendation
In `indivisible_asset.js:parsePrivatePaymentChain()`, validate `issuePrivateElement` and each `prevElement` are non-empty objects (`isNonemptyObject`) before touching `.payload`/`.unit`/`.message_index`/`.output_index`, returning `callbacks.ifError(...)` instead of allowing an unhandled `TypeError`. More generally, every element of `arrPrivateElements` should be structurally validated (non-empty object, has expected fields of expected types) immediately upon entry to `validateAndSavePrivatePaymentChain`/`parsePrivatePaymentChain`, not just the head element as currently done in `private_payment.js`.

### Proof of Concept
1. As a wallet/device counterparty, initiate a private-payment exchange for a fixed-denomination private asset so that a full/light node ends up calling `privatePayment.validateAndSavePrivatePaymentChain` with an attacker-supplied `arrPrivateElements` array (e.g., via `handleOnlinePrivatePayment` in `network.js` or the `private_payment` device message flow).
2. Craft `arrPrivateElements` with length ≥ 2 such that:
   - `arrPrivateElements[0]` (head) is a well-formed object satisfying the checks in `private_payment.js:validateAndSavePrivatePaymentChain` (has `.payload.asset`, `.message_index`, etc.), and
   - `arrPrivateElements[arrPrivateElements.length-1]` (tail, the "issue" element) is set to `null` or a non-object value (e.g. `42`).
3. Send this chain to the target node/wallet.
4. Execution reaches `indivisible_asset.js` `parsePrivatePaymentChain()`, which executes `issuePrivateElement.payload` on the malformed tail element, throwing an uncaught `TypeError: Cannot read properties of null (reading 'payload')`.
5. Because nothing catches this synchronous exception, it bubbles up to the top-level `process.on('uncaughtException')` handler in `network.js`, which rethrows and crashes the node process, denying service to that node.

(Note: exact device-message call path into `indivisible_asset.js` for cosigner-relayed chains could not be fully traced in this pass beyond `network.js`'s `handleOnlinePrivatePayment`/`handleSavedPrivatePayments`; the `private_payment.js` → `indivisible_asset.js` reachability and the missing validation itself, however, are confirmed directly from source.)

### Citations

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

**File:** private_payment.js (L104-105)
```javascript
							var assetModule = objAsset.fixed_denominations ? indivisibleAsset : divisibleAsset;
							assetModule.validateAndSavePrivatePaymentChain(conn, arrPrivateElements, transaction_callbacks);
```

**File:** indivisible_asset.js (L186-197)
```javascript
// arrPrivateElements is ordered in reverse chronological order
function parsePrivatePaymentChain(conn, arrPrivateElements, callbacks){
	var bAllStable = true;
	var issuePrivateElement = arrPrivateElements[arrPrivateElements.length-1];
	if (!issuePrivateElement.payload || !issuePrivateElement.payload.inputs || !issuePrivateElement.payload.inputs[0])
		return callbacks.ifError("invalid issue private element");
	var asset = issuePrivateElement.payload.asset;
	if (!asset)
		return callbacks.ifError("no asset in issue private element");
	var denomination = issuePrivateElement.payload.denomination;
	if (!denomination)
		return callbacks.ifError("no denomination in issue private element");
```

**File:** indivisible_asset.js (L209-218)
```javascript
			var prevElement = null; 
			if (i+1 < arrPrivateElements.length){ // excluding issue transaction
				var prevElement = arrPrivateElements[i+1];
				if (prevElement.unit !== objPrivateElement.payload.inputs[0].unit)
					return cb("not referencing previous element unit");
				if (prevElement.message_index !== objPrivateElement.payload.inputs[0].message_index)
					return cb("not referencing previous element message index");
				if (prevElement.output_index !== objPrivateElement.payload.inputs[0].output_index)
					return cb("not referencing previous element output index");
			}
```

**File:** network.js (L2376-2378)
```javascript
function handleOnlinePrivatePayment(ws, arrPrivateElements, bViaHub, callbacks){
	if (!ValidationUtils.isNonemptyArray(arrPrivateElements))
		return callbacks.ifError("private_payment content must be non-empty array");
```

**File:** network.js (L2412-2441)
```javascript
	joint_storage.checkIfNewUnit(unit, {
		ifKnown: function(){
			//assocUnitsInWork[unit] = true;
			privatePayment.validateAndSavePrivatePaymentChain(arrPrivateElements, {
				ifOk: function(){
					//delete assocUnitsInWork[unit];
					callbacks.ifAccepted(unit);
					eventBus.emit("new_my_transactions", [unit]);
				},
				ifError: function(error){
					//delete assocUnitsInWork[unit];
					callbacks.ifValidationError(unit, error);
				},
				ifWaitingForChain: function(){
					savePrivatePayment();
				}
			});
		},
		ifNew: function(){
			savePrivatePayment();
			// if received via hub, I'm requesting from the same hub, thus telling the hub that this unit contains a private payment for me.
			// It would be better to request missing joints from somebody else
			requestNewMissingJoints(ws, [unit]);
		},
		ifKnownUnverified: savePrivatePayment,
		ifKnownBad: function(){
			callbacks.ifValidationError(unit, "known bad");
		}
	});
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
