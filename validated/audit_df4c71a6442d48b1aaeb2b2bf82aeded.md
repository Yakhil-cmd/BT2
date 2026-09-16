### Title
Uncaught exception / missing `return` after hash-failure in private-payment handling causes crash of `handleSavedPrivatePayments` - (File: network.js)

### Summary
`network.js`'s `handleSavedPrivatePayments()` calls `validateAndSave()` for every private-payment chain saved by a payment counterparty. Inside `validateAndSave`, a `try/catch` around `objectHash.getBase64Hash()` fails to `return` after handling the exception, so execution falls through and continues to use the (now `undefined`) `json_payload_hash` and to call `privatePayment.validateAndSavePrivatePaymentChain()` a second time on the same, already-invalid data, after the completion callback `cb` was already invoked once inside the `catch` block via `deleteHandledPrivateChain(...)`.

### Finding Description
```js
var validateAndSave = function(){
    var objHeadPrivateElement = arrPrivateElements[0];
    try {
        var json_payload_hash = objectHash.getBase64Hash(objHeadPrivateElement.payload, true);
    }
    catch (e) {
        console.log("getBase64Hash failed for private element", objHeadPrivateElement.payload, e);
        if (ws)
            sendResult(ws, {private_payment_in_unit: row.unit, result: 'error', error: e.toString()});
        deleteHandledPrivateChain(row.unit, row.message_index, row.output_index, cb);
    }
    var key = 'private_payment_validated-'+objHeadPrivateElement.unit+'-'+json_payload_hash+'-'+row.output_index;
    privatePayment.validateAndSavePrivatePaymentChain(arrPrivateElements, { ... });
};
``` [1](#0-0) 

This is missing a `return` statement after the `catch` block (mirroring the analog of `stub_send_ret_submit()` in the CVE, which dereferences data after a failure path without validating/aborting first). As a direct result:
1. `deleteHandledPrivateChain(...)` is invoked, which asynchronously calls `cb()` from `async.each` once the DB delete finishes.
2. Execution does not stop; the code proceeds to build `key` using `undefined` for `json_payload_hash` and immediately invokes `privatePayment.validateAndSavePrivatePaymentChain(arrPrivateElements, ...)` on the same malformed `arrPrivateElements` that just failed to hash.
3. `validateAndSavePrivatePaymentChain` -> `parsePrivatePaymentChain` -> `validatePrivatePayment` in `indivisible_asset.js` reads fields off `objPrivateElement.payload` and `objPrivateElement.output` without expecting the malformed content that caused `getBase64Hash` to throw in the first place [2](#0-1) , [3](#0-2) . Because a counterparty in a private payment fully controls the JSON of `arrChains`/`arrPrivateElements` sent through `handlePrivatePaymentChains` in `wallet.js` [4](#0-3) , they can craft a payload that (a) throws during canonical-JSON hashing (e.g. through non-well-formed/self-referential-looking structures accepted by `JSON.parse` but rejected by `getJsonSourceString`) and (b) is also accepted far enough into `validatePrivatePayment`/`parsePrivatePaymentChain` to hit a second, unguarded exception (uncaught by any `try/catch` in this call chain), which in Node.js is process-fatal.
4. Additionally, `cb` may be invoked twice for the same `async.each` iteratee (once from `deleteHandledPrivateChain` in the `catch`, and potentially again from one of the `ifOk`/`ifError`/`ifWaitingForChain` callbacks reached via the fallthrough call), which is undefined behavior for `async.each` and can also corrupt the async control flow of `handleSavedPrivatePayments`, causing further unhandled callbacks/timeouts of `unlock()`/wallet mutex — a soft denial of service for that wallet node's private-payment handling.

### Impact Explanation
`handleSavedPrivatePayments` is the periodic sweep that processes private payment chains a wallet has stored from either a hub, direct peer, or private-payment counterparty. A malicious private-payment counterparty can supply a payload triggering the first exception, causing the node to fall into the double-processing/uncaught-exception path. An uncaught exception thrown deep in `parsePrivatePaymentChain`/`validatePrivatePayment` (invoked from inside an `async.each` iteratee with no surrounding try/catch) crashes the Node.js process — a denial of service of the local wallet/hub instance, analogous to the NULL-pointer-dereference DoS in the referenced CVE, where a single crafted message causes a process crash in a code path lacking a proper early-return/validation guard.

### Likelihood Explanation
Reachable by any device correspondent capable of sending "private_payment_chains" messages (`handlePrivatePaymentChains` in `wallet.js`), i.e., any private-payment counterparty a wallet interacts with, with no special privileges required. Triggering requires constructing a `payload` object that is accepted by the shallow shape checks in `handlePrivatePaymentChains` (non-empty object/array checks only) [5](#0-4)  but fails `getJsonSourceString`/`getBase64Hash` canonicalization — plausible given the loose validation prior to hashing.

### Recommendation
Add a `return;` immediately after the `deleteHandledPrivateChain(...)` call inside the `catch` block in `network.js`'s `validateAndSave` function so that execution does not fall through to use the undefined `json_payload_hash` or re-invoke `validateAndSavePrivatePaymentChain` on data that already failed hashing. Additionally, wrap the call chain from `validateAndSavePrivatePaymentChain` down through `parsePrivatePaymentChain`/`validatePrivatePayment` in defensive `try/catch` so a single malformed private-payment chain cannot crash the whole process, and ensure `cb` from `async.each` is invoked exactly once per iteration.

### Proof of Concept
1. As a device correspondent connected to a target wallet, send a `private_payment_chains` message via the hub with `chains: [[ objHeadPrivateElement ]]` where `objHeadPrivateElement.payload` passes the loose validation in `handlePrivatePaymentChains` (non-empty object, `asset` non-empty string, `inputs`/`outputs` arrays of non-empty objects) [5](#0-4)  but contains a field value that causes `getJsonSourceString` to throw when canonicalizing (e.g., deeply nested or malformed structure not otherwise rejected upstream).
2. The chain gets queued into `unhandled_private_payments` and later processed by `handleSavedPrivatePayments`.
3. `objectHash.getBase64Hash(objHeadPrivateElement.payload, true)` throws inside `validateAndSave` [6](#0-5) ; the missing `return` allows the code to fall through and call `privatePayment.validateAndSavePrivatePaymentChain` again on the same malformed data outside of any try/catch, ultimately hitting an uncaught exception in `indivisible_asset.js`'s validation chain and crashing the Node.js process, or double-invoking `cb`, corrupting the `async.each`/mutex bookkeeping for private payment processing.

### Citations

**File:** network.js (L2467-2503)
```javascript
					var validateAndSave = function(){
						var objHeadPrivateElement = arrPrivateElements[0];
						try {
							var json_payload_hash = objectHash.getBase64Hash(objHeadPrivateElement.payload, true);
						}
						catch (e) {
							console.log("getBase64Hash failed for private element", objHeadPrivateElement.payload, e);
							if (ws)
								sendResult(ws, {private_payment_in_unit: row.unit, result: 'error', error: e.toString()});
							deleteHandledPrivateChain(row.unit, row.message_index, row.output_index, cb);
						}
						var key = 'private_payment_validated-'+objHeadPrivateElement.unit+'-'+json_payload_hash+'-'+row.output_index;
						privatePayment.validateAndSavePrivatePaymentChain(arrPrivateElements, {
							ifOk: function(){
								if (ws)
									sendResult(ws, {private_payment_in_unit: row.unit, result: 'accepted'});
								if (row.peer) // received directly from a peer, not through the hub
									eventBus.emit("new_direct_private_chains", [arrPrivateElements]);
								assocNewUnits[row.unit] = true;
								deleteHandledPrivateChain(row.unit, row.message_index, row.output_index, cb);
								console.log('emit '+key);
								eventBus.emit(key, true);
							},
							ifError: function(error){
								console.log("validation of priv: "+error);
							//	throw Error(error);
								if (ws)
									sendResult(ws, {private_payment_in_unit: row.unit, result: 'error', error: error});
								deleteHandledPrivateChain(row.unit, row.message_index, row.output_index, cb);
								eventBus.emit(key, false);
							},
							// light only. Means that chain joints (excluding the head) not downloaded yet or not stable yet
							ifWaitingForChain: function(){
								console.log('waiting for chain: unit '+row.unit+', message '+row.message_index+' output '+row.output_index);
								cb();
							}
						});
```

**File:** indivisible_asset.js (L20-20)
```javascript
function validatePrivatePayment(conn, objPrivateElement, objPrevPrivateElement, callbacks){
```

**File:** indivisible_asset.js (L54-60)
```javascript
	var payload = objPrivateElement.payload;
	if (!ValidationUtils.isStringOfLength(payload.asset, constants.HASH_LENGTH))
		return callbacks.ifError("invalid asset in private payment");
	if (!ValidationUtils.isPositiveInteger(payload.denomination))
		return callbacks.ifError("invalid denomination in private payment");
	if (!ValidationUtils.isNonemptyObject(objPrivateElement.output))
		return callbacks.ifError("no output");
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
