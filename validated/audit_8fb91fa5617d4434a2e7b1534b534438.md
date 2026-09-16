### Title
Missing `return` after error path causes double invocation of the `async.each` iteratee callback in private-payment chain handling - ([File: network.js])

### Summary
In `handleSavedPrivatePayments()`, the inner `validateAndSave` function catches exceptions from hashing an incoming private payment's payload, but fails to `return` after handling the error. Execution falls through to the validation call below, which can invoke the same completion callback `cb` a second time — mirroring the CVE-2022-50248 pattern where a resource-completion path executed twice because an error branch failed to stop further processing before deferring to the normal completion path.

### Finding Description
`handleSavedPrivatePayments` iterates unhandled private payment chains with `async.each`, and for each row calls `validateAndSave`: [1](#0-0) 

```
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
```

If `objectHash.getBase64Hash(objHeadPrivateElement.payload, true)` throws (`objHeadPrivateElement.payload` is attacker-controlled — it comes from `arrPrivateElements = JSON.parse(row.json)`, itself stored from data received from a private-payment counterparty/hub message and processed unvalidated at this stage), the `catch` block calls `deleteHandledPrivateChain(row.unit, row.message_index, row.output_index, cb)`, which asynchronously invokes `cb()` once the DELETE completes: [2](#0-1) 

Because there is no `return` statement inside the `catch` block, execution continues past the `try/catch` and unconditionally calls `privatePayment.validateAndSavePrivatePaymentChain(arrPrivateElements, {...})`, whose `ifOk`/`ifError`/`ifWaitingForChain` callbacks *each* also call `cb()` (via `deleteHandledPrivateChain(...)` or directly): [3](#0-2) 

This results in the `async.each` iteratee callback `cb` being invoked twice for the same item — one call originating from the exception-handling cleanup path, and a second, later call originating from the normal validation/save completion path. This is directly analogous to the iwlwifi bug class: an error branch does not prevent a second, independent completion/free/cleanup path from firing on the same resource, producing two logically parallel "completions" for what should be a single-owner resource.

### Impact Explanation
`async.each` treats each call of `cb` as one "item done" signal; internally it decrements a pending counter and, once it reaches zero (or hits an error), invokes the final callback that calls `unlock()`. A double invocation of `cb()` per row can cause the internal completion counter to under-run, triggering the final callback (and thus `unlock()` on the `"saved_private"` mutex key) prematurely — before other rows in the same batch have actually finished being validated/saved. Since `unlock()` releases the mutex that serializes calls to `handleSavedPrivatePayments`, a premature unlock enables a new invocation of this function (e.g., triggered again upon receipt of another private chain) to run concurrently with unfinished work from the previous invocation, operating on the same `unhandled_private_payments` rows and racing on `deleteHandledPrivateChain`/`validateAndSavePrivatePaymentChain`. This can result in duplicate processing or partially-conflicting DB writes for private payment chains (private asset transfers), risking corrupted/duplicated private-chain bookkeeping — i.e., private payment state divergence, a form of accounting/spending inconsistency for the affected wallet. It also causes `json_payload_hash`/`key` to be computed with `json_payload_hash === undefined` in the fallthrough path, producing a malformed event-bus key (`'private_payment_validated-...-undefined-...'`) that will never match any listener, silently breaking wait/notify logic for that chain.

### Likelihood Explanation
This code path is reached whenever any device (including light wallets and hub-forwarded peers, i.e., an unprivileged "private-payment counterparty") sends a private payment chain that gets queued into `unhandled_private_payments` and later processed by `handleSavedPrivatePayments`. All that's required to trigger the throwing branch is a payload for the head private element that `objectHash.getBase64Hash(..., true)` cannot serialize (e.g., a value type not supported by `getJsonSourceString`, such as `undefined`/functions/`NaN` embedded in the payload JSON, or a shape that violates its assumptions). Since the payload originates from data the counterparty controls and is only `JSON.parse`d before this call (no structural validation precedes the hashing step here), a malicious but otherwise unprivileged peer can reliably trigger the exception. However, this analysis is based on static code inspection of the missing `return`; I was not able to fully verify the exact runtime input shape that makes `getBase64Hash`/`getJsonSourceString` throw for a given malformed payload, since I could not inspect the complete `string_utils.js` `getJsonSourceString` implementation.

### Recommendation
Add a `return;` immediately after `deleteHandledPrivateChain(row.unit, row.message_index, row.output_index, cb);` inside the `catch` block in `network.js`'s `validateAndSave` (within `handleSavedPrivatePayments`), so that once the error path has completed and called `cb`, execution does not also fall through to `privatePayment.validateAndSavePrivatePaymentChain`. Additionally, consider validating the shape/type of `objHeadPrivateElement.payload` before attempting to hash it, to avoid reaching the throwing code path at all.

### Proof of Concept
1. As a peer/private-payment counterparty, send a private payment chain (via the wallet/hub message flow that populates `unhandled_private_payments`) whose head element's `payload` contains a value that causes `objectHash.getBase64Hash(payload, true)` to throw (e.g., a payload containing an unsupported JS type after `JSON.parse`, or a circular/oversized structure — exact triggering value not fully confirmed due to inability to inspect `string_utils.getJsonSourceString` fully).
2. `handleSavedPrivatePayments` is invoked (on receipt or periodically) and iterates `unhandled_private_payments`, calling `validateAndSave` for the crafted row.
3. The `try` block throws; the `catch` block sends an error result and calls `deleteHandledPrivateChain(...)`, which will call `cb()` once the DB delete finishes.
4. Execution nonetheless falls through past the `catch` block and calls `privatePayment.validateAndSavePrivatePaymentChain(arrPrivateElements, {...})`, whose `ifOk`/`ifError` handler will also eventually call `cb()` (via a second `deleteHandledPrivateChain` call on the same, already-deleted row, or directly).
5. `cb` is thus invoked twice for one `async.each` item, causing the batch's final callback (and `unlock()` of the `"saved_private"` mutex) to fire before all rows are actually processed, allowing overlapping/duplicate execution of private-chain validation and save logic across concurrent invocations of `handleSavedPrivatePayments`. [4](#0-3)

### Citations

**File:** network.js (L2461-2521)
```javascript
				function(row, cb){
					var arrPrivateElements = JSON.parse(row.json);
					var ws = getPeerWebSocket(row.peer);
					if (ws && ws.readyState !== ws.OPEN)
						ws = null;
					
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
					};
					
					if (conf.bLight && arrPrivateElements.length > 1 && !row.linked)
						updateLinkProofsOfPrivateChain(arrPrivateElements, row.unit, row.message_index, row.output_index, cb, validateAndSave);
					else
						validateAndSave();
					
				},
				function(){
					unlock();
					var arrNewUnits = Object.keys(assocNewUnits);
					if (arrNewUnits.length > 0)
						eventBus.emit("new_my_transactions", arrNewUnits);
				}
			);
		});
	});
}
```

**File:** network.js (L2523-2527)
```javascript
function deleteHandledPrivateChain(unit, message_index, output_index, cb){
	db.query("DELETE FROM unhandled_private_payments WHERE unit=? AND message_index=? AND output_index=?", [unit, message_index, output_index], function(){
		cb();
	});
}
```
