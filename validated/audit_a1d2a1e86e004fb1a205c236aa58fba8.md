### Title
Missing `return` after malformed-payload error causes double callback invocation / continued processing of a rejected private payment chain in `handleSavedPrivatePayments` - ([File: network.js])

### Summary
`network.js`'s `handleSavedPrivatePayments` processes queued rows from `unhandled_private_payments`, one of which can be an attacker/counterparty-supplied private payment chain (device-message driven, reachable by any private-payment counterparty). Inside `validateAndSave()`, when `objectHash.getBase64Hash(objHeadPrivateElement.payload, true)` throws (malformed/oversized payload), the `catch` block calls `deleteHandledPrivateChain(row.unit, row.message_index, row.output_index, cb)` — which itself invokes `cb`, the `async.each` iteratee callback — but execution does **not** `return` out of the function. Code falls through to compute `key` (using the now-`undefined` `json_payload_hash`) and unconditionally calls `privatePayment.validateAndSavePrivatePaymentChain(arrPrivateElements, {...})`, whose `ifOk`/`ifError`/`ifWaitingForChain` handlers each call `cb` again. [1](#0-0) 

### Finding Description
This is the closest reachable analog to the reported bug class: a resource ("the row"/chain being handled) is released/finalized (`deleteHandledPrivateChain` deletes the DB row and invokes the completion callback `cb`, semantically "freeing" that unit of work) but the same code path continues to *use* it afterward — passing the same (already-finalized) chain into a second asynchronous operation that will independently call `cb` a second time. This mirrors a use-after-free/double-free pattern at the control-flow level: an object is torn down and then still operated upon, with two independent completion paths racing on the same shared `cb`/`unlock` state.

Concretely:
1. `cb` (the `async.each` iteratee callback) gets invoked twice for the same row — once from the error path, once from the follow-on `validateAndSavePrivatePaymentChain` callback.
2. `async.each`'s finishing callback (`function(){ unlock(); ... }`) can be triggered prematurely/again depending on timing, releasing the `saved_private` mutex lock while the malformed chain is still being processed, or calling `unlock()` twice.
3. The malformed chain (whose head hash could not even be computed) is still handed to `privatePayment.validateAndSavePrivatePaymentChain`, i.e., validation logic executes on data that the code itself had already flagged as unprocessable and had already reported "error" for and deleted from the queue. [2](#0-1) [3](#0-2) 

### Impact Explanation
Double invocation of `cb`/`unlock` in `async.each`/mutex logic causes non-deterministic reentrancy of the private-payment handling pipeline: the `saved_private` mutex can be released while stale in-flight processing (validation/save of a private divisible/indivisible asset chain) is still running, allowing a second concurrent call to `handleSavedPrivatePayments` to interleave with an unfinished chain-save transaction. Because private payment chains directly update `outputs`/`inputs` tables (`is_spent`, uniqueness flags) for private assets, races of this kind on the shared write path create a window for duplicate/partial processing of a chain (partial commit re-entered, or two chains keyed by the same trigger racing) — undermining the intended one-shot semantics of `unhandled_private_payments` row handling and creating a node-local disagreement about whether a private output has been marked spent, i.e., a path toward inconsistent/duplicate acceptance of a private payment.

### Likelihood Explanation
Reachable purely by a private-payment counterparty or paired device sending a device message (`private_payment`) whose head element's `payload` cannot be hashed by `objectHash.getBase64Hash` (e.g., contains a value that fails hashing, such as unsupported types/structure) — this requires no special privilege beyond being a payment counterparty, matching the allowed threat model. The condition is a normal error path (any payload causing `getBase64Hash` to throw), not a rare edge case, so it is trivially triggerable by any private-chain sender.

### Recommendation
Add a `return` statement immediately after invoking `deleteHandledPrivateChain(...)` inside the `catch` block in `handleSavedPrivatePayments`'s `validateAndSave` function, so that a hashing failure short-circuits the function and neither `key` computation nor `privatePayment.validateAndSavePrivatePaymentChain` execute, preventing the double `cb` invocation and the subsequent processing of an already-rejected chain.

### Proof of Concept
1. As a paired device / private-payment counterparty, send (or trigger arrival via hub delivery into `unhandled_private_payments`) a `private_payment` chain whose head element's `payload` cannot be serialized/hashed by `objectHash.getBase64Hash` (e.g., a payload containing a value type unsupported by the hashing routine, such as a circular reference or unsupported primitive smuggled through `JSON.parse(row.json)` prior to re-serialization attempts inside hashing).
2. `handleSavedPrivatePayments` picks up the row, calls `validateAndSave()`; `getBase64Hash` throws.
3. The `catch` block sends an error result and calls `deleteHandledPrivateChain(..., cb)`, invoking `cb` once.
4. Execution falls through (no `return`) and calls `privatePayment.validateAndSavePrivatePaymentChain(arrPrivateElements, {...})` on the same, already-deleted chain; whichever of `ifOk`/`ifError`/`ifWaitingForChain` fires calls `cb` a second time.
5. Observe `async.each`'s completion handler firing twice / out of order relative to the number of rows, and the `saved_private` mutex being released prematurely while the duplicate `validateAndSavePrivatePaymentChain` invocation is still mutating the DB — verifiable via instrumented logging of `unlock()` call counts and `cb` call counts under a crafted malformed private-payment payload. [4](#0-3)

### Citations

**File:** network.js (L2444-2457)
```javascript
function handleSavedPrivatePayments(unit){
	//if (unit && assocUnitsInWork[unit])
	//    return;
	if (!my_device_address) return; // skip if we don't have a wallet
	if (!unit && mutex.isAnyOfKeysLocked(["private_chains"])) // we are still downloading the history (light)
		return console.log("skipping handleSavedPrivatePayments because history download is still under way");
	var lock = unit ? mutex.lock : mutex.lockOrSkip;
	lock(["saved_private"], function(unlock){
		var sql = unit
			? "SELECT json, peer, unit, message_index, output_index, linked FROM unhandled_private_payments WHERE unit="+db.escape(unit)
			: "SELECT json, peer, unit, message_index, output_index, linked FROM unhandled_private_payments CROSS JOIN units USING(unit)";
		db.query(sql, function(rows){
			if (rows.length === 0)
				return unlock();
```

**File:** network.js (L2461-2518)
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
```
