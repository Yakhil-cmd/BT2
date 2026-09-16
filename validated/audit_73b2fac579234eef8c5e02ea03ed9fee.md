### Title
Missing `return` after error in private-payment hash computation causes use of undefined value and duplicate callback invocation - ([File: network.js])

### Summary
In `network.js`, `handleSavedPrivatePayments()`'s inner `validateAndSave()` function computes a hash of the head private-payment element's payload and, if that computation throws, handles the error but fails to `return` — execution falls through and continues to use the (now `undefined`) hash result and to re-invoke chain validation logic that itself will call the `async.each` iteratee callback again. This mirrors the reported bug class: a fallible operation's error path is not fully handled before its result is used downstream (in the kernel report, an unchecked USB control-transfer error left `data` uninitialized before being logged; here, a caught hashing exception leaves `json_payload_hash` `undefined` before it is used, and processing continues instead of stopping).

### Finding Description
`objectHash.getBase64Hash(objHeadPrivateElement.payload, true)` computes a JSON-based hash of an attacker/peer-controlled payload (`arrPrivateElements`, loaded from `unhandled_private_payments.json`, ultimately originating from data sent by a private-payment counterparty via `handleOnlinePrivatePayment`/`handlePrivatePaymentChains`). [1](#0-0) 

If the payload cannot be hashed (`getJsonSourceString`/`getBase64Hash` throws — e.g. because the JSON payload contains values that are not representable in ocore's canonical/stringified form), the `catch` block logs the error, optionally notifies the peer, and calls `deleteHandledPrivateChain(row.unit, row.message_index, row.output_index, cb)` — which itself invokes `cb()` asynchronously once the DB delete completes. [2](#0-1) 

Critically, there is no `return` statement after this `catch` block, so execution falls through to line 2478, which builds `key` using `json_payload_hash` — a variable declared with `var` inside the `try` block, hoisted to the function scope but left `undefined` because the assignment never completed due to the exception: [3](#0-2) 

Execution then proceeds to call `privatePayment.validateAndSavePrivatePaymentChain(arrPrivateElements, {...})` a second, unconditional time even though the row is already scheduled for deletion via the error path: [4](#0-3) 

That call's `ifOk`, `ifError`, and `ifWaitingForChain` handlers each independently call `cb()` (the `async.each` iteratee callback for this row) — or `deleteHandledPrivateChain(..., cb)` which itself calls `cb()`. [5](#0-4) [6](#0-5) [7](#0-6) 

The net effect: for a single row, `cb` can be invoked twice for the same `async.each` task (once via the exception path's `deleteHandledPrivateChain`, once via the unconditional `validateAndSavePrivatePaymentChain` call that always executes). `async.each`/`async` libraries do not guard against a task calling back more than once; the second invocation can prematurely fire the final callback of `async.each` (unlocking `["saved_private"]` and emitting `new_my_transactions`) while other rows in the same batch are still being processed, or can throw ("Callback was already called") depending on the async version, and additionally `deleteHandledPrivateChain` is invoked concurrently from two code paths against the same DB row while `privatePayment.validateAndSavePrivatePaymentChain` is also mutating state (asset lookup, insert queries, `COMMIT`) for that unit, potentially interleaving a persisted "delete" with an in-flight validate/save transaction. [8](#0-7) 

### Impact Explanation
The bug is reachable by an untrusted private-payment counterparty who crafts a payload for `arrPrivateElements[0].payload` that causes `getJsonSourceString`/`getBase64Hash` to throw when re-hashed on retry inside `handleSavedPrivatePayments` (a full node's periodic sweep of `unhandled_private_payments`). Triggering the double-callback race can cause `mutex.unlock(["saved_private"])` to fire early while sibling chain-processing tasks in the same batch are still running, letting a second concurrent `handleSavedPrivatePayments` invocation process (and possibly re-validate/re-save or delete) the same private payment rows out of order. This risks corrupting or dropping private payment/output records tracked for the node's own wallet (`outputs`/`inputs` rows for private assets), i.e. loss/duplication of private balance bookkeeping for a wallet-holding full node — a node-disagreement/asset-accounting integrity issue rather than a memory-safety crash (JS has no raw uninitialized memory), so impact is capped at Medium.

### Likelihood Explanation
Likelihood is moderate: it requires (1) the attacker's private payment being routed through `handleSavedPrivatePayments` (via `ifKnownUnverified`/`savePrivatePayment`/`ifWaitingForChain` retry paths, all common in light/queued processing), and (2) a payload value that specifically causes `getJsonSourceString` to throw (e.g., unsupported/forbidden field type) while still being routable earlier in the pipeline (which only performs lighter-weight `ValidationUtils` shape checks in `handlePrivatePaymentChains`, not hash computation). No special network position, hub, or leaked key is needed — it can be triggered by any peer that can send a private payment to the victim's wallet.

### Recommendation
Add a `return` after the `catch` block in `network.js`'s `validateAndSave()` (or restructure with an early-return pattern) so that when `getBase64Hash` throws, the function stops immediately after `deleteHandledPrivateChain(..., cb)` and does not fall through to build `key` or call `privatePayment.validateAndSavePrivatePaymentChain` a second time for the same row/`cb`. Additionally, guard `cb` with an idempotency wrapper (call-once) for defense in depth.

### Proof of Concept
1. As a peer/counterparty, send a private payment chain via the wallet-to-wallet protocol (`handlePrivatePaymentChains`) whose head element's `payload` passes the shape checks in `handlePrivatePaymentChains` but contains a value that makes `string_utils.getJsonSourceString` throw when invoked again later (e.g., a value type not supported by the canonical JSON source-string serializer). The initial hash check in `handlePrivatePaymentChains` (`objectHash.getBase64Hash(arrChains)`) is a hash of the wrapping array and can succeed even if a deeper/altered field triggers a throw specifically inside the per-chain path taken later.
2. The payment gets stored in `unhandled_private_payments` and later reprocessed by `handleSavedPrivatePayments()`, entering `validateAndSave()`.
3. `objectHash.getBase64Hash(objHeadPrivateElement.payload, true)` throws; the `catch` block runs `deleteHandledPrivateChain(..., cb)` (which will call `cb()` once its DB `DELETE` completes) but does not `return`.
4. Execution falls through and unconditionally invokes `privatePayment.validateAndSavePrivatePaymentChain(arrPrivateElements, {...})`, whose `ifError`/`ifWaitingForChain`/`ifOk` handlers call `cb()` (or `deleteHandledPrivateChain(..., cb)`) again for the same row.
5. Observe `cb` for the `async.each` task firing twice — either via an async-library assertion error ("Callback was already called") in logs, or via premature unlocking of the `"saved_private"` mutex before all rows in the batch complete, allowing overlapping `handleSavedPrivatePayments` runs to race on the same `unhandled_private_payments` rows.

### Citations

**File:** network.js (L2467-2478)
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
```

**File:** network.js (L2479-2503)
```javascript
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

**File:** network.js (L2512-2518)
```javascript
				function(){
					unlock();
					var arrNewUnits = Object.keys(assocNewUnits);
					if (arrNewUnits.length > 0)
						eventBus.emit("new_my_transactions", arrNewUnits);
				}
			);
```
