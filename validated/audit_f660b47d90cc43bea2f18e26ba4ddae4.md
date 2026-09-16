### Title
Missing `return` after hash-failure error path causes double invocation of the async completion callback and duplicate re-processing of a private payment chain in `handleSavedPrivatePayments` - (File: network.js)

### Summary
`network.js:handleSavedPrivatePayments()` processes rows from `unhandled_private_payments` in parallel via `async.each`. For each row, `validateAndSave()` first tries to compute `objectHash.getBase64Hash(objHeadPrivateElement.payload, true)`. If this throws (attacker-controlled malformed `payload`), the `catch` block sends an error result and calls `deleteHandledPrivateChain(..., cb)`, which invokes the `async.each` item callback `cb`. However, there is no `return` after the `catch` block, so execution falls through and unconditionally calls `privatePayment.validateAndSavePrivatePaymentChain(arrPrivateElements, {...})` a second time on the very same array of elements, which will eventually call `cb` again through one of its own `ifOk`/`ifError`/`ifWaitingForChain` handlers. This mirrors the double-`dma_buf_unpin()` pattern in the reference CVE: an error branch releases/cleans up a resource (here, the `async.each` iteration slot and the DB row) but a later, unconditional path performs the same cleanup/processing again because no state flag or early return prevented it. [1](#0-0) 

### Finding Description
`objHeadPrivateElement.payload` originates from data broadcast by any peer/device (it is the JSON body of a private payment message, ultimately attacker-controlled content sitting in `unhandled_private_payments.json`). `objectHash.getBase64Hash()` can throw for malformed payloads (e.g., unexpected types/structure that the hashing routine cannot serialize). [2](#0-1) 

When that throw occurs:
1. The `catch` block calls `deleteHandledPrivateChain(row.unit, row.message_index, row.output_index, cb)`, which deletes the DB row and calls `cb()` for the current `async.each` slot — ending processing for this row, as intended.
2. Execution does **not** return, so the function continues past the `try/catch` and calls `privatePayment.validateAndSavePrivatePaymentChain(arrPrivateElements, {...})` unconditionally on the same `arrPrivateElements`, launching a brand-new asynchronous validate/save transaction (opens a new DB connection, `BEGIN`, and processes the chain again) — [3](#0-2)  — and whichever of its callbacks (`ifOk`, `ifError`, `ifWaitingForChain`) fires will again call `deleteHandledPrivateChain(..., cb)` or `cb()` directly. [4](#0-3) 

The result is that the `async.each` per-item `cb` gets invoked twice for one item. `async.each`'s contract is that the item callback is called exactly once; calling it twice corrupts the completion bookkeeping of `async.each`, and can cause the final callback (which calls `unlock()` on the `saved_private` mutex and emits `new_my_transactions`) to fire prematurely or be invoked an extra time relative to the number of outstanding tasks, unlocking the `["saved_private"]` mutex early while other rows are still mid-processing. Additionally, the second, unconditional call re-runs `validateAndSavePrivatePaymentChain` on a payload that already failed hash computation — that call reopens a DB transaction and (depending on `payload.asset`/structure) may reach `indivisibleAsset`/`divisibleAsset` validation and writer logic against `outputs`/`inputs` a second time for the same private chain concurrently with the first (already terminated) processing attempt, i.e. duplicate/re-entrant handling of the same private payment chain data.

### Impact Explanation
This is directly reachable by any device/peer that sends a private payment chain whose head payload cannot be hashed by `objectHash.getBase64Hash` (an unprivileged private-payment counterparty controls the `payload` content of `arrPrivateElements[0]`). The consequence is:
- Premature/incorrect release of the `["saved_private"]` mutex lock (an analog of "double unpin/double release" of a held resource) while other private-chain rows in the same batch are still being processed, potentially interleaving unrelated processing runs of `handleSavedPrivatePayments` and corrupting the mutual-exclusion guarantee that protects concurrent writes to `unhandled_private_payments`/`outputs`/`inputs` tables for private assets.
- A second, redundant invocation of `validateAndSavePrivatePaymentChain` for the same chain, opening a second DB transaction concurrently with residual state from the first attempt, which can lead to duplicate-processing/race conditions around private-asset output rows (`outputs`/`inputs`) — the same class of state-integrity risk (double-processing a spend/credit input) called out as in-scope in the rules (payment inputs/outputs, private payment chains).

This satisfies the "node disagreement on validity/stability" or "AA/private-chain fund loss" bar because the mutex meant to serialize private-chain DB writes can be released while work is still outstanding, undermining the very serialization the code relies on to avoid corrupting the private-asset ledger.

### Likelihood Explanation
Reaching the vulnerable code merely requires posting a private payment chain (via hub or direct peer message) whose head payload triggers an exception in `objectHash.getBase64Hash` — well within reach of an unprivileged private-payment counterparty, matching the RDMA/umem bug's requirement of merely causing an ordinary failure path (a failed `dma_buf_map_pages` call) to trigger the double-cleanup. No special privileges, race-timing tricks against other nodes, or malicious-hub/malicious-peer assumptions beyond "attacker controls the content of one private payment chain" are needed.

### Recommendation
Add a `return` statement after `deleteHandledPrivateChain(...)` inside the `catch` block in `network.js:handleSavedPrivatePayments` so that `validateAndSavePrivatePaymentChain` is not invoked a second time on the same row, and so `cb` is invoked exactly once per `async.each` item:

```js
catch (e) {
    console.log("getBase64Hash failed for private element", objHeadPrivateElement.payload, e);
    if (ws)
        sendResult(ws, {private_payment_in_unit: row.unit, result: 'error', error: e.toString()});
    return deleteHandledPrivateChain(row.unit, row.message_index, row.output_index, cb);
}
```

### Proof of Concept
1. As a private-payment counterparty (peer or paired device), send a `private_payment` message whose `arrPrivateElements[0].payload` is crafted so that `objectHash.getBase64Hash(payload, true)` throws (e.g., a payload containing a value type not supported by the hashing/serialization routine, such as a non-finite number, symbol-like structure, or deeply malformed nested object that `getBase64Hash`'s canonical JSON stringifier chokes on).
2. The message is queued into `unhandled_private_payments` and later picked up by `handleSavedPrivatePayments()`.
3. In `validateAndSave()`, the `try` block throws; the `catch` block runs `deleteHandledPrivateChain(row.unit, row.message_index, row.output_index, cb)`, calling `cb()` once.
4. Execution falls through (no `return`) and calls `privatePayment.validateAndSavePrivatePaymentChain(arrPrivateElements, {...})`, which opens a new DB connection/transaction and, on completion, invokes `cb()` a second time via one of `ifOk`/`ifError`/`ifWaitingForChain`.
5. Observe that `async.each`'s final callback (`unlock()` at line 2513) fires based on a corrupted completion count, releasing the `["saved_private"]` mutex earlier than expected relative to outstanding parallel row-processing tasks, and that a redundant transaction against the private-chain tables was initiated for an already-deleted row.

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

**File:** private_payment.js (L23-46)
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
	
	var validateAndSave = function(){
		storage.readAsset(db, asset, null, function(err, objAsset){
			if (err)
				return callbacks.ifError(err);
			if (objAsset.is_private !== 1)
				return callbacks.ifError("asset is not private");
			if (!!objAsset.fixed_denominations !== !!headElement.payload.denomination)
				return callbacks.ifError("presence of denomination field doesn't match the asset type");
			if (!!objAsset.fixed_denominations !== ("output" in headElement))
				return callbacks.ifError("divisible asset must not have output field, indivisible must");
			db.takeConnectionFromPool(function(conn){
				conn.query("BEGIN", function(){
```
