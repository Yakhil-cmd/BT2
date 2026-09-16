### Title
Missing `return` after error handling in `handleSavedPrivatePayments` causes duplicate processing / double-callback of a private payment chain - (File: `network.js`)

### Summary
In `handleSavedPrivatePayments()`, the inner `validateAndSave` closure catches an exception thrown by `objectHash.getBase64Hash()`, sends an error result, and calls `deleteHandledPrivateChain(...)` to clean up — but does not `return` after doing so. Execution falls through to the rest of the function and calls `privatePayment.validateAndSavePrivatePaymentChain()` a second time on the same (already being deleted) private-payment row, exactly mirroring the reported bug class: an error/cancellation path is taken, but the function keeps executing as if nothing happened.

### Finding Description
`validateAndSave` is defined inside `handleSavedPrivatePayments`: [1](#0-0) 

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
};
```

`deleteHandledPrivateChain` itself is asynchronous and calls `cb` when its DELETE finishes: [2](#0-1) 

There is no `return` statement after the `catch` block. Consequently, once `getBase64Hash` throws:
1. `deleteHandledPrivateChain(row.unit, row.message_index, row.output_index, cb)` is invoked (this will eventually invoke `cb()`, marking one iteration of the outer `async.each` as complete).
2. Execution does **not** stop — the code proceeds to compute `key` using `json_payload_hash`, which is `undefined` because the assignment inside the `try` never completed.
3. `privatePayment.validateAndSavePrivatePaymentChain(arrPrivateElements, {...})` is called on the same `arrPrivateElements`, whose `ifOk`/`ifError`/`ifWaitingForChain` callbacks all eventually call `cb()` again — as well as call `sendResult` and `deleteHandledPrivateChain` again.

This produces:
- A double invocation of `cb` for the same row inside `async.each`, which is undefined/dangerous behavior for the `async` library (can cause the outer iteration count to be miscounted, callbacks fired multiple times, or the completion callback of `async.each` firing prematurely/twice).
- A second, redundant call into `privatePayment.validateAndSavePrivatePaymentChain`, re-processing a private-payment chain whose deletion (`deleteHandledPrivateChain`) row cleanup was already kicked off concurrently — a race between two deletes/inserts on `unhandled_private_payments`.
- Potential duplicate `sendResult`/`eventBus.emit(key, ...)` emissions to a peer.

This is directly analogous to the reported issue: after an error path is entered and a "cancellation"/cleanup action is issued, the function does not revert/stop, and continues executing the main logic as if the error never happened.

### Impact Explanation
`handleSavedPrivatePayments` is invoked from the wallet's private-payment retry/queue-processing logic (`network.handleOnlinePrivatePayment` queues payments here, and this function is periodically re-invoked to process `unhandled_private_payments`). The trigger condition — `objectHash.getBase64Hash` throwing on `objHeadPrivateElement.payload` — is reachable by a private-payment counterparty who can freely construct the `payload` object of a private chain element sent to a peer (the payload is attacker-supplied JSON stored verbatim in `unhandled_private_payments` before this validation step runs, per `savePrivatePayment` in `handleOnlinePrivatePayment`). By crafting a payload whose structure causes `object_hash.js` to throw (e.g., unexpected type triggering an internal `throw Error(...)` in the hashing/serialization routine), an attacker can force this double-processing bug on every retry cycle for their malicious chain.

The concrete consequences are:
- Double invocation of the `async.each` callback can lead to duplicate `eventBus.emit("new_my_transactions", ...)` firing, duplicate network replies, or corrupted mutex/lock bookkeeping in the wallet processing pipeline, causing the wallet to become stuck processing private payments (denial of legitimate progress on the private-payment queue) or emit inconsistent state to listeners.
- Because `deleteHandledPrivateChain` and `validateAndSavePrivatePaymentChain` both race on the same DB row without proper sequencing, a private payment could be validated/saved based on stale state, or the row could be deleted while a save operation targeting it is still pending, producing an inconsistent `unhandled_private_payments` table state and possible loss/duplication of a private payment's queued processing.

This does not directly allow double-spend or fund creation, but it does allow a single malicious counterparty message to reliably corrupt the wallet's private-payment processing loop/control-flow, which is a state-consistency/DoS-class issue on the wallet side (not a purely no-impact bug).

### Likelihood Explanation
Likelihood is High: the attacker only needs to send one private-payment chain whose head element's `payload` triggers an exception in `objectHash.getBase64Hash`. Since `savePrivatePayment` (used when queuing, i.e., `ifNew`/`ifKnownUnverified` in `handleOnlinePrivatePayment`) stores the JSON payload without first exercising this hashing call, the malformed payload reaches `handleSavedPrivatePayments`/`validateAndSave` unfiltered. No special privileges, hub cooperation, or race conditions on the attacker's side are required — a single crafted private-payment message from any paired device/counterparty is sufficient to trigger the double-processing.

### Recommendation
Add a `return` immediately after the error-handling branch in the `catch` block so the function stops executing once the hash computation fails and the private chain is being deleted:

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
        return deleteHandledPrivateChain(row.unit, row.message_index, row.output_index, cb);
    }
    var key = 'private_payment_validated-'+objHeadPrivateElement.unit+'-'+json_payload_hash+'-'+row.output_index;
    privatePayment.validateAndSavePrivatePaymentChain(arrPrivateElements, { ... });
};
```

This ensures `cb` is invoked exactly once per row and prevents the redundant second call into `privatePayment.validateAndSavePrivatePaymentChain` after an unrecoverable hashing failure.

### Proof of Concept
1. A malicious paired device sends a private payment to the victim's wallet via `handleOnlinePrivatePayment` with `arrPrivateElements[0].payload` crafted so that it is accepted and stored by `savePrivatePayment` (`INSERT ... INTO unhandled_private_payments`) but later causes `objectHash.getBase64Hash(payload, true)` to throw when re-processed (e.g., a payload field with a type/structure rejected internally by `object_hash.js`'s serialization routine, but not rejected by the earlier structural checks in `handleOnlinePrivatePayment`/`handlePrivatePaymentChains`).
2. On the next periodic call to `handleSavedPrivatePayments()` (triggered e.g. by `new_joint`/history sync events), the row is read from `unhandled_private_payments` and `validateAndSave` is invoked.
3. `objectHash.getBase64Hash` throws inside the `try`; the `catch` block runs `deleteHandledPrivateChain(row.unit, row.message_index, row.output_index, cb)` (async, will eventually call `cb`).
4. Execution does not stop: `key` is computed with `json_payload_hash === undefined`, and `privatePayment.validateAndSavePrivatePaymentChain(arrPrivateElements, {...})` is called immediately afterward, which will itself eventually invoke `cb` again through one of `ifOk`/`ifError`/`ifWaitingForChain`.
5. `cb` (the `async.each` iterator callback) is now called twice for the same row, and `deleteHandledPrivateChain` is racing/duplicated against a fresh validate-and-save attempt on the same DB row — observable via duplicated `console.log`/`sendResult` calls and inconsistent `unhandled_private_payments` state after the run.

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

**File:** network.js (L2523-2526)
```javascript
function deleteHandledPrivateChain(unit, message_index, output_index, cb){
	db.query("DELETE FROM unhandled_private_payments WHERE unit=? AND message_index=? AND output_index=?", [unit, message_index, output_index], function(){
		cb();
	});
```
