### Title
Double-completion / stale-data continuation after a caught exception in `handleSavedPrivatePayments` — analogous "free-then-use" bug reachable by any private-payment counterparty - ([File: network.js])

### Summary
`network.js`'s `handleSavedPrivatePayments()` processes queued rows from `unhandled_private_payments` under the `["saved_private"]` mutex, using `async.each` to drive completion (`cb`) and eventual `unlock()`. Inside the per-row `validateAndSave` closure, a `try/catch` around `objectHash.getBase64Hash(objHeadPrivateElement.payload, true)` calls `deleteHandledPrivateChain(...)` (which deletes the row and invokes `cb()`, i.e. "consumes"/finalizes this unit of work) but is **missing a `return`** after the `catch` block, exactly mirroring the CVE-2022-48851 pattern where `netif_rx_ni(skb)` hands off/frees `skb` but the caller keeps dereferencing it afterward.

### Finding Description [1](#0-0) 

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
        deleteHandledPrivateChain(row.unit, row.message_index, row.output_index, cb);   // <-- deletes row + calls cb(), finalizing this item
    }
    var key = 'private_payment_validated-'+objHeadPrivateElement.unit+'-'+json_payload_hash+'-'+row.output_index;
    privatePayment.validateAndSavePrivatePaymentChain(arrPrivateElements, {              // <-- execution continues anyway
        ifOk: function(){ ... deleteHandledPrivateChain(row.unit, row.message_index, row.output_index, cb); ... },
        ifError: function(error){ ... deleteHandledPrivateChain(row.unit, row.message_index, row.output_index, cb); ... },
        ifWaitingForChain: function(){ ... cb(); }
    });
};
```

`deleteHandledPrivateChain` at [2](#0-1)  deletes the DB row and then invokes `cb()`. Once that happens, the row/iteration should be considered "freed"/finished from `async.each`'s point of view. Because there is no `return` in the `catch` block, control flow falls through and:
1. `json_payload_hash` is `undefined`, so `key` becomes a malformed string `'private_payment_validated-<unit>-undefined-<output_index>'`.
2. The code proceeds to call `privatePayment.validateAndSavePrivatePaymentChain(arrPrivateElements, ...)` on data whose payload has already been judged invalid/unhashable.
3. Whichever of `ifOk`/`ifError`/`ifWaitingForChain` fires will call `cb()` (and, for `ifOk`/`ifError`, `deleteHandledPrivateChain(...)`) **a second time** for the same `async.each` item.

This is the same bug class as `gdm_lte_rx()`: a resource/callback that was already handed off (and effectively "freed"/finalized) is dereferenced/used again afterward.

### Impact Explanation
`async.each`'s completion tracking is corrupted by the double invocation of `cb`. In common `async` implementations, calling the per-item callback more than once decrements/increments the internal remaining-count incorrectly, which can cause the `async.each` final callback (which calls `unlock()` on the `["saved_private"]` mutex and emits `new_my_transactions`) to fire **before** all rows have actually finished processing. Because `handleSavedPrivatePayments` is guarded by this same mutex to serialize processing of `unhandled_private_payments`, a premature `unlock()` allows another concurrent invocation (e.g. triggered by a new incoming private payment or timer) to start processing the same queue table while the first pass is still mid-flight for other rows, breaking the intended serialization. It can also cause a private-payment chain that was already flagged as erroneous to still be run through `privatePayment.validateAndSavePrivatePaymentChain`, and `new_my_transactions`/`all_private_payments_handled` style events to fire out of sync with actual completion, misleading wallet-side balance/UI logic and downstream watchers (e.g. `handledChainsCache`, AA/wallet listeners keyed off unit completion). This is reachable by any private-payment counterparty who can craft a payload that fails `objectHash.getBase64Hash` (e.g. a malformed/unexpected value type in the head private element's `payload`), since `arrPrivateElements` ultimately originates from a peer/hub `private_payment(s)` message and is stored verbatim into `unhandled_private_payments.json` before being read back and processed here.

### Likelihood Explanation
Any device paired with the victim, or peer sending a `private_payment` justsaying (via `handleOnlinePrivatePayment` → `unhandled_private_payments`), fully controls the JSON payload of the private element. `objectHash.getBase64Hash(payload, true)` performs strict type/shape validation of the payload during hashing and throws on unexpected content; a low-effort malformed private payment is sufficient to enter the `catch` branch on every retry of `handleSavedPrivatePayments` (called on every new incoming private payment and via periodic re-processing), making the race condition and stale-callback re-invocation reliably triggerable without any special privileges.

### Recommendation
Add a `return` immediately after `deleteHandledPrivateChain(...)` inside the `catch` block in `validateAndSave` (network.js, around line 2476) so that once the item has been finalized (row deleted, `cb()` invoked), no further code path re-invokes `cb()` or continues to use the already-finalized `arrPrivateElements`/`row`. As defense-in-depth, `deleteHandledPrivateChain`/`cb` usage in this function could also be hardened to tolerate/guard against double invocation (e.g. via a "handled" flag) to prevent similar completion-count corruption if other code paths regress in the future.

### Proof of Concept
1. As a paired device or peer, send a `private_payment` (or `private_payments`) message whose head element's `payload` is well-formed enough to pass the initial `wallet.js`/`network.js` structural checks (`isNonemptyObject`, `isNonemptyString(e.payload.asset)`, arrays of objects for `inputs`/`outputs`) but crafted so that `objectHash.getBase64Hash(payload, true)` throws (e.g., an output/input field with a type or numeric format objectHash's strict validator rejects, such as a non-integer amount or disallowed value type inside the payload object).
2. The message is queued into `unhandled_private_payments` and later processed by `handleSavedPrivatePayments`.
3. In `validateAndSave`, `getBase64Hash` throws; the code sends an error result, deletes the row, and calls `cb()` — then falls through (no `return`) and calls `privatePayment.validateAndSavePrivatePaymentChain(arrPrivateElements, ...)` regardless.
4. That call's `ifOk`/`ifError` callback invokes `deleteHandledPrivateChain(...)` (no-op DELETE) and `cb()` a second time for the same `async.each` iteration, corrupting the completion count and causing `unlock()` on `["saved_private"]` to be reached out of sync with the real completion state, enabling overlapping/concurrent processing of the `unhandled_private_payments` queue on subsequent calls to `handleSavedPrivatePayments`.

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

**File:** network.js (L2523-2525)
```javascript
function deleteHandledPrivateChain(unit, message_index, output_index, cb){
	db.query("DELETE FROM unhandled_private_payments WHERE unit=? AND message_index=? AND output_index=?", [unit, message_index, output_index], function(){
		cb();
```
