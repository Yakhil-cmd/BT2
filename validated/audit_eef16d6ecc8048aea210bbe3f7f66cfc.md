## Title
Missing `return` after exception handling causes double-callback / mutex double-unlock analogous to `pci_slot_trylock()` unlock imbalance — ([File: network.js])

### Summary
`network.js`'s `handleSavedPrivatePayments()` protects processing of received private-payment chains with a `mutex.lock(["saved_private"], ...)` critical section. Inside the per-row iterator, the inner `validateAndSave()` closure has an error branch that — just like the PCI patch's leftover `pci_dev_unlock(dev)` on a path that no longer holds the lock — fails to `return` after triggering its own completion callback, so a single logical "unlock"/"done" event fires twice for the same `async.each` item.

### Finding Description
In `validateAndSave()`: [1](#0-0) 

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

If `objectHash.getBase64Hash()` throws (an attacker-supplied private-payment payload can be crafted to make hashing fail, e.g. a payload object that is not JSON-safe), the `catch` block calls `deleteHandledPrivateChain(..., cb)` — which will eventually invoke the shared `async.each` iterator callback `cb` once the DELETE completes — but execution then falls through (no `return`) into `privatePayment.validateAndSavePrivatePaymentChain(arrPrivateElements, {...})`. Every one of that function's callback branches (`ifOk`, `ifError`, `ifWaitingForChain`) also calls `cb()` (see lines 2486, 2495, 2501). The net effect is that `cb()` is invoked **twice** for the same row, exactly mirroring the underlying bug class in the report: an error/cleanup action (`unlock`) that should have been removed on a refactored path is left in place, firing redundantly.

`async.each`'s completion function then also has the potential to run more than once: [2](#0-1) 

```
},
function(){
    unlock();
    var arrNewUnits = Object.keys(assocNewUnits);
    if (arrNewUnits.length > 0)
        eventBus.emit("new_my_transactions", arrNewUnits);
}
```

`unlock()` here releases the process-wide `mutex.js` lock on key `["saved_private"]`. `mutex.js`'s `exec()`/`release()` model is exactly analogous to the kernel's per-object lock: each `unlock` closure tracks its own `bLocked` flag and calls `release(arrKeys)`, which removes the *first* array in `arrLockedKeyArrays` that is deep-equal to `["saved_private"]`: [3](#0-2) 

Because a new call to `handleSavedPrivatePayments()` (or any other code using the same key) can acquire `["saved_private"]` again as soon as the first (legitimate) `unlock()` runs and `handleQueue()` dispatches the next queued job, a second, stray `unlock()`/`release()` invocation triggered by the leftover callback path does **not** throw "double unlock?" (that check is local to the `exec()` closure and only fires if the *same* closure's `unlock` is called twice) — instead it matches and removes the *new, unrelated* job's entry from `arrLockedKeyArrays` via `_.isEqual`, releasing a lock that belongs to a different, currently-running critical section. This is precisely the "incorrect unlock of a lock that belongs to another thread" failure mode described in the CVE.

### Impact Explanation
Once the `"saved_private"` mutex is erroneously released mid-flight, two concurrent invocations of `handleSavedPrivatePayments()` (or of any other logic guarded by the same lock key) can execute in parallel over the same set of unhandled private payments. `validateAndSavePrivatePaymentChain` performs double-spend/uniqueness checks and inserts private outputs into the wallet's local database; without the serialization the mutex is meant to guarantee, the same private-payment chain can be validated and credited twice, or interleaved with a second in-flight chain touching the same private asset/output, allowing duplicated crediting of private payment amounts to the recipient's local ledger — a fund-accounting/double-spend-style corruption reachable purely by sending a crafted private-payment chain as a private-payment counterparty.

### Likelihood Explanation
Triggering the exception path only requires an attacker acting as a private-payment counterparty (or device peer) to send a private-payment chain whose head payload cannot be hashed by `objectHash.getBase64Hash` (any payload value that is not `JSON.stringify`-friendly, e.g. containing `undefined`, circular references, or unsupported types once parsed via `JSON.parse(row.json)`). This is a single-message trigger with no special timing requirement to reach the buggy code path; the resulting mutex corruption additionally requires a second job to be queued on `"saved_private"` at the right moment, which is plausible under normal wallet activity (multiple private payments arriving close together).

### Recommendation
Add a `return;` at the end of the `catch` block in `validateAndSave()` (network.js line ~2477) so that `deleteHandledPrivateChain(..., cb)` is the only path that invokes `cb` when hashing fails, and `privatePayment.validateAndSavePrivatePaymentChain(...)` is never called with data that already failed basic hashing. Additionally, consider hardening `mutex.js`'s `release()` to only remove an entry if it corresponds to the exact `unlock` closure that is being invoked (e.g. by tracking the closure/job reference rather than relying purely on `_.isEqual(arrKeys, ...)`), so a stray extra unlock cannot ever free a different, still-active critical section.

### Proof of Concept
1. As a device/private-payment counterparty, send a private-payment chain (`private_payments_chain` / `private_payment` message) whose head element's `payload` is crafted so `objectHash.getBase64Hash(payload, true)` throws (e.g. a payload containing a value that fails JSON round-tripping consistency used internally, or a maliciously large/circular nested object caught by `objectHash`'s internal hashing logic).
2. The payment is queued into `unhandled_private_payments` and later picked up by `handleSavedPrivatePayments()`.
3. Inside `validateAndSave()`, the `try` block throws; the `catch` branch calls `deleteHandledPrivateChain(..., cb)` and, due to the missing `return`, execution falls through and additionally invokes `privatePayment.validateAndSavePrivatePaymentChain(arrPrivateElements, {...})`, whose result callback also calls `cb`.
4. `cb` fires twice for the same `async.each` item; depending on timing, the `async.each` completion handler (which calls `unlock()`) can run again after a second job has already acquired the `"saved_private"` lock, causing that job's lock entry to be removed prematurely from `mutex.js`'s `arrLockedKeyArrays`.
5. With the lock freed early, a second concurrent private-payment validation/save can run in parallel with an unrelated one still in progress, allowing duplicate processing/crediting of private payment chains.

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

**File:** network.js (L2511-2518)
```javascript
				},
				function(){
					unlock();
					var arrNewUnits = Object.keys(assocNewUnits);
					if (arrNewUnits.length > 0)
						eventBus.emit("new_my_transactions", arrNewUnits);
				}
			);
```

**File:** mutex.js (L34-58)
```javascript
function release(arrKeys){
	for (var i=0; i<arrLockedKeyArrays.length; i++){
		if (_.isEqual(arrKeys, arrLockedKeyArrays[i])){
			arrLockedKeyArrays.splice(i, 1);
			return;
		}
	}
}

function exec(arrKeys, proc, next_proc){
	arrLockedKeyArrays.push(arrKeys);
	console.log("lock acquired", arrKeys);
	var bLocked = true;
	proc(function unlock(unlock_msg) {
		if (!bLocked)
			throw Error("double unlock?");
		if (unlock_msg)
			console.log(unlock_msg);
		bLocked = false;
		release(arrKeys);
		console.log("lock released", arrKeys);
		if (next_proc)
			next_proc.apply(next_proc, arguments);
		handleQueue();
	});
```
