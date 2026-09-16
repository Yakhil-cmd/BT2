### Title
Missing `return` after error branch in `handleSavedPrivatePayments` causes double-callback and corrupted serialization of private-payment validation - (File: network.js)

### Summary
In `network.js`, the `validateAndSave` closure inside `handleSavedPrivatePayments()` computes a payload hash and, on failure, deletes the DB record and invokes the async iterator callback `cb`, but falls through (no `return`) into the normal validation path that invokes `cb` again via `deleteHandledPrivateChain`/`eventBus` callbacks. This mirrors the CVE-2019-8956 bug class (a completion/free path is taken, but execution continues to reuse/re-trigger the same resource-completion handle), producing a double free of the async control-flow token that guards the mutex-serialized private-payment validation queue.

### Finding Description
`handleSavedPrivatePayments()` iterates unhandled private payments with `async.each`, serialized under the `mutex.lock(["saved_private"], ...)` lock that is meant to guarantee private payment chains are validated and applied one batch at a time [1](#0-0) .

Inside the per-row iterator, `validateAndSave` tries to hash the head private element's payload:
```
try {
    var json_payload_hash = objectHash.getBase64Hash(objHeadPrivateElement.payload, true);
}
catch (e) {
    ...
    deleteHandledPrivateChain(row.unit, row.message_index, row.output_index, cb);
}
var key = 'private_payment_validated-'+objHeadPrivateElement.unit+'-'+json_payload_hash+'-'+row.output_index;
privatePayment.validateAndSavePrivatePaymentChain(arrPrivateElements, { ... deleteHandledPrivateChain(..., cb) ... });
``` [2](#0-1) 

There is no `return` after the `catch` block's `deleteHandledPrivateChain(row.unit, row.message_index, row.output_index, cb)` call at line 2476. `deleteHandledPrivateChain` deletes the DB row and always calls `cb()` once the delete completes [3](#0-2) . Execution then continues past the catch block to call `privatePayment.validateAndSavePrivatePaymentChain(arrPrivateElements, ...)` on the same, now already-"freed" (DB row already deleted) chain, whose `ifOk`/`ifError`/`ifWaitingForChain` branches each also eventually call `cb()` (directly or through a second `deleteHandledPrivateChain`). This results in the `async.each` iterator callback `cb` being invoked twice for the same row — a "double free" of the completion token analogous to the use-after-free pattern in the CVE, where a handle is used again after the code path that finalizes/frees it has already run.

The `mutex` implementation explicitly protects against double-`unlock()` on the *outer* lock (`throw Error("double unlock?")` in `exec()`), but nothing protects the `async.each` iterator from being called twice by the caller code [4](#0-3) . Depending on the installed `async` version, a duplicate iterator callback either throws ("Callback was already called") — an uncaught exception inside the `mutex.lock(["saved_private"], ...)` critical section, which would leave the `saved_private` lock held forever (since `unlock()`, i.e., the lock's own callback at line 2513, is invoked from the `async.each` final callback that may never fire correctly after the double-callback corruption) — or silently completes the `async.each` early while other rows are still mid-validation, breaking the intended serialization of `validateAndSavePrivatePaymentChain` for concurrently pending private chains.

### Impact Explanation
The `saved_private` mutex exists specifically to serialize application of private (asset) payment chains so that conflicting/overlapping private spends are not validated concurrently. If the lock is stuck permanently (uncaught exception path), the wallet/node can no longer process any further private payments — a concrete freezing of private-payment fund handling reachable simply by a private-payment counterparty sending a malformed payload that makes `objectHash.getBase64Hash` throw. If instead the double-callback causes the `async.each` completion to fire early while other chains are still being validated in parallel, the intended one-at-a-time processing guarantee for private chains is violated, opening a race window where two conflicting private payment chains touching the same private output could be concurrently validated/saved instead of serially, risking a private double-spend being locally accepted.

### Likelihood Explanation
The trigger condition is a private payment message (received directly from a device/paired counterparty or via hub) whose head payload causes `objectHash.getBase64Hash` to throw — this is reachable by any private-payment counterparty crafting the payload of the head element of a private chain (`arrPrivateElements[0].payload`), which is attacker-controlled JSON stored in `unhandled_private_payments.json` prior to validation. No special privileges beyond being able to send a device message/private payment chain are required.

### Recommendation
Add a `return` immediately after the `catch` block's `deleteHandledPrivateChain(...)` call at line 2476 in `network.js` so the function does not fall through into `privatePayment.validateAndSavePrivatePaymentChain(...)` after the record has already been deleted and `cb` already invoked. This restores single-invocation semantics for the `async.each` iterator callback and preserves the serialization guarantee of the `saved_private` mutex lock.

### Proof of Concept
1. As a private-payment counterparty/paired device, send a private payment chain via `handlePrivatePaymentChains`/direct device message whose head element's `payload` object causes `objectHash.getBase64Hash(payload, true)` to throw (e.g., a payload containing a value type that `objectHash` cannot canonicalize/hash, such as a circular reference or unsupported type reachable via the parsed JSON).
2. The chain is queued into `unhandled_private_payments` and later picked up by `handleSavedPrivatePayments()`.
3. In `validateAndSave`, the hash computation throws; `deleteHandledPrivateChain(..., cb)` runs and calls `cb()` once the row is deleted.
4. Execution falls through (missing `return`) to `privatePayment.validateAndSavePrivatePaymentChain(arrPrivateElements, ...)`, which — regardless of outcome — invokes `cb()` a second time (via its own `ifOk`/`ifError` branch calling `deleteHandledPrivateChain` again, or `ifWaitingForChain` calling `cb()` directly).
5. `async.each`'s iterator callback (`cb`) is thus called twice for the same row, corrupting the `async.each` control flow that gates release of the `saved_private` mutex lock, either throwing inside the critical section (permanently locking `saved_private`) or completing early and breaking serialization with other in-flight private chain validations.

### Citations

**File:** network.js (L2450-2461)
```javascript
	var lock = unit ? mutex.lock : mutex.lockOrSkip;
	lock(["saved_private"], function(unlock){
		var sql = unit
			? "SELECT json, peer, unit, message_index, output_index, linked FROM unhandled_private_payments WHERE unit="+db.escape(unit)
			: "SELECT json, peer, unit, message_index, output_index, linked FROM unhandled_private_payments CROSS JOIN units USING(unit)";
		db.query(sql, function(rows){
			if (rows.length === 0)
				return unlock();
			var assocNewUnits = {};
			async.each( // handle different chains in parallel
				rows,
				function(row, cb){
```

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

**File:** network.js (L2523-2527)
```javascript
function deleteHandledPrivateChain(unit, message_index, output_index, cb){
	db.query("DELETE FROM unhandled_private_payments WHERE unit=? AND message_index=? AND output_index=?", [unit, message_index, output_index], function(){
		cb();
	});
}
```

**File:** mutex.js (L43-59)
```javascript
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
}
```
