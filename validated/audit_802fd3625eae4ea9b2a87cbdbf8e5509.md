## Title
Missing `return` after error branch in `handleSavedPrivatePayments` causes double-processing/double-callback of malformed private payment chains - ([File: network.js])

### Summary
`network.js`'s `handleSavedPrivatePayments()` iterates over private payment chains that a private-payment counterparty (sender) delivered to the local wallet/hub, and for each one calls an inner `validateAndSave` closure that first computes a hash of the head element's payload. When that hash computation throws (e.g. a crafted/malformed payload from the counterparty that `objectHash.getBase64Hash` cannot serialize), the `catch` block reports the error and calls `deleteHandledPrivateChain(...)`, but it never returns out of the function afterward, so execution falls through to unconditionally invoke `privatePayment.validateAndSavePrivatePaymentChain(...)` on the very same, already-invalid element. [1](#0-0) 

### Finding Description
`deleteHandledPrivateChain` itself invokes the `cb` passed into the `async.each` iterator as soon as the DB delete completes: [2](#0-1) 

Because the enclosing `catch` block does not `return`, the same `cb` is captured again inside the `privatePayment.validateAndSavePrivatePaymentChain(...)` callbacks (`ifOk`, `ifError`, `ifWaitingForChain`), each of which also eventually calls `cb()`: [3](#0-2) 

This is directly analogous to the reported ERC20 issue: a call whose failure/return status is not checked (here, the thrown exception from the hash computation is only partially handled — the code logs it and starts cleanup but does not stop the rest of the function from running "as if nothing happened"), so the caller proceeds to treat the failed operation's data as if it were still valid input to further fund-affecting logic. Here the failure path still falls into calling the real chain-validation/save routine a second time with the "poisoned" `arrPrivateElements`, while the `async.each` completion callback (`cb`) for that row is invoked twice.

### Impact Explanation
`async.each`'s finishing callback is only supposed to fire once per item; the underlying `async` library invokes the group's completion callback (which calls `unlock()` on the `"saved_private"` mutex and emits `"new_my_transactions"`) as soon as all items have called back once — a second `cb()` call for the same row can trigger the completion function again or interleave with in-flight processing of other rows, releasing the `"saved_private"` mutex extra times. Since this mutex serializes processing of the wallet's incoming private-payment queue, a spurious/extra unlock can let a subsequent `handleSavedPrivatePayments` invocation start operating concurrently on `unhandled_private_payments` rows that are still being finalized, risking duplicate insertion attempts or a private chain being simultaneously validated/saved twice (`privatePayment.validateAndSavePrivatePaymentChain` runs concurrently for the same or overlapping rows). This can lead to state confusion in the wallet's private-asset bookkeeping (duplicate `ifOk` handling, duplicate `new_direct_private_chains` / `new_my_transactions` events) and, depending on downstream event consumers that credit balances or forward chains on these events, to double-accounting of a private asset payment — i.e. potential double-crediting/duplication of a private payment for the affected wallet.

### Likelihood Explanation
A private-payment counterparty (the sender of a private payment chain, which is an unprivileged party from the recipient's perspective) fully controls the JSON payload of the head private element that gets stored in `unhandled_private_payments` and later reloaded and parsed here. Crafting a payload that causes `objectHash.getBase64Hash` to throw (e.g., unsupported/circular data shapes accepted by `JSON.parse` but rejected by the hashing routine) is a normal, low-effort action for a private payment counterparty, making this reachable without any special privileges — it only requires sending or forwarding a specially crafted private payment chain to a target wallet.

### Recommendation
Add an explicit `return` after `deleteHandledPrivateChain(...)` inside the `catch` block of `validateAndSave` in `network.js` (around line 2476) so that on a hashing failure the function does not fall through to invoke `privatePayment.validateAndSavePrivatePaymentChain` a second time and does not risk calling `cb` more than once for the same `async.each` item.

### Proof of Concept
1. As a private-payment counterparty, construct a private payment chain whose head element's `payload` field is a value that `objectHash.getBase64Hash(objHeadPrivateElement.payload, true)` cannot hash (throws), while still passing the earlier `isNonemptyObject`/array checks used when the chain is queued into `unhandled_private_payments` (see `network.js` `handleOnlinePrivatePayment`).
2. Send this chain to a light wallet or hub; it gets stored via `savePrivatePayment` into `unhandled_private_payments`.
3. When `handleSavedPrivatePayments` later processes this row, `objectHash.getBase64Hash` throws inside `validateAndSave`; `deleteHandledPrivateChain` is called (calls `cb()` once the DB delete completes), but execution continues past the `catch` block and calls `privatePayment.validateAndSavePrivatePaymentChain(arrPrivateElements, {...})`, whose `ifError`/`ifOk`/`ifWaitingForChain` callback will call `cb()` again for the same row — resulting in `cb` being invoked twice for a single `async.each` item, prematurely/duplicately releasing the `"saved_private"` mutex and racing subsequent private-payment processing.

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

**File:** network.js (L2523-2526)
```javascript
function deleteHandledPrivateChain(unit, message_index, output_index, cb){
	db.query("DELETE FROM unhandled_private_payments WHERE unit=? AND message_index=? AND output_index=?", [unit, message_index, output_index], function(){
		cb();
	});
```
