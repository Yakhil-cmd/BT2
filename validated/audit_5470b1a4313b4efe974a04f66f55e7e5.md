### Title
Missing `return` after error handling causes double invocation of the async iteration callback in private-payment processing, crashing the node via a double mutex unlock - ([File: network.js])

### Summary
`handleSavedPrivatePayments()` in `network.js` processes attacker-reachable private-payment chains stored in `unhandled_private_payments`. In its inner `validateAndSave` closure, a `try/catch` around `objectHash.getBase64Hash()` fails to `return` after handling the exception in the `catch` block, so execution falls through and re-enters the validation/save path a second time for the same item, leading to the shared `cb` (the `async.each` iteratee-completion callback) being invoked twice for one item. This is the same bug *class* as CVE-2026-31053 (a resource-release routine invoked more than once on error paths), here manifesting as a double-invocation of a completion/"free" callback instead of a C `free()`, with an analogous crash/DoS outcome.

### Finding Description
In [1](#0-0) , `validateAndSave` does:
```js
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
`deleteHandledPrivateChain(..., cb)` asynchronously calls `cb()` once its `DELETE` query completes [2](#0-1) . Because the `catch` block does not `return`, execution continues past it and calls `privatePayment.validateAndSavePrivatePaymentChain(arrPrivateElements, {...})` again, whose `ifOk`/`ifError`/`ifWaitingForChain` callbacks each also eventually call `cb()` [3](#0-2) . The result: for a single `row` (one item passed to `async.each`), the iteratee callback `cb` fires twice.

This `cb` is the completion callback of `async.each(rows, function(row, cb){...}, function(){ unlock(); ... })` [4](#0-3) . Calling an `async.each` iteratee callback more than once for the same item causes the library's internal completion counter to be decremented an extra time, which can cause the final callback `function(){ unlock(); ... }` to fire prematurely or more than once. `unlock` here comes from `mutex.lock(["saved_private"], ...)` [5](#0-4) , and `mutex.js`'s `exec()` explicitly guards against being unlocked twice by throwing:
```js
proc(function unlock(unlock_msg) {
    if (!bLocked)
        throw Error("double unlock?");
    ...
});
``` [6](#0-5) 

The trigger to reach `getBase64Hash` throwing is attacker-controllable: `objHeadPrivateElement.payload` originates from JSON supplied by a private-payment counterparty (or forwarded via the hub) through `handleOnlinePrivatePayment` / `handlePrivatePaymentChains`, stored verbatim into `unhandled_private_payments.json` [7](#0-6)  and later reloaded and `JSON.parse`d in `handleSavedPrivatePayments` without any schema/serializability validation before hashing [8](#0-7) . A payload crafted with values that make `objectHash.getBase64Hash` throw (e.g., unsupported/invalid types for the deterministic hashing routine) reliably reaches the double-`cb` path.

### Impact Explanation
When the mutex is unlocked twice, `mutex.js` throws an unhandled `Error("double unlock?")` inside an asynchronous DB callback context, which is not caught anywhere in this call chain. This crashes the wallet/node process — a denial-of-service condition matching the CVE's outcome ("cause the application to crash, resulting in a denial-of-service condition"). Because the `"saved_private"` mutex key governs processing of all queued private payments, a crash/restart loop or a permanently stuck lock also blocks further private-payment (and, by extension, dependent wallet) processing until the operator intervenes, which is a legitimate node/wallet availability impact reachable purely by a private-payment counterparty sending one malformed payload.

### Likelihood Explanation
Likelihood is fairly high for a targeted attacker: they only need to be a private-payment counterparty (or someone forwarding a payload through the hub to a light wallet) and craft a `payload` object that causes `getBase64Hash` to throw. No special privileges, node-operator access, or race conditions across multiple peers are required — a single malicious chain sent to `handleOnlinePrivatePayment`/`handlePrivatePaymentChains` is enough to populate `unhandled_private_payments` and eventually get replayed through `handleSavedPrivatePayments`.

### Recommendation
Add a `return` (or restructure to an `if/else`) after handling the `catch` block in `validateAndSave` so that execution does not fall through to call `privatePayment.validateAndSavePrivatePaymentChain` a second time:
```js
try {
    var json_payload_hash = objectHash.getBase64Hash(objHeadPrivateElement.payload, true);
}
catch (e) {
    console.log("getBase64Hash failed for private element", objHeadPrivateElement.payload, e);
    if (ws)
        sendResult(ws, {private_payment_in_unit: row.unit, result: 'error', error: e.toString()});
    return deleteHandledPrivateChain(row.unit, row.message_index, row.output_index, cb);
}
```
Additionally, harden `async.each`/`cb` usage patterns generally (guard `cb` so it can only fire once per item, e.g., wrap with a "call-once" helper), and consider making `mutex.js`'s unlock error recoverable (log + ignore) rather than an uncaught throw, to reduce the blast radius of any similar latent double-callback bugs elsewhere in the codebase.

### Proof of Concept
1. As a device paired with the victim wallet (or via the hub), send a `private_payments` message whose chain's head element has a `payload` that causes `objectHash.getBase64Hash` to throw when serialized/hashed deterministically (e.g., a payload containing a value type not supported by the deterministic JSON/hash serializer used by `object_hash.js`, such as a `bigint`, or a self/duplicate-referencing structure introduced during composition that survives `JSON.stringify`/`JSON.parse` round-trip but fails the hash function's stricter type checks).
2. This gets persisted to `unhandled_private_payments` via `savePrivatePayment` in `handleOnlinePrivatePayment` [7](#0-6) .
3. When `handleSavedPrivatePayments()` next runs (triggered periodically/on new unit), it loads the row, `JSON.parse`s it, and calls `validateAndSave()`, hitting the `getBase64Hash` throw, taking the `catch` path, and then falling through to call `validateAndSavePrivatePaymentChain` again — invoking `cb` twice for the same `row`.
4. The doubled completion signal drives the `async.each` final callback to invoke `unlock()` more than once on the `"saved_private"` mutex key, and `mutex.js`'s `exec()` throws `Error("double unlock?")` in the `db.query` callback, crashing the node process.

Note: I was not able to directly inspect `object_hash.js`'s `getBase64Hash`/`getSourceString` implementation within the available context to enumerate the exact input values that throw (index size limits truncated that lookup). Confirming the precise malformed-payload trigger for the `throw` would require starting a Devin session with full repository access to read `object_hash.js` in detail and test candidate payloads.

### Citations

**File:** network.js (L2390-2401)
```javascript
	var savePrivatePayment = function(cb){
		// we may receive the same unit and message index but different output indexes if recipient and cosigner are on the same device.
		// in this case, we also receive the same (unit, message_index, output_index) twice - as cosigner and as recipient.  That's why IGNORE.
		db.query(
			"INSERT "+db.getIgnore()+" INTO unhandled_private_payments (unit, message_index, output_index, json, peer) VALUES (?,?,?,?,?)", 
			[unit, message_index, output_index, JSON.stringify(arrPrivateElements), bViaHub ? '' : ws.peer], // forget peer if received via hub
			function(){
				callbacks.ifQueued();
				if (cb)
					cb();
			}
		);
```

**File:** network.js (L2450-2451)
```javascript
	var lock = unit ? mutex.lock : mutex.lockOrSkip;
	lock(["saved_private"], function(unlock){
```

**File:** network.js (L2459-2518)
```javascript
			async.each( // handle different chains in parallel
				rows,
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

**File:** network.js (L2523-2525)
```javascript
function deleteHandledPrivateChain(unit, message_index, output_index, cb){
	db.query("DELETE FROM unhandled_private_payments WHERE unit=? AND message_index=? AND output_index=?", [unit, message_index, output_index], function(){
		cb();
```

**File:** mutex.js (L43-58)
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
```
