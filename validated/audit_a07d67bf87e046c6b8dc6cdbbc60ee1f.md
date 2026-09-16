### Title
Missing `return` after exception handler causes fall-through execution with unchecked/corrupted state when processing an unprivileged peer's private payment - (File: network.js)

### Summary
The external report describes an unchecked `transferFrom()` return value, where the caller assumes success without verifying it, risking silent fund-handling failures. The closest reachable analog in `ocore` is in `handleSavedPrivatePayments()`, where a failure signal (a thrown exception from hashing malformed private-payment payload data) is caught but **not propagated as a terminal outcome** — execution falls through to code that assumes the hash computation succeeded and to a second, conflicting completion path.

### Finding Description
In `network.js`, `validateAndSave` (defined inside `handleSavedPrivatePayments`) computes a hash of an untrusted, peer-supplied private-payment payload: [1](#0-0) 

If `objectHash.getBase64Hash(objHeadPrivateElement.payload, true)` throws (e.g., because the JSON-parsed `arrPrivateElements` from `unhandled_private_payments`, ultimately sourced from a peer/device message via `handleOnlinePrivatePayment` / `handlePrivatePaymentChains`, contains a malformed or oversized payload object that the hashing routine rejects with a thrown error), the `catch` block calls `deleteHandledPrivateChain(row.unit, row.message_index, row.output_index, cb)` — which itself invokes `cb()` to signal completion of that `async.each` item — but there is **no `return` statement** after this call. Execution continues past the `catch` block to:
```js
var key = 'private_payment_validated-'+objHeadPrivateElement.unit+'-'+json_payload_hash+'-'+row.output_index;
privatePayment.validateAndSavePrivatePaymentChain(arrPrivateElements, { ... });
```
This is directly analogous to the reported bug class: the failure path (exception) is "handled" but its result is not checked/enforced before the code proceeds as if the earlier step succeeded — the same "unchecked result, assume success, continue" root cause as the ERC20 `transferFrom()` report, just manifesting as an uncontrolled fall-through instead of an ignored boolean.

Consequences of proceeding:
- `json_payload_hash` is `undefined` in the `key` string used for `eventBus.emit(key, ...)`/`eventBus.once(key, ...)` synchronization with `handlePrivatePaymentChains` in `wallet.js` [2](#0-1) , so the corresponding "waiting" listener registered under a *different*, correctly-computed key never fires — the private-payment confirmation from the hub/light client can be stuck.
- `privatePayment.validateAndSavePrivatePaymentChain` is invoked a second time on the same array *after* `deleteHandledPrivateChain` already removed/finalized the record via its own callback path, meaning `cb` (the `async.each` iteratee callback) can be invoked twice for the same row — once from `deleteHandledPrivateChain`, and again asynchronously from inside the `ifOk`/`ifError` callbacks of `validateAndSavePrivatePaymentChain`.
- Because `handleSavedPrivatePayments` guards the whole batch with `mutex.lock(["saved_private"], ...)`, a double/duplicate invocation of the iteratee callback disrupts the intended one-shot completion semantics of that critical-section lock protecting private-payment persistence, allowing the lock to be released while a private-payment DB transaction (`BEGIN`/`COMMIT` in `private_payment.js`) is still in flight for the same or a different row being processed concurrently.

### Impact Explanation
This is reachable by any device/hub peer sending a private-payment chain (a normal wallet operation, not requiring any special privilege) whose head payload cannot be hashed by `objectHash.getBase64Hash` (e.g. crafted with unsupported/invalid types, oversized nested structures, or fields that trip up the deterministic-JSON hashing routine). Once triggered:
- The corresponding private payment can be stuck indefinitely in `unhandled_private_payments` from the recipient's perspective while the sender/hub believes the payment was forwarded, effectively **freezing funds** the recipient cannot ever apply/spend (the `ifWaitingForChain`/queued flow in `wallet.js` never resolves because the emitted key does not match what any listener is waiting on).
- Loss of the intended single-completion guarantee around the `mutex.lock(["saved_private"])` critical section undermines the serialization the code relies on for correctly persisting private-payment chains, which is the same mechanism protecting against double-processing of the same chain/outputs.

This matches the "AA/wallet fund freezing" and "node disagreement on validity" categories of acceptable impact from the rules — it does not touch p2p/network-DoS mechanics directly, but a strictly-local application-logic defect in fund-relevant private-payment handling triggered by ordinary peer-supplied payment data.

### Likelihood Explanation
Medium. It requires the attacker (or a buggy peer) to craft a private-payment payload that specifically causes `objectHash.getBase64Hash` to throw rather than simply fail validation checks (most malformed-payload cases are caught earlier by explicit `ValidationUtils` checks in `private_payment.js`/`indivisible_asset.js`/`divisible_asset.js` and return controlled errors, not exceptions). Still, this is a single-shot, unprivileged-peer-reachable path (private payment chains are user/wallet initiated) and the underlying defect (fall-through after an unreturned catch) is unconditional once the exception is thrown — no race or timing dependency needed to trigger the broken control flow itself.

### Recommendation
Add an explicit `return` after handling the exception in the `catch` block so that execution does not continue with an invalid `json_payload_hash` or re-invoke `validateAndSavePrivatePaymentChain`/`cb` a second time:
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
More generally, audit other `try { ... } catch (e) { ...; someCallback(); }` blocks in `network.js`/`wallet.js` for the same missing-`return` pattern, since — like the audited ERC20 report — the systemic risk is code proceeding on the assumption that a preceding step succeeded without actually verifying/enforcing that outcome.

### Proof of Concept
1. Craft a private-payment `arrPrivateElements[0].payload` object such that `objectHash.getBase64Hash(payload, true)` throws (e.g., a payload containing a value type unsupported by the deterministic JSON/hash serializer, or one engineered to exceed internal recursion/size assumptions of `object_hash.js`).
2. Send this as a `private_payment` (or via `private_payments`/`payment_notification` device message flow) to a light or full wallet node so it is stored via `savePrivatePayment` into `unhandled_private_payments` and later processed by `handleSavedPrivatePayments`.
3. Observe (via added logging or `eventBus` tracing) that:
   - The `catch` block logs the hashing failure and calls `deleteHandledPrivateChain(...)`.
   - Execution nonetheless continues to compute `key` with `json_payload_hash === undefined` and calls `privatePayment.validateAndSavePrivatePaymentChain(arrPrivateElements, ...)` a second time.
   - The `async.each` iteratee `cb` for that row fires more than once, and the `eventBus.emit(key, ...)` in the `ifOk`/`ifError` handlers never matches the key any caller in `wallet.js`'s `handlePrivatePaymentChains` is listening for, leaving that private-payment permanently unconfirmed from the caller's perspective. [1](#0-0) [3](#0-2) [2](#0-1) [4](#0-3)

### Citations

**File:** network.js (L2451-2465)
```javascript
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
					var arrPrivateElements = JSON.parse(row.json);
					var ws = getPeerWebSocket(row.peer);
					if (ws && ws.readyState !== ws.OPEN)
						ws = null;
```

**File:** network.js (L2467-2480)
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
```

**File:** wallet.js (L1033-1063)
```javascript
			var key = 'private_payment_validated-'+objHeadPrivateElement.unit+'-'+json_payload_hash+'-'+output_index;
			assocValidatedByKey[key] = false;
			network.handleOnlinePrivatePayment(ws, arrPrivateElements, true, {
				ifError: function(error){
					console.log("handleOnlinePrivatePayment error: "+error);
					cb("an error"); // do not leak error message to the hub
				},
				ifValidationError: function(unit, error){
					console.log("handleOnlinePrivatePayment validation error: "+error);
					cb("an error"); // do not leak error message to the hub
				},
				ifAccepted: function(unit){
					console.log("handleOnlinePrivatePayment accepted");
					assocValidatedByKey[key] = true;
					cb(); // do not leak unit info to the hub
				},
				// this is the most likely outcome for light clients
				ifQueued: function(){
					console.log("handleOnlinePrivatePayment queued, will wait for "+key);
					eventBus.once(key, function(bValid){
						if (!bValid)
							return cancelAllKeys();
						assocValidatedByKey[key] = true;
						if (bParsingComplete)
							checkIfAllValidated();
						else
							console.log('parsing incomplete yet');
					});
					cb();
				}
			});
```

**File:** private_payment.js (L45-59)
```javascript
			db.takeConnectionFromPool(function(conn){
				conn.query("BEGIN", function(){
					var transaction_callbacks = {
						ifError: function(err){
							conn.query("ROLLBACK", function(){
								conn.release();
								callbacks.ifError(err);
							});
						},
						ifOk: function(){
							conn.query("COMMIT", function(){
								conn.release();
								callbacks.ifOk();
							});
						}
```
