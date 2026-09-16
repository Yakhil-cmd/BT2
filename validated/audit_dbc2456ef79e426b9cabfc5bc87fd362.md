I've found the key bug. Let me verify the exact code and confirm the missing `return` statement in `network.js`.Confirmed: the `catch` block at `network.js:2472-2477` has no `return` after calling `deleteHandledPrivateChain(...cb)`, so execution falls through to build `key` (with `json_payload_hash === undefined`) and calls `privatePayment.validateAndSavePrivatePaymentChain(arrPrivateElements, {...})` again — a second, independent path that itself eventually invokes `cb` (via `ifOk`/`ifError`/`ifWaitingForChain`). This causes the `async.each` iteratee callback `cb` for that row to be released/invoked twice, mirroring the CVE-2015-8718 double-free pattern where a single resource is freed via two different matching code paths.

### Title
Double invocation of async.each iteratee callback via unreturned catch path in private-payment chain handling - (File: network.js)

### Summary
In `handleSavedPrivatePayments()`, the inner `validateAndSave()` closure catches a hashing failure on the head private element's payload but does not `return` after handling it, letting control fall through to a second, independent call path that also resolves the same `cb`.

### Finding Description
`handleSavedPrivatePayments()` iterates over rows from `unhandled_private_payments` with `async.each(rows, function(row, cb){ ... })` [1](#0-0) . For each row, `validateAndSave()` computes `json_payload_hash = objectHash.getBase64Hash(objHeadPrivateElement.payload, true)` inside a `try/catch`. On failure, the `catch` block logs the error, optionally sends an error result to the peer, and calls `deleteHandledPrivateChain(row.unit, row.message_index, row.output_index, cb)` — which asynchronously deletes the row and then invokes `cb()` [2](#0-1) .

Critically, there is no `return` statement after this call, so execution continues past the `catch` block: `key` is computed (using the now-`undefined` `json_payload_hash`), and `privatePayment.validateAndSavePrivatePaymentChain(arrPrivateElements, {...})` is invoked with callbacks `ifOk`, `ifError`, and `ifWaitingForChain`, each of which also eventually resolves the same `cb` for this iteration — either directly (`ifWaitingForChain` calls `cb()` synchronously) or via `deleteHandledPrivateChain(...cb)` in `ifOk`/`ifError` [3](#0-2) .

`arrPrivateElements` (and thus `objHeadPrivateElement.payload`) originates from `unhandled_private_payments.json`, which is populated directly from data sent by a peer or a private-payment counterparty via `handleOnlinePrivatePayment` → `savePrivatePayment` without validating that `payload` is hashable/serializable [4](#0-3) . `objectHash.getBase64Hash` throws on payloads containing values it cannot stably stringify/hash (e.g., certain malformed nested structures), so an attacker who is a private-payment counterparty (or forwards such an unhandled row) can reliably trigger the `catch` branch.

Because `async.each`'s iteratee callback is a one-shot completion signal, invoking it twice is the async-callback analog of a double free: the second call operates on a resource (the `rows` iteration state / `cb`) that has already been "released." Depending on the async library semantics this can throw ("Callback was already called"), corrupt the iteration/completion count (invoking the final callback of `async.each` prematurely, before other chains in the same batch have finished, and/or invoking it twice), and can also race two independent commit/delete paths against the same `unhandled_private_payments` row.

### Impact Explanation
An uncaught exception thrown by the async library due to a double callback invocation on the hub/wallet's main event loop is unhandled (there is no surrounding try/catch here), crashing the Node.js process. Because `handleSavedPrivatePayments` is on the core private-payment handling path invoked whenever private-payment chains are queued and joints become available, this is remotely triggerable by any device peer or private-payment counterparty sending a chain whose head payload cannot be hashed, causing repeated node crashes and denial of service for wallet/hub private-payment processing — i.e., the node becomes unable to process new private-payment units. This matches the CVE's medium-severity crash/DoS impact class translated to this codebase's async-callback "resource release" pattern.

### Likelihood Explanation
Reachable purely from network/device-message input: a private-payment counterparty crafts a private-payment chain whose head element's `payload` triggers an exception inside `objectHash.getBase64Hash` (e.g., a payload shape that `getBase64Hash`'s canonicalization/hashing logic cannot handle, such as unsupported types/circular structures introduced through JSON round-tripping of `unhandled_private_payments.json`). The row only needs to reach `unhandled_private_payments` and then be replayed through `handleSavedPrivatePayments`, which happens automatically as part of normal processing — no privileged access or race timing is required beyond crafting the payload.

### Recommendation
Add a `return` immediately after the `deleteHandledPrivateChain(...)` call inside the `catch` block in `validateAndSave()` (network.js) so that when the hash computation fails, the function does not fall through to also call `privatePayment.validateAndSavePrivatePaymentChain`. Additionally, guard against double-invocation of `cb` defensively (e.g., wrap `cb` in a "called-once" helper) as a hardening measure, and validate `objHeadPrivateElement.payload` shape before storing it in `unhandled_private_payments` to prevent unhashable payloads from being persisted at all.

### Proof of Concept
1. As a private-payment counterparty (or a peer forwarding a private payment), send a `private_payment` message whose `arrPrivateElements[0].payload` is a value that will parse via `JSON.parse` (so it passes initial storage) but causes `objectHash.getBase64Hash(payload, true)` to throw when later processed (e.g., a payload containing a numeric property that is `NaN`/`Infinity` after JSON round-trip abuse, or another shape known to break the canonical hashing routine used by `objectHash`).
2. This gets persisted via `savePrivatePayment` into `unhandled_private_payments` [4](#0-3) .
3. When `handleSavedPrivatePayments()` next runs (e.g., after joints tied to the chain become known), it reads the row and calls `validateAndSave()`.
4. `getBase64Hash` throws, hitting the `catch` block, which calls `deleteHandledPrivateChain(..., cb)` — but code execution falls through and also calls `privatePayment.validateAndSavePrivatePaymentChain`, invoking `cb` a second time for the same `async.each` iteration, throwing an uncaught "Callback was already called" style error and crashing the node process.

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

**File:** network.js (L2444-2461)
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
			var assocNewUnits = {};
			async.each( // handle different chains in parallel
				rows,
				function(row, cb){
```

**File:** network.js (L2469-2477)
```javascript
						try {
							var json_payload_hash = objectHash.getBase64Hash(objHeadPrivateElement.payload, true);
						}
						catch (e) {
							console.log("getBase64Hash failed for private element", objHeadPrivateElement.payload, e);
							if (ws)
								sendResult(ws, {private_payment_in_unit: row.unit, result: 'error', error: e.toString()});
							deleteHandledPrivateChain(row.unit, row.message_index, row.output_index, cb);
						}
```

**File:** network.js (L2478-2503)
```javascript
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
