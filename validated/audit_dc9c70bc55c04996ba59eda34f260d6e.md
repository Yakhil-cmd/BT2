### Title
Missing `return` after error path in `handleSavedPrivatePayments` causes malformed private payment chain to be validated and double-processed - (File: network.js)

### Summary
In `network.js`, the function `handleSavedPrivatePayments` builds a `validateAndSave` closure that computes `json_payload_hash` from the head private element's payload inside a `try/catch`. When `objectHash.getBase64Hash()` throws (e.g., the stored `unhandled_private_payments.json` contains a payload that cannot be hashed, such as one containing values not supported by `getJsonSourceString`/`getBase64Hash`), the `catch` block reports the error, deletes the chain record, and invokes the `async.each` iteration callback `cb()` — but does not `return` afterward. Execution falls through to compute `key` (using the now-`undefined` `json_payload_hash`) and calls `privatePayment.validateAndSavePrivatePaymentChain(...)`, which will itself eventually invoke `cb()` a second time via its `ifOk`/`ifError`/`ifWaitingForChain` handlers (through `deleteHandledPrivateChain`). [1](#0-0) 

### Finding Description
`handleSavedPrivatePayments(unit)` iterates rows from `unhandled_private_payments` — records queued when a private-payment counterparty (recipient/cosigner) sends a chain of private elements that could not yet be validated (e.g. `ifWaitingForChain`) or was received while catching up. For each row it defines:

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
        deleteHandledPrivateChain(row.unit, row.message_index, row.output_index, cb);
        // <-- MISSING return here
    }
    var key = 'private_payment_validated-'+objHeadPrivateElement.unit+'-'+json_payload_hash+'-'+row.output_index;
    privatePayment.validateAndSavePrivatePaymentChain(arrPrivateElements, { ... });
};
``` [1](#0-0) 

Because the `catch` block does not `return`, after handling the "unhashable payload" error and calling `deleteHandledPrivateChain(..., cb)` (which itself asynchronously deletes the DB row and then invokes the `async.each` callback `cb`), the same synchronous call stack continues on to build `key` with `json_payload_hash === undefined` and to call `privatePayment.validateAndSavePrivatePaymentChain(arrPrivateElements, {...})` on the same, already-known-malformed `arrPrivateElements`. This second call's callbacks (`ifOk`, `ifError`, or `ifWaitingForChain`) each ultimately call `cb()` again (directly, or by calling `deleteHandledPrivateChain` again), which means the `async.each` iterator callback for this row can fire twice.

This mirrors the reported bug class in the external report: a success/error check is effectively bypassed because execution proceeds past the point where it should have stopped (there, the code checked success *after* returning; here, the code fails to stop *after* handling the error), leading to continued processing of an item that should have been abandoned.

### Impact Explanation
Calling the `async.each` per-item callback (`cb`) twice for the same row is a violation of the async control-flow contract. Depending on the `async` library version and internal state, this can:
- Cause `handleSavedPrivatePayments`'s final callback (which calls `unlock()` and emits `"new_my_transactions"`) to fire prematurely or to be invoked with an inconsistent `assocNewUnits` state, before all rows have actually finished processing.
- Cause the process-wide `mutex.lock(["saved_private"], ...)` to be released and re-entered in an unexpected order, since `unlock()` in the final callback may run out of sync with the remaining outstanding private-chain validations still in flight.
- Cause `validateAndSavePrivatePaymentChain` to run its validate/save logic against a payload that already threw during a basic hashing operation, which is unexpected and not exercised by the normal validation path (the head element's payload is precisely the thing needed to compute `payload_hash` for indivisible/private asset validation), potentially leading to inconsistent acceptance/rejection of a private payment chain relative to what other nodes (or the same node, prior to this code path) would determine, i.e., a discrepancy in what the node considers a valid private payment for a stable output.

Because the mutex/lock ordering and callback invocation contract around unit saving is central to how ocore serializes joint/private-payment handling, a double-callback here can produce a divergence between the actual DB state (record deleted, or a validation outcome recorded) and the higher-level bookkeeping (`assocNewUnits`, event emission), which in the worst case affects whether a party is notified about / treats a private payment as valid twice or not at all.

### Likelihood Explanation
This path is reachable by an unprivileged private-payment counterparty: they simply need to have a chain of private elements queued into `unhandled_private_payments` (e.g., via `ifWaitingForChain`) whose head element's `payload` cannot be serialized/hashed by `objectHash.getBase64Hash` — for instance, by crafting the private payload with a structure that throws in `getJsonSourceString` (as also handled defensively elsewhere in `signed_message.js`/`getJsonSourceString`, which explicitly guards against nulls/empty objects for this exact reason). Triggering `getBase64Hash` to throw requires a malformed-but-attacker-controlled payload, since `arrPrivateElements` originates from data sent by the payer/counterparty and stored verbatim as JSON. This is a plausible, low-effort trigger for a legitimate (non-hub, non-peer-infrastructure) protocol participant.

### Recommendation
Add an explicit `return;` immediately after `deleteHandledPrivateChain(row.unit, row.message_index, row.output_index, cb);` inside the `catch` block in `validateAndSave` within `handleSavedPrivatePayments`, so execution does not fall through to compute `key` and call `validateAndSavePrivatePaymentChain` a second time on the same malformed data:

```js
catch (e) {
    console.log("getBase64Hash failed for private element", objHeadPrivateElement.payload, e);
    if (ws)
        sendResult(ws, {private_payment_in_unit: row.unit, result: 'error', error: e.toString()});
    return deleteHandledPrivateChain(row.unit, row.message_index, row.output_index, cb);
}
```

### Proof of Concept
1. As a private-payment counterparty, send a chain of private elements whose head `payload` object is structured so that `objectHash.getJsonSourceString`/`getBase64Hash` throws (e.g., contains a value type unsupported by the hashing routine, similar to the null/empty-object guard already present in `signed_message.js`).
2. Ensure the chain first gets queued into `unhandled_private_payments` via the `ifWaitingForChain` path in `handleReceivedPrivatePayment`.
3. Trigger `handleSavedPrivatePayments` (called when new units matching the chain arrive, or periodically for readiness checks).
4. Observe that `validateAndSave` for this row: (a) logs the hashing failure, sends an error result, and calls `deleteHandledPrivateChain(..., cb)`, then (b) without returning, proceeds to build `key` with `undefined` in place of `json_payload_hash` and calls `privatePayment.validateAndSavePrivatePaymentChain` on the same malformed chain, whose callback invokes `cb` a second time for the same `async.each` item — verifiable by instrumenting/logging `cb` invocation counts per row or by observing the `async.each` final callback / `unlock()` firing before all rows have truly completed. [2](#0-1)

### Citations

**File:** network.js (L2444-2521)
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
		});
	});
}
```
