### Title
Fall-through after caught hashing exception causes a private payment chain's completion callback to fire twice, corrupting `async.each` iteration and permanently stalling private-payment processing - (File: network.js)

### Summary
The CVE describes MiniSSDPd's `processRequest` calling `free()` twice on an error path because execution is not properly stopped after an error is handled, leading to an invalid free and daemon crash. The same bug class — failing to `return` after handling an error, so a completion/cleanup callback fires again later in the same function — exists in ocore's private-payment intake path in `handleSavedPrivatePayments()`.

### Finding Description
In `network.js`, `handleSavedPrivatePayments()` processes rows from `unhandled_private_payments` with `async.each`, one `cb` per row. Inside the per-row worker, `validateAndSave()` does: [1](#0-0) 

If `objectHash.getBase64Hash(objHeadPrivateElement.payload, true)` throws (e.g. because the payload JSON — which is attacker-controlled content coming from a private-payment counterparty/device message — contains a value type that `getSourceString`/`getJsonSourceString` cannot serialize, such as `undefined`, a function-like structure, or another value that triggers an "unknown type" throw in the hashing/source-string routines), the `catch` block already calls `deleteHandledPrivateChain(row.unit, row.message_index, row.output_index, cb)`, which itself invokes `cb` once the DELETE completes: [2](#0-1) 

Critically, the `catch` block does not `return`. Execution falls through to the line right after it, which unconditionally calls `privatePayment.validateAndSavePrivatePaymentChain(arrPrivateElements, {...})` using the same `cb`: [3](#0-2) 

That call's `ifOk`/`ifError`/`ifWaitingForChain` handlers each also invoke `cb` (via `deleteHandledPrivateChain(...,cb)` or directly), so `cb` for the same `async.each` item ends up invoked twice — once from the `catch` block's cleanup and once again from whichever branch `validateAndSavePrivatePaymentChain` resolves to. This double invocation of a completion callback inside an iteration/cleanup construct is the direct analog of the double-free/invalid-free pattern in the CVE: the code doesn't stop the control flow after already finalizing (freeing/cleaning up) the resource for that item.

The impact of a double `cb()` inside `async.each` depends on the async library version, but at minimum it desynchronizes the iteration counter that `async.each` uses to detect completion; this can cause the `async.each` final callback to fire prematurely/multiple times or never at all for the remaining unprocessed rows. Since that final callback is responsible for calling `unlock()` on the `"saved_private"` mutex key: [4](#0-3) 

a corrupted callback count can leave the `"saved_private"` mutex permanently held (mutex.js's own defense — `throw Error("double unlock?")` — protects mutex.js itself from a double-unlock crash, but does not protect the corrupted `async.each` bookkeeping upstream). A held `"saved_private"` lock means `handleSavedPrivatePayments()` (via `mutex.lock`/`mutex.lockOrSkip`) can never run again, so no further private payment chains for this node/wallet are ever validated or delivered — a node-wide processing stall triggerable by any private-payment counterparty who sends a single malformed private-payment JSON payload.

### Impact Explanation
An attacker acting as a private-payment counterparty (someone who can send a private payment/device message to a victim's wallet) can craft a payload whose `payload` object cannot be source-stringified/hashed, causing the exception path described above. This does not need to corrupt existing chain data; it only needs to reach the `catch` block. The resulting double callback corrupts the shared `async.each` completion bookkeeping and can leave the node's `"saved_private"` mutex key permanently locked, silently disabling all future private-payment intake for that node (denial of service against a specific counterparty's ability to process private/off-chain payments). This matches the "network unable to confirm new units"/processing-freeze criterion for Medium-severity issues, scoped to private payment chain handling (an explicitly in-scope reachable surface).

### Likelihood Explanation
Likelihood is moderate: it requires the attacker to construct a private-payment JSON payload whose content triggers a throw inside `getSourceString`/`getJsonSourceString` when hashing (e.g., unexpected/invalid field types not otherwise rejected before this point in the flow, since this happens before the chain has been fully validated by `validateAndSavePrivatePaymentChain`). No special privilege beyond being a private-payment counterparty (someone the victim already exchanges private payments with, or an untrusted peer sending a private chain directly) is required, and the code path is reached automatically whenever `unhandled_private_payments` rows are processed.

### Recommendation
Add a `return` immediately after the `deleteHandledPrivateChain(...)` call inside the `catch` block in `validateAndSave()` (network.js, around lines 2472–2477), so that once the error path has already invoked `cb`, execution cannot fall through and invoke `validateAndSavePrivatePaymentChain(...)`, which would call `cb` a second time. Additionally, consider wrapping worker callbacks with an "call-once" guard (similar to `async.ensureAsync`/a manual `bCalled` flag) as defense in depth for all `async.each` workers in this file that have multiple branches which each independently invoke `cb`.

### Proof of Concept
1. As a private-payment counterparty, send the victim node a private payment chain whose head element's `payload` contains a value that `getJsonSourceString`/`getSourceString` cannot serialize (e.g., a field with an unsupported type causing "unknown type" or similar throw in `string_utils.js`'s source-string builder), so that it lands in `unhandled_private_payments`.
2. When the victim calls `handleSavedPrivatePayments()`, the row is picked up by `async.each`; `validateAndSave()` throws inside the `try`, hits `catch`, and calls `deleteHandledPrivateChain(..., cb)` — invoking `cb` once.
3. Execution falls through (no `return`) to `privatePayment.validateAndSavePrivatePaymentChain(...)`, which resolves to one of `ifOk`/`ifError`/`ifWaitingForChain` and invokes `cb` a second time.
4. Observe that the `"saved_private"` mutex lock obtained at the top of `handleSavedPrivatePayments()` (network.js:2451) is never released for subsequent invocations (or the `async.each` final callback misfires), preventing the node from further processing entries in `unhandled_private_payments`, confirmed by no further "handleSavedPrivatePayments" activity and pending private payments never being delivered/confirmed.

### Citations

**File:** network.js (L2451-2521)
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

**File:** network.js (L2523-2526)
```javascript
function deleteHandledPrivateChain(unit, message_index, output_index, cb){
	db.query("DELETE FROM unhandled_private_payments WHERE unit=? AND message_index=? AND output_index=?", [unit, message_index, output_index], function(){
		cb();
	});
```
