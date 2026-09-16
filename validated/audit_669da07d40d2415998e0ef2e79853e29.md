### Title
Race Condition on Concurrent Private-Payment Chain Validation Leads to Double-Credit of the Same Private Coin - (File: private_payment.js)

### Summary
`privatePayment.validateAndSavePrivatePaymentChain()` performs a "check-if-duplicate" read followed by an insert/update of the private output on a **freshly acquired DB connection/transaction**, with no mutex or unique-key protection scoped to the specific output being claimed. When two chains for the *same* private output are processed concurrently (which the code explicitly does — network.js comments "handle different chains in parallel"), both can pass the duplicate check before either commits, and both proceed to record/credit the output, corrupting local wallet/asset state — the same "concurrent operation on shared mutable state without adequate serialization" bug class as the NetBSD `cryptodev_op()` double-free (CVE-2026-32848), translated to ocore's private-asset bookkeeping.

### Finding Description
`validateAndSavePrivatePaymentChain()` in [1](#0-0)  takes an independent DB connection per call and begins its own transaction: [2](#0-1) 

It then performs a SELECT to detect whether the output was already recorded (the "check if duplicate" query), and only after that check calls into `divisibleAsset`/`indivisibleAsset`'s `validateAndSavePrivatePaymentChain()` to actually insert/mark the output as spent: [3](#0-2) 

Nowhere in this path is a mutex acquired that is scoped to the specific `(unit, message_index, output_index)` (or the underlying source output being claimed). Compare this to the AA/joint-write paths and asset-transfer double-spend detection elsewhere in the codebase, which explicitly use `mutex.lock(["private_write"], ...)` or per-address/`handleJoint` locks before mutating shared state, e.g.: [4](#0-3) 

The consumer of this function, `handleSavedPrivatePayments()` in network.js, explicitly processes multiple queued private-payment rows **in parallel** with `async.each`: [5](#0-4) [6](#0-5) 

Because each parallel invocation opens its own DB transaction and only guards against duplicates via a read-then-write pattern inside that transaction (not via a lock keyed to the output identity), two concurrently-processed copies of the same private-payment chain (e.g., resent by a payment counterparty, or replayed via two different peers/paths before the first copy's row is deleted from `unhandled_private_payments`) can both pass the "is it already in `outputs`" check before either transaction commits its INSERT, then both commit independently. The `indivisible_asset.js`/`divisible_asset.js` save paths issue `INSERT ... IGNORE`/`UPDATE ... WHERE is_spent=0` statements per-chain, but these guard against overwriting a *finalized* record, not against two racing transactions that both read `is_spent=0`/no-row state simultaneously and both proceed to mark/insert the output as unspent-then-received twice, or to link two independent recipient chains to the same head output before either write is visible to the other.

This is directly analogous to the CVE-2026-32848 bug class: a per-session (here, per-output) mutable state object is validated and mutated by two concurrent workers without a lock keyed to that specific resource, because the locking granularity used elsewhere in the codebase (mutex keyed by address/unit, e.g. `mutex.lock(arrAuthorAddresses, ...)` in [7](#0-6) ) is absent here.

### Impact Explanation
If exploitable, an attacker acting as a private-payment counterparty could cause the wallet/hub to accept and credit the same private coin output twice concurrently, before the duplicate-check transaction of either copy becomes visible to the other. This is a concrete double-spend/double-credit of a private asset output — funds could be recorded as received twice locally, or an output could end up in an inconsistent `is_spent`/ownership state, directly matching the "double-spend of a stable output" / "unauthorized spending" impact criteria.

### Likelihood Explanation
Reachability requires only that an unprivileged private-payment counterparty (or a device sending a `private_payments` message) can cause the same chain to be queued and processed more than once concurrently — e.g., by sending the same private-payment chain via two different peers/messages in a short window, or by triggering re-processing before `deleteHandledPrivateChain` clears the earlier row. The DB race window is real because each call takes an independent connection with `BEGIN`, and the surrounding code explicitly parallelizes handling of different rows (`async.each`) without any output-scoped mutex.

### Recommendation
Add a mutex lock keyed on the private output's identity (e.g., `asset + unit + message_index + output_index`, or `src_unit/src_message_index/src_output_index` for the consumed input) around the duplicate-check-and-save sequence in `private_payment.js`'s `validateAndSavePrivatePaymentChain()`, similar to the `mutex.lock(["private_write"], ...)` pattern already used in `validation.js`. Alternatively/additionally, enforce a DB-level unique constraint that makes the "check duplicate" + insert atomic (e.g., use `INSERT ... ON CONFLICT DO NOTHING` /`INSERT IGNORE` guarded by a unique key on the output identity) instead of a separate SELECT followed by a later INSERT/UPDATE in a different code path.

### Proof of Concept
Conceptual (not verified end-to-end due to lack of runtime access):
1. Attacker (private-payment counterparty) sends the same private-payment chain to the victim node/wallet through two concurrent channels (e.g., two different peers, or a resend before the first is deleted from `unhandled_private_payments`).
2. `handleSavedPrivatePayments()` queues both rows and processes them via `async.each`, each invoking `privatePayment.validateAndSavePrivatePaymentChain()` on its own DB connection/transaction ( [8](#0-7) ).
3. Both transactions execute the duplicate-check SELECT ( [9](#0-8) ) before either has committed the INSERT/UPDATE performed by `divisible_asset.js`/`indivisible_asset.js`'s save routine, so both see "not yet present" and proceed to record the output.
4. Both transactions commit, resulting in the private output being credited/recorded twice.

Note: I was not able to fully trace every code path that queues private-payment chains for processing (e.g., all callers of `handleOnlinePrivatePayment`) within the available exploration, so the exact triggering sequence (which peer/device message paths can cause true duplicate concurrent processing before dedup) should be verified by a background agent with full repository and runtime access.

### Citations

**File:** private_payment.js (L23-44)
```javascript
function validateAndSavePrivatePaymentChain(arrPrivateElements, callbacks){
	if (!ValidationUtils.isNonemptyArray(arrPrivateElements))
		return callbacks.ifError("no priv elements array");
	var headElement = arrPrivateElements[0];
	if (!headElement.payload)
		return callbacks.ifError("no payload in head element");
	var asset = headElement.payload.asset;
	if (!asset)
		return callbacks.ifError("no asset in head element");
	if (!ValidationUtils.isNonnegativeInteger(headElement.message_index))
		return callbacks.ifError("no message index in head private element");
	
	var validateAndSave = function(){
		storage.readAsset(db, asset, null, function(err, objAsset){
			if (err)
				return callbacks.ifError(err);
			if (objAsset.is_private !== 1)
				return callbacks.ifError("asset is not private");
			if (!!objAsset.fixed_denominations !== !!headElement.payload.denomination)
				return callbacks.ifError("presence of denomination field doesn't match the asset type");
			if (!!objAsset.fixed_denominations !== ("output" in headElement))
				return callbacks.ifError("divisible asset must not have output field, indivisible must");
```

**File:** private_payment.js (L45-105)
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
					};
					// check if duplicate
					var sql = "SELECT address, denomination, amount, blinding FROM outputs WHERE unit=? AND asset=? AND message_index=?";
					var params = [headElement.unit, asset, headElement.message_index];
					if (objAsset.fixed_denominations){
						if (!ValidationUtils.isNonnegativeInteger(headElement.output_index))
							return transaction_callbacks.ifError("no output index in head private element");
						sql += " AND output_index=?";
						params.push(headElement.output_index);
					}
					conn.query(
						sql, 
						params, 
						function(rows){
							if (rows.length > 1)
								throw Error("more than one output "+sql+' '+params.join(', '));
							if (rows.length > 0 && rows[0].address){ // we could have this output already but the address is still hidden
								const stored = rows[0];
								const payload = headElement.payload;
								let bDuplicate = false;
								if (objAsset.fixed_denominations){ // the row we selected is exactly headElement.output_index, filtered in sql above
									const claimed_output = payload.outputs?.[headElement.output_index];
									const revealed_output = headElement?.output;
									bDuplicate =
										ValidationUtils.isNonemptyObject(claimed_output)
										&& ValidationUtils.isNonemptyObject(revealed_output)
										&& stored.denomination === payload.denomination
										&& stored.amount === claimed_output.amount
										&& stored.address === revealed_output.address
										&& stored.blinding === revealed_output.blinding;
								}
								else // divisible outputs are never hidden individually and sql has no output_index filter, so match against any of them
									bDuplicate = (payload.outputs || []).some(output => {
										return ValidationUtils.isNonemptyObject(output)
											&& stored.denomination === 1
											&& stored.amount === output.amount
											&& stored.address === output.address
											&& stored.blinding === output.blinding;
									});
								if (bDuplicate) {
									console.log("duplicate private payment "+params.join(', '));
									return transaction_callbacks.ifOk();
								}
							}
							var assetModule = objAsset.fixed_denominations ? indivisibleAsset : divisibleAsset;
							assetModule.validateAndSavePrivatePaymentChain(conn, arrPrivateElements, transaction_callbacks);
```

**File:** validation.js (L354-357)
```javascript
	if (!arrAuthorAddresses.every(isValidAddress))
		return callbacks.ifUnitError("invalid author address");

	mutex.lock(arrAuthorAddresses, function(unlock){
```

**File:** validation.js (L2283-2295)
```javascript
						mutex.lock(["private_write"], function(unlock){
							console.log("--- will ununique the conflicts of unit "+objUnit.unit);
							conn.query(
								sql, 
								doubleSpendVars, 
								function(){
									console.log("--- ununique done unit "+objUnit.unit);
									objValidationState.arrDoubleSpendInputs.push({message_index: message_index, input_index: input_index});
									unlock();
									cb3();
								}
							);
						});
```

**File:** network.js (L2443-2503)
```javascript
// if unit is undefined, find units that are ready
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
```
