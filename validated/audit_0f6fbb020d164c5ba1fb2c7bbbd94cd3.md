### Title
Race condition in parallel private-payment-chain validation allows double-spend of a private asset output - ([File: network.js])

### Summary
`network.js`'s `handleSavedPrivatePayments()` deliberately validates multiple queued private payment chains **in parallel** (`async.each`, commented "handle different chains in parallel"), each opening its own DB connection/transaction and delegating to `private_payment.js`'s `validateAndSavePrivatePaymentChain()`, which performs a check-then-insert sequence with no cross-transaction serialization for the specific output/input being spent. This mirrors the `conquer-once` bug class: a shared mutable resource (spent/unspent output state) is accessed from concurrent execution contexts with an insufficient synchronization guarantee, allowing two conflicting operations to both observe a "not yet spent / not yet duplicate" state and commit, corrupting the invariant the lock/check was meant to protect. [1](#0-0) 

### Finding Description
`handleSavedPrivatePayments` acquires a coarse `mutex.lock(["saved_private"])` only to guard the *batch read* of `unhandled_private_payments`, then explicitly farms out validation/save of each private chain concurrently via `async.each`: [2](#0-1) 

Each chain's `validateAndSave` calls `privatePayment.validateAndSavePrivatePaymentChain`, which takes its own DB connection, begins its own transaction, performs a duplicate-output check, and then invokes the asset-specific validator (`divisibleAsset`/`indivisibleAsset`) before committing: [3](#0-2) 

Deeper in the call chain, spend validation for a `transfer` input relies on `checkInputDoubleSpend` in `validation.js`, which reads existing `inputs` rows to detect conflicts and only takes the `["private_write"]` mutex *after* a conflict is already found, to fix up `is_unique` flags on the losing record — it does not prevent two concurrently-running transactions from both reading "no existing spend of this source output" before either has committed its own `INSERT INTO inputs`: [4](#0-3) [5](#0-4) 

Because each private chain validation runs on an independent connection/transaction (`db.takeConnectionFromPool` + `BEGIN`...`COMMIT`), and `handleSavedPrivatePayments` intentionally processes them in parallel rather than serially, there is no atomic check-and-reserve of the source output across the concurrent transactions. This is functionally the same class of bug as `conquer-once`'s `OnceCell`: a primitive intended to provide mutual exclusion over shared state (`mutex.lock`, the duplicate-check `SELECT`) does not actually cover the critical section that matters (the specific source output being spent), so concurrent workers can race past the check and corrupt shared state.

### Impact Explanation
If an attacker (a private-payment counterparty, e.g., a malicious sender in a private-payment protocol who controls when/how chains are submitted, including submitting the same private output as two different payment chains to two different recipients, or via two delivery paths — direct P2P and via hub) can cause two conflicting private chains spending the same private output to be queued into `unhandled_private_payments` and processed by the same `handleSavedPrivatePayments` parallel batch, both chains' transactions can pass the duplicate/double-spend checks before either commits (particularly relevant when `conf.storage == "mysql"`, where transactions execute as real concurrent DB operations rather than serialized SQLite writes). Both chains would then be accepted, each recipient's wallet recording the private output as validly received — i.e., a double-spend of a private-asset output, resulting in supply/asset inflation for the affected private asset and loss of funds/trust for the party whose payment appears spent-but-still-valid elsewhere.

### Likelihood Explanation
Reaching this code path only requires posting private payment chains through normal wallet/device-message channels (`handleOnlinePrivatePayment`, `handlePrivatePaymentChains`), which any paired device / private-payment counterparty can do without special privileges. Triggering the race requires timing two conflicting chains to land in the same processing batch, which is plausible given `handleSavedPrivatePayments` runs on a periodic timer (`setInterval(handleSavedPrivatePayments, 5*1000)`) and processes all currently-queued rows in parallel via `async.each`. [6](#0-5) 

### Recommendation
Serialize validation/commit of private payment chains that reference the same source output (or more conservatively, the same asset) by acquiring a `mutex.lock` keyed on the specific `(unit, message_index, output_index)` / spend-proof before beginning the transaction in `private_payment.js`'s `validateAndSavePrivatePaymentChain`, and hold it until commit — mirroring what `["private_write"]` attempts to do for public-unit double-spend bookkeeping, but applied *before* the check rather than only after a conflict is detected. Alternatively, replace `async.each` with `async.eachSeries` in `handleSavedPrivatePayments`, or add a unique DB constraint on the spent-output identity enforced within the same transaction with `SELECT ... FOR UPDATE` semantics where the backend supports it.

### Proof of Concept
1. Attacker holds a private, divisible-asset output `O` at address `A`.
2. Attacker crafts two private payment chains, `Chain1` spending `O` to recipient `R1`, and `Chain2` spending `O` to recipient `R2`, both referencing the same source `(unit, message_index, output_index)` for `O`.
3. Attacker sends `Chain1` to `R1` and, within the same ~5-second processing window, sends `Chain2` to `R2` (or relays both via a hub configured with `conf.storage == "mysql"`), so both land in `unhandled_private_payments` before the next `handleSavedPrivatePayments` tick.
4. `handleSavedPrivatePayments` reads both rows and validates them concurrently via `async.each`, each on its own DB connection/transaction; `checkInputDoubleSpend`'s SELECT for existing spenders of `O` returns empty for both before either INSERT commits.
5. Both `Chain1` and `Chain2` pass validation and commit, so `R1` and `R2` both record the private output as validly received — a double-spend of the same private asset output.

### Citations

**File:** network.js (L2444-2465)
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
```

**File:** network.js (L4444-4445)
```javascript
	setInterval(joint_storage.purgeUncoveredNonserialJointsUnderLock, 60*1000);
	setInterval(handleSavedPrivatePayments, 5*1000);
```

**File:** private_payment.js (L45-107)
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
						}
					);
```

**File:** validation.js (L2258-2296)
```javascript
			function checkInputDoubleSpend(cb2){
			//	if (objAsset)
			//		profiler2.start();
				doubleSpendWhere += " AND unit != " + conn.escape(objUnit.unit);
				if (objAsset){
					doubleSpendWhere += " AND asset=?";
					doubleSpendVars.push(payload.asset);
				}
				else
					doubleSpendWhere += " AND asset IS NULL";
				// final-bad units are treated as non-existent competitors (their inputs.is_unique is kept NULL)
				var doubleSpendQuery = "SELECT "+doubleSpendFields+" FROM inputs " + doubleSpendIndexMySQL + " JOIN units USING(unit) WHERE "+doubleSpendWhere+" AND sequence!='final-bad'";
				checkForDoublespends(
					conn, "divisible input", 
					doubleSpendQuery, doubleSpendVars, 
					objUnit, objValidationState, 
					function acceptDoublespends(cb3){
						console.log("--- accepting doublespend on unit "+objUnit.unit);
						var sql = "UPDATE inputs SET is_unique=NULL WHERE "+doubleSpendWhere+
							" AND (SELECT is_stable FROM units WHERE units.unit=inputs.unit)=0";
						if (!(objAsset && objAsset.is_private)){
							objValidationState.arrAdditionalQueries.push({sql: sql, params: doubleSpendVars});
							objValidationState.arrDoubleSpendInputs.push({message_index: message_index, input_index: input_index});
							return cb3();
						}
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
					}, 
```

**File:** validation.js (L2402-2410)
```javascript
					var input_key = (payload.asset || "base") + "-" + input.unit + "-" + input.message_index + "-" + input.output_index;
					if (objValidationState.arrInputKeys.indexOf(input_key) >= 0)
						return cb("input "+input_key+" already used");
					objValidationState.arrInputKeys.push(input_key);
					
					doubleSpendWhere = "type=? AND src_unit=? AND src_message_index=? AND src_output_index=?";
					doubleSpendVars = [type, input.unit, input.message_index, input.output_index];
					if (conf.storage == "mysql")
						doubleSpendIndexMySQL = " FORCE INDEX(bySrcOutput) ";
```
