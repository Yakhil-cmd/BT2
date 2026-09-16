### Title
Race condition between concurrent private-payment-chain validations allows double-spend of a private output - ([File: private_payment.js])

### Summary
`private_payment.js`'s `validateAndSavePrivatePaymentChain()` and its per-asset-type counterparts in `divisible_asset.js`/`indivisible_asset.js` validate and commit private payment chains on their **own** freshly-taken DB connection/transaction, without ever acquiring the `arrAuthorAddresses` mutex that the normal unit-validation path (`validation.validate()`) uses to serialize double-spend checks for the same address. Two private-chain validations that spend the *same* private output can therefore run concurrently on two separate connections, both pass the double-spend check before either commits, and both get accepted — an analog of the ext4 race where two code paths mutate/observe shared state under different locks (xattr_sem vs i_rwsem) with no common serialization point.

### Finding Description
The public/serial validation entry point `validate()` in `validation.js` funnels all unit validation for a set of author addresses through a single mutex before doing anything DB-visible: [1](#0-0) 

That mutex lock is what prevents two concurrent validations against the same author address from racing past `checkForDoublespends`/`checkInputDoubleSpend`.

However, **private payment chains never go through `validate()`**. They are validated and saved directly via `private_payment.js`: [2](#0-1) 

which takes its own `db.takeConnectionFromPool()` + `BEGIN` and, after a "duplicate" check limited to the *same* output row, dispatches to the asset-specific saver: [3](#0-2) 

The asset-specific path (`divisible_asset.js` / `indivisible_asset.js`) calls `validation.validatePayment()` directly — the same double-spend logic used by `validate()`, but invoked **without** the `mutex.lock(arrAuthorAddresses, ...)` wrapper: [4](#0-3) [5](#0-4) 

Inside `validatePaymentInputsAndOutputs`, the double-spend check queries the `inputs` table for conflicting spends of the same `src_unit/src_message_index/src_output_index`, and only takes a lock (`private_write`) in the narrow "accept doublespend" branch — not around the initial existence check itself: [6](#0-5) 

Because private-chain validation opens a brand-new connection/transaction per invocation (`private_payment.js:45`) and is dispatched in parallel for multiple chains (`network.js` `handleSavedPrivatePayments` uses `async.each`, and `wallet.js` `handlePrivatePaymentChains` processes each chain independently), two concurrent private-chain validations that spend the same private output can each run their `SELECT ... FROM inputs WHERE src_unit=... AND src_message_index=... AND src_output_index=...` check before either has committed its own `INSERT INTO inputs`. Neither sees the other's pending spend, both pass validation, and both `INSERT`/`UPDATE outputs SET is_spent=1` succeed in their own transactions.

This mirrors the ext4 CVE precisely: the write path (`ext4_write`/`generic_perform_write`) and the state-mutating path (`ext4_convert_inline_data`) each held a different lock (`i_rwsem` vs `xattr_sem`) and could interleave because there was no shared lock guarding the state flag; here, the canonical unit-validation path is serialized by the `arrAuthorAddresses` mutex, but the private-payment-chain path bypasses that mutex entirely and relies only on per-connection transaction isolation, which does not prevent the interleaving described above under READ-COMMITTED/REPEATABLE-READ MySQL semantics (the configuration explicitly supported by `conf.storage === 'mysql'` throughout this codebase).

### Impact Explanation
A malicious private-payment counterparty (or a device forwarding the same chain via two peers/connections) can cause a full node to accept two different consuming private-payment chains for the same underlying private output before either transaction commits. This is a double-spend of a stable private output — funds that should be spendable only once are effectively spent twice, causing loss of funds for the legitimate recipient/asset holder and node disagreement on which chain is valid once both are persisted.

### Likelihood Explanation
The attack requires only sending crafted/duplicated private-payment chain data through two concurrent channels reachable by any private-payment counterparty (e.g., `wallet.js handlePrivatePaymentChains` and/or `network.js handleOnlinePrivatePayment`/`handleSavedPrivatePayments`), which is normal unprivileged wallet-to-wallet/hub traffic. No special network position or node compromise is needed — only timing of two roughly simultaneous submissions of chains spending the same private output, which an attacker fully controls.

### Recommendation
Serialize private-payment-chain validation/save on the same mutex domain used by `validate()` — e.g., acquire `mutex.lock(arrAuthorAddresses (or a per-output key), ...)` in `private_payment.js` before doing the duplicate/double-spend checks and the `INSERT`/`UPDATE` in `divisible_asset.js`/`indivisible_asset.js`, mirroring how `writer.saveJoint()` and `validate()` coordinate via the `write`/`handleJoint`/author-address mutexes. Alternatively, take a dedicated lock keyed by `(src_unit, src_message_index, src_output_index)` around the whole validate-and-save sequence for private payment chains.

### Proof of Concept
1. Attacker (private-payment counterparty) creates a valid private payment chain `A` spending output `O`.
2. Attacker crafts a second chain `B` that also spends output `O` (e.g., resending the same input with a different output/blinding, or via two colluding forwarding peers).
3. Attacker submits chain `A` to the victim node via one connection (`wallet.js: handlePrivatePaymentChains`) and, within the same short window, submits chain `B` via another connection/peer path (`network.js: handleSavedPrivatePayments`).
4. Both invocations reach `private_payment.js: validateAndSavePrivatePaymentChain` on separate DB connections; both pass the `checkForDoublespends` SELECT in `validation.js` before either commits its `INSERT INTO inputs`.
5. Both transactions commit: output `O` is now recorded as consumed by two different, non-conflicting-looking spends, i.e., double-spent.

### Citations

**File:** validation.js (L354-358)
```javascript
	if (!arrAuthorAddresses.every(isValidAddress))
		return callbacks.ifUnitError("invalid author address");

	mutex.lock(arrAuthorAddresses, function(unlock){
		
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

**File:** private_payment.js (L35-53)
```javascript
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
			db.takeConnectionFromPool(function(conn){
				conn.query("BEGIN", function(){
					var transaction_callbacks = {
						ifError: function(err){
							conn.query("ROLLBACK", function(){
								conn.release();
								callbacks.ifError(err);
							});
						},
```

**File:** private_payment.js (L60-111)
```javascript
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
				});
			});
		});
	};
```

**File:** divisible_asset.js (L78-93)
```javascript
function validateDivisiblePrivatePayment(conn, objPrivateElement, callbacks){
	
	var unit = objPrivateElement.unit;
	var message_index = objPrivateElement.message_index;
	var payload = objPrivateElement.payload;

	if (!ValidationUtils.isStringOfLength(payload.asset, constants.HASH_LENGTH))
		return callbacks.ifError("invalid asset in private divisible payment");
	if (!ValidationUtils.isNonemptyArray(payload.inputs))
		return callbacks.ifError("no inputs");
	
	validation.initPrivatePaymentValidationState(
		conn, unit, message_index, payload, callbacks.ifError, 
		function(bStable, objPartialUnit, objValidationState){
		
			var arrAuthorAddresses = objPartialUnit.authors.map(function(author) { return author.address; } );
```

**File:** indivisible_asset.js (L83-93)
```javascript
	if (!ValidationUtils.isNonemptyObject(input))
		return callbacks.ifError("no inputs[0]");
	
	profiler.start();
	validation.initPrivatePaymentValidationState(
		conn, objPrivateElement.unit, objPrivateElement.message_index, payload, callbacks.ifError, 
		function(bStable, objPartialUnit, objValidationState){
		
			profiler.stop('initPrivatePaymentValidationState');
			var arrFuncs = [];
			var spend_proof;
```
