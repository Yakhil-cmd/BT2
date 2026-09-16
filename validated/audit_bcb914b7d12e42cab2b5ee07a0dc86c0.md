### Title
Race condition between concurrently-validated private-payment double-spend handlers can permanently freeze/desync inputs uniqueness state - (File: validation.js)

### Summary
`validation.js`'s `checkInputDoubleSpend()` (inside `validatePaymentInputsAndOutputs`) handles competing spends of the same input differently for private vs. public assets. For public/base assets, the "un-unique" `UPDATE inputs SET is_unique=NULL` is queued into `objValidationState.arrAdditionalQueries` and executed later, inside the same DB transaction/lock that serializes validation by author address (`mutex.lock(arrAuthorAddresses, ...)` in `validate()`). For private assets (`objAsset.is_private`), the same kind of update is instead executed immediately, guarded only by a separate, unrelated mutex key `"private_write"` [1](#0-0) , completely independent of the author-address lock that serializes the rest of unit/private-payment validation [2](#0-1) .

### Finding Description
`validate()` normally serializes all validation and double-spend bookkeeping for a set of author addresses under a single mutex key (`mutex.lock(arrAuthorAddresses, ...)`), and defers any `UPDATE inputs SET is_unique=NULL` for accepted double-spends into `objValidationState.arrAdditionalQueries`, to be applied atomically together with the rest of the unit's state changes inside the surrounding DB transaction [3](#0-2) [4](#0-3) .

However, private-payment chain validation does **not** go through this author-address-locked path. `validateAndSavePrivatePaymentChain` → `validateDivisiblePrivatePayment` calls `validation.initPrivatePaymentValidationState` and `validation.validatePayment`/`validatePaymentInputsAndOutputs` directly on an externally-supplied `conn`, without ever acquiring `mutex.lock(arrAuthorAddresses, ...)` [5](#0-4) . This code path is reachable purely from message traffic that an unprivileged counterparty (or paired device forwarding a private payment) can send, via `handlePrivatePaymentChains`/`handleSavedPrivatePayments`, which only take generic queue-processing mutexes (`"saved_private"`, `"private_chains"`) unrelated to the specific spending addresses [6](#0-5) .

For private assets specifically, `checkInputDoubleSpend` bypasses the deferred/queued update mechanism and instead takes a distinct, narrowly-scoped lock, `mutex.lock(["private_write"], ...)`, immediately issuing `UPDATE inputs SET is_unique=NULL WHERE ...` against the shared `inputs` table on whatever `conn`/transaction happens to be open [7](#0-6) . Because this lock key is unrelated to the author-address lock guarding concurrent unit validation, two validations that legitimately compete for the same input (one under the address-mutex-protected public/AA validation path, one under the private-payment path with no address-level serialization) can interleave: one path reads/queries `inputs`/`units` rows for uniqueness, decides `is_unique` state, and commits/rolls back its own transaction while the other path — holding only `"private_write"` momentarily — performs an out-of-band `UPDATE` against the same rows using a *different* connection/transaction. This is structurally analogous to CVE-2020-25285: two independent handlers (sysctl handlers in the kernel case; author-address-serialized public validation vs. `"private_write"`-serialized private validation here) mutate shared state (hugetlb pool metadata vs. the `inputs.is_unique` column and in-memory `objValidationState.arrDoubleSpendInputs`) using separate, uncoordinated locks, rather than a single lock that covers the whole invariant.

The practical consequence: the `is_unique` flag on `inputs` (which encodes "this competing spend has been resolved as non-serial/serial") can be left in a state inconsistent with the outcome actually recorded by the transaction that decided sequence for the conflicting unit, because the write happens on a separate connection/transaction outside of the enclosing BEGIN/COMMIT boundary that the rest of `objValidationState`'s bookkeeping (`arrAdditionalQueries`) relies on for public assets. If the enclosing transaction of the *other* concurrent unit rolls back (e.g. validation later fails, or the unit turns out invalid), the out-of-band `UPDATE` performed via `"private_write"` is not rolled back with it, leaving a permanent mismatch between the recorded `sequence`/`is_unique` state of a private input and the actual outcome of the competing unit.

### Impact Explanation
An inconsistent `is_unique` flag on `inputs` for a private asset directly controls whether a given spend of that input is treated as unique/serial (final good) or not. A stale/incorrect `is_unique=NULL` (or missing un-uniqueing) can allow:
- A previously "resolved" double-spend of a private-asset input to be treated inconsistently by different nodes/processes (some seeing it un-uniqued, i.e. eligible to be spent again, others not), producing **node disagreement on validity**, or
- A private output being spendable twice if the un-unique update is lost due to the rollback of the transaction it was mistakenly tied to, enabling a **double-spend of a (private) output** that should have been finalized as non-serial.

This matches the required impact bar: node disagreement on validity/stability or unauthorized double-spend of an output.

### Likelihood Explanation
Reachable from routine, unprivileged activity: any counterparty of a private payment (or a paired device relaying `private_payment_chain` messages) can submit competing/double-spending private payment chains that trigger `checkInputDoubleSpend` concurrently with other validations touching the same input rows, since private-chain validation is not serialized by author address like public unit validation is. The race requires precise timing between the two independently-locked code paths (`arrAuthorAddresses` lock vs. `"private_write"` lock), so it is not trivially deterministic, but no privileged access, malicious peer/hub behavior, or network-level manipulation is required — only normal private-payment message flow with adversarial timing, consistent with a Medium-severity race condition (paralleling the CVSS AC:H rating of the original CVE).

### Recommendation
- Ensure private-payment double-spend resolution uses the *same* invariant-covering lock as public validation (i.e., serialize on the conflicting input's owning address(es), not an unrelated `"private_write"` key), or
- Defer the `UPDATE inputs SET is_unique=NULL` for private assets into `objValidationState.arrAdditionalQueries` and apply it within the same transaction/commit boundary as the rest of the validation state, exactly as already done for public/base assets, eliminating the separate out-of-band write path entirely.

### Proof of Concept
1. Node A begins validating unit U1 (private asset payment) — validation not protected by `arrAuthorAddresses` mutex, since it is a private-payment chain validated via `validateDivisiblePrivatePayment`/`validatePayment`/`validatePaymentInputsAndOutputs` on its own `conn`.
2. Concurrently, node A also processes competing unit U2 spending the same private input (received independently, e.g. relayed by the counterparty's device), entering `checkInputDoubleSpend` for U2's validation.
3. Both U1 and U2's `checkInputDoubleSpend` detect the conflicting record and enter `acceptDoublespends`; for the private asset branch, each acquires `mutex.lock(["private_write"])` in turn and issues `UPDATE inputs SET is_unique=NULL WHERE ... AND (SELECT is_stable ...)=0` on its own `conn` [8](#0-7) .
4. If U1's overall validation transaction later fails or rolls back (e.g., a later message in the same unit fails validation, triggering `ROLLBACK` in `validate()`'s `commit_fn`) after U1's `checkInputDoubleSpend` already committed its out-of-band `UPDATE` via `"private_write"` on a separate connection, the `is_unique=NULL` write is *not* rolled back with U1, leaving `inputs.is_unique` state for the competing private input decoupled from U1's actual acceptance, permanently desynchronizing sequence/double-spend bookkeeping for that private asset input across the two units.

### Citations

**File:** validation.js (L354-380)
```javascript
	if (!arrAuthorAddresses.every(isValidAddress))
		return callbacks.ifUnitError("invalid author address");

	mutex.lock(arrAuthorAddresses, function(unlock){
		
		var conn = null;
		var commit_fn = null;
		var start_time = null;

		async.series(
			[
				function(cb){
					if (external_conn) {
						conn = external_conn;
						start_time = Date.now();
						commit_fn = function (cb2) { cb2(); };
						return cb();
					}
					db.takeConnectionFromPool(function(new_conn){
						conn = new_conn;
						start_time = Date.now();
						commit_fn = function (cb2) {
							conn.query(objValidationState.bAdvancedLastStableMci ? "COMMIT" : "ROLLBACK", function () { cb2(); });
						};
						conn.query("BEGIN", function(){cb();});
					});
				},
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

**File:** divisible_asset.js (L78-178)
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

			function validateSpendProofs(sp_cb){

				var arrSpendProofs = [];
				async.eachSeries(
					payload.inputs,
					function(input, cb){
						if (input.type === "issue"){
							var address = input.address || arrAuthorAddresses[0];
							try {
								var spend_proof = objectHash.getBase64Hash({
									asset: payload.asset,
									amount: input.amount,
									address: address,
									serial_number: input.serial_number
								});
							}
							catch (e) {
								return cb("failed to calc issue spend proof: " + e.message);
							}
							arrSpendProofs.push({address: address, spend_proof: spend_proof});
							cb();
						}
						else if (!input.type){
							conn.query(
								"SELECT address, amount, blinding FROM outputs WHERE unit=? AND message_index=? AND output_index=? AND asset=?",
								[input.unit, input.message_index, input.output_index, payload.asset],
								function(rows){
									if (rows.length !== 1)
										return cb("not 1 row when selecting src output");
									var src_output = rows[0];
									try {
										var spend_proof = objectHash.getBase64Hash({
											asset: payload.asset,
											unit: input.unit,
											message_index: input.message_index,
											output_index: input.output_index,
											address: src_output.address,
											amount: src_output.amount,
											blinding: src_output.blinding
										});
									}
									catch (e) {
										return cb("failed to calc transfer spend proof: " + e.message);
									}
									arrSpendProofs.push({address: src_output.address, spend_proof: spend_proof});
									cb();
								}
							);
						}
						else
							cb("unknown input type: "+input.type);
					},
					function(err){
						if (err)
							return sp_cb(err);
						//arrSpendProofs.sort(function(a,b){ return a.spend_proof.localeCompare(b.spend_proof); });
						conn.query(
							"SELECT address, spend_proof FROM spend_proofs WHERE unit=? AND message_index=? ORDER BY spend_proof_index", 
							[unit, message_index],
							function(rows){
								if (rows.length !== arrSpendProofs.length)
									return sp_cb("incorrect number of spend proofs");
								for (var i=0; i<rows.length; i++){
									if (rows[i].address !== arrSpendProofs[i].address || rows[i].spend_proof !== arrSpendProofs[i].spend_proof)
										return sp_cb("incorrect spend proof");
								}
								sp_cb();
							}
						);
					}
				);
			}

			var arrFuncs = [];
			arrFuncs.push(validateSpendProofs);
			arrFuncs.push(function(cb){
				validation.validatePayment(conn, payload, message_index, objPartialUnit, objValidationState, cb);
			});
			async.series(arrFuncs, function(err){
				console.log("162: "+err);
				err ? callbacks.ifError(err) : callbacks.ifOk(bStable, arrAuthorAddresses);
			});
		}
	);
```

**File:** network.js (L2443-2451)
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
```
