### Title
Private-payment double-spend "un-uniquing" runs immediately under a narrow `private_write` lock instead of being deferred with the validation transaction, unlike public assets - ([File: validation.js])

### Summary
The Linux CVE fixes a race where ring state was updated under one lock (`sk_receive_queue.lock`) while the related receive-hook was published outside that lock, letting a concurrent reader observe a torn state. `ocore`'s equivalent shared, security-relevant state is the `inputs.is_unique` flag that arbitrates which of two conflicting (double-spending) inputs is considered "the" spend. In `validateInputDoubleSpend`'s `acceptDoublespends` callback (`validation.js`), public-asset conflicts are resolved by queuing the "un-unique" `UPDATE` into `objValidationState.arrAdditionalQueries`, to be executed later, atomically, inside the same commit as the rest of unit's write (`writer.js`). Private-asset conflicts instead execute the `UPDATE inputs SET is_unique=NULL ...` immediately, under a separate, narrowly-scoped `private_write` mutex that is acquired and released around just that one query — decoupled from the `handleJoint`/author-address lock that serializes the rest of validation and from the `conn`'s own transaction commit/rollback timing.

### Finding Description
`checkInputDoubleSpend` in `validation.js` builds a query to detect other (non final-bad) inputs spending the same source output, then calls `checkForDoublespends`: [1](#0-0) 

When a genuine double-spend is accepted (i.e., this unit is not included in the ancestry of the competitor), `acceptDoublespends` decides how to demote the competing input's `is_unique` flag to `NULL` (so the new unit can become the "unique"/winning claim on the disputed output):

- For a **public asset**, the demotion SQL is deferred: pushed onto `objValidationState.arrAdditionalQueries`, and only executed later inside `writer.saveJoint`, as part of the exact same DB transaction/commit that persists the new unit — this keeps the read (which determined a conflict exists) and the write (demoting the loser) atomically tied to the fate of the whole unit's validation/write. [2](#0-1) 

- For a **private asset**, the demotion SQL is executed *immediately*, inside `checkInputDoubleSpend`, guarded only by a freshly acquired/released `mutex.lock(["private_write"], ...)`, using the validation's own `conn`/transaction — a scope entirely disjoint from the `arrAuthorAddresses` lock that guards the rest of `validate()`: [3](#0-2) 

Because the `private_write` lock is released as soon as this single query completes — long before the surrounding unit validation finishes and its transaction is committed or rolled back via `commit_fn` — a second, concurrent private-payment validation that touches the *same* disputed source output can acquire `private_write`, run its own `SELECT`/conflict check, and mutate `is_unique` again, all while the first transaction's fate (COMMIT vs ROLLBACK) is still undetermined: [4](#0-3) 

This is structurally the same class of bug as the CVE: two pieces of state that must change together — "who currently holds `is_unique`" and "the transaction that decided it" — are protected by two different, narrower locks (`private_write` vs. the outer validation/transaction boundary), so a second concurrent private-chain validation can observe/alter `is_unique` in a window where the first update has not yet been durably committed (or could still be rolled back), unlike the public-asset path where the update is intentionally deferred to be atomic with the commit.

### Impact Explanation
`is_unique=NULL` vs `is_unique=1` on `inputs` is exactly the flag `checkForDoublespends`'s SQL query relies on to determine which of two conflicting private-asset spends of the same source output is treated as the live/serial claim. If the un-uniquing runs and is visible to (or racily contended by) a second concurrent private-payment validation on the same output before the first transaction's outcome is finalized, two different validators (e.g., a wallet accepting a locally-forwarded private chain, and a hub/light-vendor relaying another chain concurrently) can reach different conclusions about which spend is unique. Because private payments are validated client-side (both counterparties, without full-network consensus visible to light wallets — `conf.bLight` even short-circuits to reject conflicts outright rather than resolve via graph comparison), an attacker acting as one counterparty in overlapping private payment chains can exploit the narrow lock window to get two different recipients to each accept a chain that spends the same private output, i.e., a **double-spend of a private-asset output** accepted by different parties — a fund-loss condition for the honest counterparty.

### Likelihood Explanation
Exploitation requires an attacker to control both ends (or forward two conflicting private chains) that spend the same private output to two different recipients nearly simultaneously, exploiting the small window between `private_write` unlock and the eventual `COMMIT`/`ROLLBACK` of each transaction. This is a real but narrow timing window, reachable by "a private-payment counterparty" as permitted by the task's reachability rules, without needing malicious peers/nodes/hubs. It requires no elevated privileges — only sending crafted, conflicting private-payment chains — matching the CVSS profile of the source CVE (local, low privilege, high impact).

### Recommendation
Make the private-asset un-uniquing consistent with the public-asset path: defer the `UPDATE inputs SET is_unique=NULL ...` into `objValidationState.arrAdditionalQueries` and execute it inside `writer.saveJoint`'s single commit, instead of running it immediately under the disjoint `private_write` lock. If immediate execution is required for private assets (e.g., to prevent a second validation from picking the same source while this one is mid-flight), the `private_write` lock must be held for the entire duration of the enclosing unit's validation and commit/rollback decision, not just around the single `UPDATE` query, so that the observed "conflict resolved" state and the transaction outcome cannot diverge.

### Proof of Concept
1. Attacker (author of a private-asset output) constructs two private payment chains, `A` and `B`, both spending the same private source output (`src_unit`/`message_index`/`output_index`) to two different recipient devices, `R1` and `R2`.
2. Attacker sends chain `A` to `R1` and, essentially concurrently, chain `B` to `R2` (both go through `private_payment.js` → `divisible_asset.js`/`indivisible_asset.js` → `validation.js`'s `validatePaymentInputsAndOutputs`).
3. `R1`'s validation of `A` reaches `checkInputDoubleSpend`; assume no conflict found yet (first to check), so no un-uniquing needed, and `R1`'s transaction proceeds toward commit.
4. Before `R1`'s transaction commits, `R2`'s validation of `B` reaches `checkInputDoubleSpend`, detects `A`'s prior claim is not in `B`'s ancestry, and calls `acceptDoublespends`, which takes the `private_write` lock and immediately runs `UPDATE inputs SET is_unique=NULL WHERE ...` against `A`'s row using `R2`'s own connection/transaction, then releases `private_write` right away — independent of whether `R1`'s transaction (which may still be pending) ever commits.
5. Because the un-unique write and lock release for `B`'s validation are decoupled from `A`'s transaction's actual commit/rollback, timing variations (e.g., `R1`'s transaction rolling back for an unrelated later validation failure, or committing after `R2` already released the lock and moved on) can result in `R1` and `R2` independently reaching `ifOk` for their respective chains, each locally recording their own spend of the same private output as valid/unique — a private double-spend accepted by two different counterparties.

Note: full confirmation of exploitability requires dynamic testing with two real concurrent private-payment validations against the same source output to observe whether both `R1` and `R2` can independently reach `ifOk`; the static analysis above establishes the lock-scope mismatch (root cause) but not a fully executed end-to-end reproduction.

### Citations

**File:** validation.js (L357-378)
```javascript
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
```

**File:** validation.js (L446-472)
```javascript
				if(err){
					if (profiler.isStarted())
						profiler.stop('validation-advanced-stability');
					// We might have advanced the stability point and have to commit the changes as the caches are already updated.
					// There are no other updates/inserts/deletes during validation
					commit_fn(function(){
						var consumed_time = Date.now()-start_time;
						profiler.add_result('failed validation', consumed_time);
						console.log(objUnit.unit+" validation "+JSON.stringify(err)+" took "+consumed_time+"ms");
						if (!external_conn)
							conn.release();
						unlock();
						if (typeof err === "object"){
							if (err.error_code === "unresolved_dependency")
								callbacks.ifNeedParentUnits(err.arrMissingUnits, err.bRequestPrunedContent);
							else if (err.error_code === "need_hash_tree") // need to download hash tree to catch up
								callbacks.ifNeedHashTree();
							else if (err.error_code === "invalid_joint") // ball found in hash tree but with another unit
								callbacks.ifJointError(err.message);
							else if (err.error_code === "transient")
								callbacks.ifTransientError(err.message);
							else
								throw Error("unknown error code");
						}
						else
							callbacks.ifUnitError(err);
					});
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

**File:** writer.js (L55-74)
```javascript
	initConnection(function(conn){
		var start_time = Date.now();
		
		// additional queries generated by the validator, used only when received a doublespend
		for (var i=0; i<objValidationState.arrAdditionalQueries.length; i++){
			var objAdditionalQuery = objValidationState.arrAdditionalQueries[i];
			conn.addQuery(arrQueries, objAdditionalQuery.sql, objAdditionalQuery.params);
			breadcrumbs.add('====== additional query '+JSON.stringify(objAdditionalQuery));
			if (objAdditionalQuery.sql.match(/temp-bad/)){
				var arrUnstableConflictingUnits = objAdditionalQuery.params[0];
				breadcrumbs.add('====== conflicting units in additional queries '+arrUnstableConflictingUnits.join(', '));
				arrUnstableConflictingUnits.forEach(function(conflicting_unit){
					var objConflictingUnitProps = storage.assocUnstableUnits[conflicting_unit];
					if (!objConflictingUnitProps)
						return breadcrumbs.add("====== conflicting unit "+conflicting_unit+" not found in unstable cache"); // already removed as uncovered
					if (objConflictingUnitProps.sequence === 'good')
						objConflictingUnitProps.sequence = 'temp-bad';
				});
			}
		}
```
