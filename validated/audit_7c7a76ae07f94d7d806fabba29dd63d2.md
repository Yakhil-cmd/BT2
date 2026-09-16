## Analysis

The CVE-2021-47688 bug class is: a destructive/irreversible state-changing action (file truncation) is executed **before** the authorization check (`VerifyCanWrite`) that is supposed to gate it, so if the check later fails, the damage is already done and cannot be undone.

The closest analog in this codebase is in unit validation's handling of **main-chain stability advancement while validating `last_ball`/`parent_units`**.

### Root cause

While validating a newly-posted unit's parents, `validateParents()` calls `main_chain.determineIfStableInLaterUnitsAndUpdateStableMcFlag()` to check whether `last_ball_unit` is stable "in view of" the *unit's own, attacker-supplied* `parent_units`: [1](#0-0) 

That helper, if it decides the earlier unit has become stable, does **not** defer the write to the caller's transaction. Instead it immediately grabs its own DB connection/mutex and commits the stability advance directly: [2](#0-1) 

Note that `conn` used for `stabilizeMci`/`markMcIndexStable` inside this function is obtained via a **separate** `db.takeConnectionFromPool()` call, guarded only by `mutex.lock(["handleJoint"])`, completely independent from the outer validation transaction (`conn`/`commit_fn`) that is still deciding whether the *triggering unit itself* is valid: [3](#0-2) 

Back in the caller, the returned `bAdvancedLastStableMci` flag is checked, and one assignment is explicitly marked dead ("not used"): [4](#0-3) 

Because the early `return callback(createTransientError(...))` on line 811-812 fires whenever `bAdvancedLastStableMci` is true, the assignment on line 822 is unreachable — confirming that the outer `objValidationState.bAdvancedLastStableMci` bookkeeping used by `commit_fn` at the top of `validate()` does not actually track this side effect: [5](#0-4) 

So the sequencing is: **write (advance stability / mark MCI stable) → then the overall accept/reject decision (equivalent to `VerifyCanWrite`) for the unit that triggered it**, exactly mirroring OpenFileDescriptor-truncate-before-VerifyCanWrite in the CVE.

### Impact

`determineIfStableInLaterUnitsAndUpdateStableMcFlag` is invoked using `objUnit.parent_units` — attacker-controlled — as the "later units" set that determines whether an earlier ball becomes stable: [6](#0-5) 

A node can be induced to permanently commit a main-chain-index stability advance based on a **still-unvalidated, attacker-crafted unit's parent set**, before that unit's signatures, sequence, and other checks are verified. If the triggering unit subsequently fails validation for unrelated reasons (bad signature, malformed messages, etc.) and is rejected via `ifUnitError`, the stability commit made on the separate connection is never rolled back — the node's local view of MC stability has already diverged based on data from a unit that the network as a whole will never accept. Because stability determines which outputs are considered final/spendable and which AA triggers are stable/executable, this can cause the node to disagree with peers on the stability of specific outputs/units, a precondition for double-spend or fund-loss scenarios in AA/state-var reliant flows.

### Title
Premature commit of main-chain stability advancement before unit validation outcome is finalized - (File: `validation.js`, `main_chain.js`)

### Summary
`validateParents()` triggers `main_chain.determineIfStableInLaterUnitsAndUpdateStableMcFlag()` using the untrusted unit's own `parent_units` to decide if `last_ball_unit` should become stable. That helper commits the stability advance to the database on an independent connection/transaction, guarded only by a `handleJoint` mutex, before the surrounding `validate()` call has determined whether the triggering unit itself passes all remaining checks (signatures, sequence, messages, etc.). The bookkeeping flag intended to track this side effect on `objValidationState` is dead code (explicitly commented "not used"), confirming the outer transaction's commit/rollback logic cannot undo it.

### Finding Description
In `validate()`, `validateParents()` is called as one step of an `async.series` pipeline that runs inside a DB transaction managed by `commit_fn` [7](#0-6) . Deep inside that step, `checkNoSameAddressInDifferentParents`'s prerequisite path calls `main_chain.determineIfStableInLaterUnitsAndUpdateStableMcFlag(conn, last_ball_unit, objUnit.parent_units, objLastBallUnitProps.is_stable, ...)` [6](#0-5) .

Inside that function, if stability advances, the code takes a **new** connection from the pool and a `handleJoint` mutex, then loops calling `stabilizeMci(mci)` for each newly-stable MCI, committing directly to the database, all before the outer `validate()` call's `async.series` pipeline has finished checking the rest of the triggering unit (author signatures, message contents, sequence, etc.): [8](#0-7) 

The result is returned to the caller via `handleResult(bStable, true)` *before* the mutex-protected commit loop even runs, so the caller cannot block on it, and any subsequent validation failure for the current unit cannot be used to prevent or reverse the already-committed stability advance.

### Impact Explanation
Any unprivileged peer can post a unit whose `parent_units`/`last_ball_unit` are engineered to make an earlier ball look stable "in view of" that peer-chosen parent set, even if the unit ultimately fails validation for an unrelated reason. Because the stability write already landed on a separate, already-committed connection, the node's local main-chain stability state can be advanced based on data supplied by a unit that the network will never actually accept. Since main-chain stability determines finality of payment outputs and AA trigger execution, this creates a path toward **node disagreement on stability/validity** between honest nodes that did or didn't process the same rejected unit, which is a prerequisite for accepting a double-spend of an output other nodes still consider unstable, or for a node executing/finalizing AA state based on a stability decision the rest of the network does not share.

### Likelihood Explanation
The path is reachable directly from `validate()`'s normal processing of any incoming unit with `parent_units`, requiring no special privileges — an ordinary unit poster can trigger it by choosing parents/last_ball that satisfy `determineIfStableInLaterUnits` for an as-yet-unstable ball. Likelihood is Medium: it requires carefully crafted parent/last_ball selection and a unit that ultimately still fails a later validation step, which is a narrower but realistic condition given how sensitive to timing/witness-level computations `determineIfStableInLaterUnits` is.

### Recommendation
Defer the stability advancement's DB writes to the same transaction/connection used for the rest of the triggering unit's validation, and only commit them once the entire unit has been fully accepted (i.e., move the write inside the same `commit_fn`/rollback scope as the rest of `validate()`), or make `determineIfStableInLaterUnitsAndUpdateStableMcFlag` return the pending mutation set to the caller instead of eagerly committing it on an independent connection. At minimum, restore the dead `objValidationState.bAdvancedLastStableMci` tracking so the outer transaction logic is aware the side effect occurred and can act accordingly, and re-audit whether the flag needs to gate anything else in `commit_fn`.

### Proof of Concept
1. As an unprivileged peer, monitor the DAG for an unstable ball `B` on the main chain whose current free-tip witnessed levels are just below the threshold needed to stabilize it.
2. Construct and broadcast a new unit `U` whose `parent_units` are chosen (from currently free units) such that, combined, they push `determineIfStableInLaterUnits(conn, B, U.parent_units)` to return `true` (satisfy witness-level majority), while ensuring `U` will subsequently fail validation for an unrelated reason (e.g., invalid signature over otherwise well-formed content, or invalid `payload_commission`).
3. When the node processes `U`, `validateParents()` invokes `determineIfStableInLaterUnitsAndUpdateStableMcFlag(conn, last_ball_unit, U.parent_units, ...)`, which commits the stability advance of `B` (and any earlier unstable MCIs) directly to the database via its own connection under the `handleJoint` mutex.
4. `U` subsequently fails validation later in the `async.series` pipeline and is rejected via `ifUnitError`; the outer transaction rolls back `U`'s own changes, but the stability advance already committed in step 3 is not reverted.
5. The node now considers `B`'s MCI stable based on a rejected unit's parent set, while peers that never saw `U` may not yet consider it stable — producing a stability/validity divergence between nodes.

### Citations

**File:** validation.js (L357-380)
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
					});
				},
```

**File:** validation.js (L411-417)
```javascript
				function(cb){
					profiler.stop('validation-hash-tree-parents');
				//	profiler.start(); // conflicting with profiling in determineIfStableInLaterUnitsAndUpdateStableMcFlag
					!objUnit.parent_units
						? cb()
						: validateParents(conn, objJoint, objValidationState, cb);
				},
```

**File:** validation.js (L447-472)
```javascript
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

**File:** validation.js (L802-826)
```javascript
						// Last ball is not stable yet in our view. Check if it is stable in view of the parents
						main_chain.determineIfStableInLaterUnitsAndUpdateStableMcFlag(conn, last_ball_unit, objUnit.parent_units, objLastBallUnitProps.is_stable, function(bStable, bAdvancedLastStableMci){
							/*if (!bStable && objLastBallUnitProps.is_stable === 1){
								var eventBus = require('./event_bus.js');
								eventBus.emit('nonfatal_error', "last ball is stable, but not stable in parents, unit "+objUnit.unit, new Error());
								return checkNoSameAddressInDifferentParents();
							}
							else */if (!bStable)
								return callback(objUnit.unit+": last ball unit "+last_ball_unit+" is not stable in view of your parents "+objUnit.parent_units);
							if (bAdvancedLastStableMci)
								return callback(createTransientError("last ball just advanced, try again"));
							if (!bAdvancedLastStableMci)
								return checkNoSameAddressInDifferentParents();
							conn.query("SELECT ball FROM balls WHERE unit=?", [last_ball_unit], function(ball_rows){
								if (ball_rows.length === 0)
									throw Error("last ball unit "+last_ball_unit+" just became stable but ball not found");
								if (ball_rows[0].ball !== last_ball)
									return callback("last_ball "+last_ball+" and last_ball_unit "+last_ball_unit
													+" do not match after advancing stability point");
								if (bAdvancedLastStableMci)
									objValidationState.bAdvancedLastStableMci = true; // not used
								checkNoSameAddressInDifferentParents();
							});
						});
					});
```

**File:** main_chain.js (L1192-1240)
```javascript
function determineIfStableInLaterUnitsAndUpdateStableMcFlag(conn, earlier_unit, arrLaterUnits, bStableInDb, handleResult){
	if (!handleResult)
		return new Promise(resolve => determineIfStableInLaterUnitsAndUpdateStableMcFlag(conn, earlier_unit, arrLaterUnits, bStableInDb, resolve));
	determineIfStableInLaterUnits(conn, earlier_unit, arrLaterUnits, function(bStable){
		console.log("determineIfStableInLaterUnits", earlier_unit, arrLaterUnits, bStable);
		if (!bStable)
			return handleResult(bStable);
		if (bStable && bStableInDb)
			return handleResult(bStable);
		breadcrumbs.add('stable in parents, will wait for handleJoint lock');
		handleResult(bStable, true);

		// result callback already called, we stay here to move the stability point forward.
		// To avoid deadlocks, we always first obtain a "handleJoint" lock, then a db connection
		const bOpListCanChange = hasUnstableOpVoteCount();
		mutex.lock(["handleJoint"], function(unlock){
			breadcrumbs.add('stable in parents, got handleJoint lock');
			storage.readLastStableMcIndex(db, function(last_stable_mci){
				/*if (last_stable_mci >= constants.v4UpgradeMci && !(constants.bTestnet && last_stable_mci === 3547801)) {
					// we don't advance the stability point in v4 as that would necessitate executing triggers and updating actual tps fees. We return a transient error and expect that the stability point will move thanks to other units before the earlier_unit is retransmitted.
					await conn.query("COMMIT");
					conn.release();
					unlock();
					return console.log(`${earlier_unit} not stable in db but stable in later units ${arrLaterUnits.join(', ')} in v4`);
				//	throwError(`${earlier_unit} not stable in db but stable in later units ${arrLaterUnits.join(', ')} in v4`);
				}*/
				storage.readUnitProps(db, earlier_unit, async function(objEarlierUnitProps){
					if (!objEarlierUnitProps.is_on_main_chain)
						throw Error("earlier unit is no longer on main chain");
					var new_last_stable_mci = objEarlierUnitProps.main_chain_index;
					if (new_last_stable_mci <= last_stable_mci || objEarlierUnitProps.is_stable)
						return unlock("the stability point moved while we were waiting for the lock, last_stable_mci="+last_stable_mci+", new_last_stable_mci="+new_last_stable_mci);
					for (let mci = last_stable_mci + 1; mci <= new_last_stable_mci; mci++) {
						if (bOpListCanChange && mci >= constants.v4UpgradeMci) {
							// check stability before every step using the best parent's OP list (the standard rule for advancing stability). The initial stability of the earlier_unit was determined using the OP list of the last stable unit
							const conn = await db.takeConnectionFromPool();
							const [{ unit }] = await conn.query("SELECT unit FROM units WHERE main_chain_index=? AND is_on_main_chain=1", [mci]);
							const bMciStable = await determineIfStableInLaterUnits(conn, unit, arrLaterUnits);
							conn.release();
							if (!bMciStable) break;
						}
						await stabilizeMci(mci);
					}
					unlock();
				});
			});
		});
	});
}
```
