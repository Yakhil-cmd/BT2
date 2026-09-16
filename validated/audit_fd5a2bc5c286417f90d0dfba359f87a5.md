### Title
Stability-advancement state desync when last-ball validation returns a transient "just advanced" error before propagating `bAdvancedLastStableMci` - (File: validation.js)

### Summary
`validateParents()` calls `main_chain.determineIfStableInLaterUnitsAndUpdateStableMcFlag()` to check/advance the stable main-chain flag while validating an incoming unit's `last_ball`/`last_ball_unit`. When that function reports `bAdvancedLastStableMci === true`, `validateParents()` immediately returns a transient error ("last ball just advanced, try again") **without** setting `objValidationState.bAdvancedLastStableMci = true`. The top-level `validate()` decides whether to `COMMIT` or `ROLLBACK` the DB transaction solely based on `objValidationState.bAdvancedLastStableMci`. This mirrors the CVE-2022-45409 pattern: a state-mutating operation is started/partially applied, then the caller aborts through an error path that skips the "finish"/flag-propagation step, leaving the committed side effects and the rollback decision out of sync.

### Finding Description
In `validate()` (validation.js), stability of the transaction is decided here: [1](#0-0) 
`commit_fn` performs `COMMIT` only `if (objValidationState.bAdvancedLastStableMci)`, otherwise `ROLLBACK`. The comment right above the failure path explicitly acknowledges the hazard: "We might have advanced the stability point and have to commit the changes as the caches are already updated. There are no other updates/inserts/deletes during validation." [2](#0-1) 

The flag is supposed to be set inside `validateParents()`'s handling of `determineIfStableInLaterUnitsAndUpdateStableMcFlag`: [3](#0-2) 

Specifically:
```
main_chain.determineIfStableInLaterUnitsAndUpdateStableMcFlag(conn, last_ball_unit, objUnit.parent_units, objLastBallUnitProps.is_stable, function(bStable, bAdvancedLastStableMci){
    ...
    else if (!bStable)
        return callback(...);
    if (bAdvancedLastStableMci)
        return callback(createTransientError("last ball just advanced, try again"));   // <-- returns WITHOUT setting objValidationState.bAdvancedLastStableMci
    if (!bAdvancedLastStableMci)
        return checkNoSameAddressInDifferentParents();
    conn.query("SELECT ball FROM balls WHERE unit=?", [last_ball_unit], function(ball_rows){
        ...
        if (bAdvancedLastStableMci)
            objValidationState.bAdvancedLastStableMci = true; // not used
        checkNoSameAddressInDifferentParents();
    });
});
```
The local callback parameter `bAdvancedLastStableMci` being `true` means `determineIfStableInLaterUnitsAndUpdateStableMcFlag` (in `main_chain.js`) already performed the in-connection/in-memory work of advancing the stable MC index (e.g. calling `markMcIndexStable`, updating `storage.assocStableUnits`/related in-memory caches, and queueing kvstore `batch` writes) before invoking this callback. Yet the very first branch that checks `bAdvancedLastStableMci` returns early via `callback(createTransientError(...))` and never reaches the line that would set `objValidationState.bAdvancedLastStableMci = true`.

Back in `validate()`'s failure handler, `commit_fn` will then issue `ROLLBACK` (because `objValidationState.bAdvancedLastStableMci` is falsy) even though the stability-advancement work already happened and updated process-wide in-memory caches (and possibly queued a `batch` write) as part of the same DB transaction/connection. This produces a state where the SQL-side effects are rolled back but the in-memory caches (`storage.assocStableUnits`, etc.) that were already mutated are not reverted — an analogous "aborted mid-operation, finishing step skipped" bug to the reported GC use-after-free class, except here the divergence is between the persisted DB and the process's cached view of stability/main-chain state.

### Impact Explanation
If the in-memory stability caches diverge from the rolled-back DB state, a node's local view of which units/MCIs are stable can become inconsistent with what is actually committed to disk. Because stability determines whether inputs are spendable, whether double-spends are resolved, and which branch is authoritative, this class of desync can lead to the node disagreeing with itself (and potentially with peers) on unit validity/stability — a precondition for accepting a unit it should reject (or vice versa), which can enable double-spend acceptance or a stuck/diverged node unable to reach consensus on new units. This satisfies the "node disagreement on validity or stability" / "network unable to confirm new units" impact bar.

### Likelihood Explanation
The path is reachable by any ordinary unit poster: simply submitting a unit whose `last_ball_unit` triggers `determineIfStableInLaterUnitsAndUpdateStableMcFlag` to advance stability at the moment of validation is a normal, permissionless occurrence (it is explicitly anticipated and handled with a transient-retry error message "last ball just advanced, try again"), not a privileged or malicious-peer/hub scenario. However, I was not able to fully verify (within the available index) the exact internals of `determineIfStableInLaterUnitsAndUpdateStableMcFlag` / `markMcIndexStable` in `main_chain.js` to confirm precisely which in-memory caches are mutated before the callback fires and whether those mutations are otherwise idempotent/self-healing on retry (e.g., recomputed from DB on next read). This is the key uncertainty: if all affected caches are always re-derived from the DB before being trusted (making the stale in-memory state harmless), the practical exploitability would be much lower or moot.

### Recommendation
- Set `objValidationState.bAdvancedLastStableMci = true` immediately in the `if (bAdvancedLastStableMci) return callback(createTransientError(...))` branch, before returning, so the commit/rollback decision in `validate()` always matches whatever side effects `determineIfStableInLaterUnitsAndUpdateStableMcFlag` already performed.
- Audit `markMcIndexStable` / `determineIfStableInLaterUnitsAndUpdateStableMcFlag` in `main_chain.js` to confirm whether any in-memory cache mutation happens before the transaction is guaranteed to commit, and make such mutations transactional (deferred until COMMIT) or idempotent/rollback-safe.
- Add a regression test that forces `determineIfStableInLaterUnitsAndUpdateStableMcFlag` to report `bAdvancedLastStableMci = true` on the transient-error branch and asserts the surrounding SQL transaction is committed (not rolled back) and that caches remain consistent with the DB afterward.

### Proof of Concept
Conceptual reproduction (exact trigger conditions require lab verification against `main_chain.js` internals, which I could not fully inspect):
1. Have a node validate an incoming unit `U` whose `last_ball_unit` is not yet marked stable in the local `units` table but is stable "in view of parents" of `U`.
2. `validateParents()` calls `main_chain.determineIfStableInLaterUnitsAndUpdateStableMcFlag()`, which advances the stable MC index (mutating in-memory stability caches / queuing batch writes) and returns `bAdvancedLastStableMci = true`.
3. `validateParents()` hits the early-return branch at validation.js:811-812 and calls back with a transient error, skipping the `objValidationState.bAdvancedLastStableMci = true` assignment at line 822.
4. `validate()`'s failure handler runs `commit_fn`, which issues `ROLLBACK` because `objValidationState.bAdvancedLastStableMci` was never set — even though the stability advancement's in-memory/cache effects already occurred.
5. Subsequent validations/reads that rely on the (now stale) in-memory caches versus the rolled-back DB rows can disagree on stability, which is the entry point for consensus-affecting inconsistency. [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** validation.js (L372-378)
```javascript
					db.takeConnectionFromPool(function(new_conn){
						conn = new_conn;
						start_time = Date.now();
						commit_fn = function (cb2) {
							conn.query(objValidationState.bAdvancedLastStableMci ? "COMMIT" : "ROLLBACK", function () { cb2(); });
						};
						conn.query("BEGIN", function(){cb();});
```

**File:** validation.js (L445-472)
```javascript
			function(err){
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
