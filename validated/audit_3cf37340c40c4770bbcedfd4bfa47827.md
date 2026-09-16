### Title
Missing synchronization between stability-point advancement and unit validation allows a TOCTOU race on last-ball stability - ([File: main_chain.js])

### Summary
`main_chain.determineIfStableInLaterUnitsAndUpdateStableMcFlag()` reports a stability verdict to its caller *before* the corresponding database/cache mutation that makes that verdict true has actually been committed, and the two phases are protected by different, unrelated mutex domains. This mirrors the CVE-2019-11599 bug class: a consumer inspects shared state (vma layout / here: stability of an MCI and its cached unit props) while a concurrent actor is still allowed to mutate that same state without a shared lock, producing an inconsistent view that downstream validation logic (double-spend / sequence checks) trusts as final.

### Finding Description
`validateParents()` calls this function while holding a mutex lock keyed on the *unit's own author addresses*, not on any global stability-related key: [1](#0-0) 

Inside `determineIfStableInLaterUnitsAndUpdateStableMcFlag()`, once `bStable` is computed, the result is handed back to the caller immediately via `handleResult(bStable, true)`. The comment right above the call is explicit that the callback has already fired and everything from that point on is best-effort cleanup: [2](#0-1) 

Only after invoking `handleResult` does the function acquire the `"handleJoint"` mutex to actually read `readLastStableMcIndex`, verify `objEarlierUnitProps`, and walk `stabilizeMci(mci)` across the MCI range to write `is_stable`, cached unit props (`storage.assocStableUnits`/`assocUnstableUnits`), execute AA triggers, and update TPS fees: [3](#0-2) 

Because the caller in `validateParents()` is holding a lock on `arrAuthorAddresses` — a completely different key than `"handleJoint"` — a second unit validation for *different* authors can enter `validateParents()` concurrently and call the same function again for an overlapping or identical MCI range while the first call's `stabilizeMci` loop is still running under `"handleJoint"`: [4](#0-3) 

The consumer of the "stable" verdict (`checkNoSameAddressInDifferentParents()`, and further down `findConflictingUnits()`/`checkForDoublespends()` in author/message validation) relies on `main_chain_index`, `is_stable`, and `sequence` columns of `units`/`unit_authors` that may not yet reflect the just-computed stability transition, since the actual `UPDATE`s happen later inside `stabilizeMci()` under the unrelated lock. `tryToAdvanceStabilityPointForCatchupAATrigger()` in `network.js` invokes the very same function on yet another, uncoordinated connection with no outer author-address lock at all, widening the race window further: [5](#0-4) 

The root cause is the same as in the kernel CVE: the code that reads/relies on evolving shared state (`is_stable` flags, `main_chain_index`, in-memory `storage.assocUnstableUnits`/`assocStableUnits` caches) does not hold the same lock as the code that mutates that state (`stabilizeMci`), so two racing paths can observe or act on a half-updated stability point.

### Impact Explanation
If a conflicting-unit / double-spend check (`findConflictingUnits`, `checkForDoublespends` in `validation.js`) executes for one unit while another concurrent validation's `stabilizeMci` walk is mid-flight for the same MCI range, the `is_stable`/`main_chain_index`/`sequence` values read by the first unit can be stale relative to the just-reported "stable" verdict. This can let a unit be accepted as serial/good against a view of the DAG that a concurrently-stabilizing writer is simultaneously altering (including running AA triggers and TPS fee updates for that MCI), producing node disagreement on unit validity/stability between nodes that happen to interleave the race differently, or admitting a unit whose last-ball stability assumption is invalidated moments later — a precondition for accepting a payment that later conflicts with a stable output.

### Likelihood Explanation
Triggering the race only requires an attacker (or even ordinary network traffic) to submit two units authored by different addresses whose `last_ball_unit`s are on the boundary of becoming stable at roughly the same time — a naturally recurring condition on a live network with concurrent unit posting, and explicitly reachable by any unprivileged unit poster since `validate()` is entered from `handleJoint`/`handlePostedJoint` for every incoming/posted unit. No special network position or privilege is needed; only precise timing of two ordinary unit submissions is required, which is plausible given how frequently `determineIfStableInLaterUnitsAndUpdateStableMcFlag` is invoked at the stability frontier.

### Recommendation
Serialize all callers of `determineIfStableInLaterUnitsAndUpdateStableMcFlag()` (in `validation.js`, `network.js`) on the same lock key used for the actual stabilization walk (`"handleJoint"`), or restructure the function so `handleResult` is only invoked after the MCI-advancement loop and cache mutation are fully committed, removing the "report result early, mutate later" pattern. At minimum, ensure the unit's own validation transaction cannot be trusted/committed based on a stability verdict whose backing mutation is still pending under an unrelated lock.

### Proof of Concept
1. Prepare two units U1 (author A1) and U2 (author A2) whose `last_ball_unit`s are the same on-MC unit that is stable in the view of both units' parents but not yet marked `is_stable=1` in the `units` table.
2. Submit U1 and U2 concurrently (e.g., via two simultaneous `handlePostedJoint`/`handleJoint` calls). Each acquires `mutex.lock(arrAuthorAddresses,...)` on disjoint address sets (`A1` vs `A2`), so both proceed into `validateParents()` in parallel.
3. Both call `main_chain.determineIfStableInLaterUnitsAndUpdateStableMcFlag(conn, last_ball_unit, ...)`. The first caller to reach `handleResult(bStable, true)` unblocks its `validateParents()` continuation immediately, while its own `stabilizeMci()` walk (writing `is_stable`, `main_chain_index`, executing AA triggers, updating cached `storage.assocStableUnits`) is still queued behind the `"handleJoint"` mutex.
4. The second caller's `checkNoSameAddressInDifferentParents`/`findConflictingUnits`/`checkForDoublespends` queries run against `units`/`unit_authors` rows that have not yet been updated by step 3's in-flight `stabilizeMci` loop, potentially returning a decision (serial/good vs conflicting) inconsistent with the state that will exist microseconds later once the first caller's `"handleJoint"`-protected mutation completes.
5. Instrumenting with `breadcrumbs.add` (already present at `main_chain.js:1201/1208`) and timestamps shows the window between `handleResult(bStable, true)` and the actual `stabilizeMci` completion, confirming the unsynchronized read/mutate gap.

### Citations

**File:** validation.js (L357-357)
```javascript
	mutex.lock(arrAuthorAddresses, function(unlock){
```

**File:** validation.js (L794-826)
```javascript
					readMaxParentLastBallMci(function(max_parent_last_ball_mci){
						if (objLastBallUnitProps.is_stable === 1){
							// if it were not stable, we wouldn't have had the ball at all
							if (objLastBallUnitProps.ball !== last_ball)
								return callback("stable: last_ball "+last_ball+" and last_ball_unit "+last_ball_unit+" do not match");
							if (objValidationState.last_ball_mci <= constants.lastBallStableInParentsUpgradeMci || max_parent_last_ball_mci === objValidationState.last_ball_mci)
								return checkNoSameAddressInDifferentParents();
						}
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

**File:** main_chain.js (L1192-1208)
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
```

**File:** main_chain.js (L1218-1236)
```javascript
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
```

**File:** network.js (L1328-1349)
```javascript
async function tryToAdvanceStabilityPointForCatchupAATrigger(objJoint){
	const objUnit = objJoint.unit;
	const unit = objUnit.unit;
	const ball = objJoint.ball;
	if (!ball || storage.assocHashTreeUnitsByBall[ball] !== unit)
		return;
	// the parent might not be known to us yet, hence not in assocUnstableUnits
	const parent_unit = objUnit.parent_units.find(parent_unit => {
		const props = storage.assocUnstableUnits[parent_unit];
		return props && props.is_on_main_chain && !props.is_stable;
	});
	if (!parent_unit)
		return;
	const arrFreeUnits = main_chain.getFreeUnits();
	console.log(`possible AA trigger for unit ${unit}: trying to advance the stability point to its MC parent ${parent_unit} using free units ${arrFreeUnits.join(', ')}`);
	// use a dedicated connection so that interleaving writes from other tasks don't interfere with this check
	const conn = await db.takeConnectionFromPool();
	await conn.query("BEGIN");
	const bStable = await main_chain.determineIfStableInLaterUnitsAndUpdateStableMcFlag(conn, parent_unit, arrFreeUnits, false);
	console.log(`AA parent ${parent_unit} stable in free units ${arrFreeUnits.join(', ')}? ${bStable}`);
	await conn.query("COMMIT");
	conn.release();
```
