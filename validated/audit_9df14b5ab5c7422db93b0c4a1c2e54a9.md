# Race Condition in Premature Stability-Result Callback Before Lock-Protected State Mutation - (File: main_chain.js)

### Summary
The CometBFT advisory fixes a race where `gossipVotesRoutine` read/mutated shared peer-vote state from a goroutine that raced with another goroutine holding (or about to hold) the same state's lock, and the fix wraps the critical section in a lock acquired for the full duration (RAII-style) instead of releasing/reporting early. `ocore` has a structurally similar pattern in `determineIfStableInLaterUnitsAndUpdateStableMcFlag()`: it invokes the caller's result callback (`handleResult`) *before* it has taken the `handleJoint` lock and performed the actual mutation of shared, cached DAG-stability state (`storage.assocUnstableUnits`, `storage.assocStableUnits`, `min_retrievable_mci`, and eventual `stabilizeMci()`/AA-trigger execution). Other unit-processing paths that read this same cached state in the intervening window can observe stale/inconsistent stability status.

### Finding Description
`determineIfStableInLaterUnitsAndUpdateStableMcFlag(conn, earlier_unit, arrLaterUnits, bStableInDb, handleResult)` first determines whether `earlier_unit` is stable relative to `arrLaterUnits`, and — critically — calls the result callback immediately once stability is determined, annotating this in its own comment: [1](#0-0) 

The function then *continues executing after already answering the caller*, acquiring the `"handleJoint"` mutex only afterward to perform the real state transition (`stabilizeMci` for each MCI up to `new_last_stable_mci`): [2](#0-1) 

This code path is reachable from an unprivileged unit poster: `validation.js` calls `determineIfStableInLaterUnitsAndUpdateStableMcFlag` while validating parents of a newly posted/received unit, and `network.js` invokes it directly from `tryToAdvanceStabilityPointForCatchupAATrigger`, which any node runs whenever unit validation returns the transient `"possible AA"` error during catch-up: [3](#0-2) [4](#0-3) 

The `tryToAdvanceStabilityPointForCatchupAATrigger` code even acknowledges the concurrency hazard explicitly ("use a dedicated connection so that interleaving writes from other tasks don't interfere with this check"), but this only protects the DB connection, not the process-wide in-memory caches (`storage.assocUnstableUnits`/`assocStableUnits`) that other concurrently-running validations, `data_feeds.js` lookups, and AA trigger balance calculations read directly without going through any lock (see e.g. `data_feeds.js` iterating `storage.assocUnstableMessages`/`assocUnstableUnits` unprotected): [5](#0-4) 

Because the stability result is reported to the calling validation logic (which may proceed to treat `earlier_unit`/its MCI as final and continue composing dependent validation decisions) before the `handleJoint` lock is obtained and the mci-by-mci `stabilizeMci` mutation actually commits, a second unit being validated or an AA trigger evaluating data feeds/balances in the same window can read the pre-mutation cache state (unit not yet marked stable, `count_aa_responses`/balances not yet updated) while the first caller has already been told "stable."

### Impact Explanation
If two logically dependent decisions (e.g., data-feed value resolution for an AA condition, main-chain-index-dependent balance snapshot for `aa_balances`, or a second unit's parent-stability check) are made against inconsistent snapshots of `storage.assocUnstableUnits`/`assocStableUnits` straddling this window, nodes can diverge on unit validity/stability, or an AA can evaluate a data feed/balance using not-yet-committed vs. already-committed state depending on timing — this falls under "node disagreement on validity or stability," which can, in the worst case, contribute to inconsistent stabilization of MC indexes across nodes or double execution/omission of AA triggers tied to the advanced stability point.

### Likelihood Explanation
Triggering the "possible AA" transient-error path only requires posting a unit that a catching-up node cannot yet validate because a preceding AA trigger for the same address hasn't executed — an entirely normal, attacker-reachable condition for any node still catching up (which happens routinely after any node restart or resync). No special privileges are needed; only network posting of an ordinary unit is required to enter this code path repeatedly.

### Recommendation
Refactor `determineIfStableInLaterUnitsAndUpdateStableMcFlag` so that the `handleResult` callback is only invoked after the `handleJoint` lock has been acquired and the stability-point advance (`stabilizeMci` loop) has fully committed, mirroring the CometBFT fix pattern of holding the lock for the entire critical section (RAII-style) rather than reporting a result and continuing unguarded mutation afterward. Alternatively, ensure all callers explicitly wait on a completion signal from the background continuation (not just the boolean stability result) before making further decisions that depend on `storage.assocUnstableUnits`/`assocStableUnits` consistency.

### Proof of Concept
Exact reproduction requires precise timing between: (1) a node catching up and receiving a unit whose validation returns `"possible AA"`, triggering `tryToAdvanceStabilityPointForCatchupAATrigger` → `determineIfStableInLaterUnitsAndUpdateStableMcFlag`, and (2) a second concurrently-processed unit or AA trigger reading `storage.assocUnstableUnits`/`assocStableUnits` (e.g., via `data_feeds.js` or `aa_composer.js` balance lookups) in the window between the early `handleResult(bStable, true)` callback and the later `handleJoint`-locked `stabilizeMci` commit. I was not able to fully trace every downstream consumer of the prematurely-returned result within the available investigation budget, so the exact interleaving needed to produce a concretely provable double-spend/consensus-fork scenario (as opposed to a narrower stale-cache read) remains unverified and should be confirmed with a live/e2e race-reproduction test (analogous to the CometBFT PR's own approach of "exacerbating the race in tests") before treating this as fully proven.

### Citations

**File:** main_chain.js (L1195-1235)
```javascript
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
```

**File:** network.js (L1216-1217)
```javascript
					if (error === "possible AA" && bCatchingUp)
						tryToAdvanceStabilityPointForCatchupAATrigger(objJoint);
```

**File:** network.js (L1328-1350)
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
}
```

**File:** data_feeds.js (L34-44)
```javascript
		for (var unit in storage.assocUnstableMessages) {
			var objUnit = storage.assocUnstableUnits[unit] || storage.assocStableUnits[unit];
			if (!objUnit)
				throw Error("unstable unit " + unit + " not in assoc");
			if (!objUnit.bAA)
				continue;
			if (objUnit.latest_included_mc_index < min_mci || objUnit.latest_included_mc_index > max_mci)
				continue;
			if (_.intersection(arrAddresses, objUnit.author_addresses).length === 0)
				continue;
			storage.assocUnstableMessages[unit].forEach(function (message) {
```
