## Analysis

The EigenLayer commit fixes a race where an offchain "table updater" would **panic (crash the whole service)** if another transaction updated the same table first — the fix is to detect the already-updated case and return early instead of blowing up. The equivalent reachable surface in `ocore` is the main-chain stability advancement logic in `main_chain.js`, which is entered from ordinary unit validation and can be frontrun by a concurrent unit that reorganizes the main chain.

### Root cause

`validateParents()` calls `main_chain.determineIfStableInLaterUnitsAndUpdateStableMcFlag()` whenever a posted unit's `last_ball_unit` is not yet marked stable in the DB but might be stable from the point of view of the unit's parents: [1](#0-0) 

Inside that function, the stability determination is done first (without holding any global lock), the caller is immediately unblocked via `handleResult(bStable, true)`, and only *afterwards* does the code acquire the `handleJoint` mutex and *re-read* the earlier unit's properties to actually advance the stability point: [2](#0-1) 

Between the initial (lock-free) stability check and the point where the `handleJoint` lock is finally obtained and `objEarlierUnitProps` is freshly read, another unit can be concurrently validated and written by `writer.saveJoint()` → `main_chain.updateMainChain()`, which is able to rebuild/reorganize the main chain and flip `is_on_main_chain` for previously-included units: [3](#0-2) 

If that concurrent "frontrunning" write moves `earlier_unit` off the main chain before the delayed continuation runs, the guard at line 1219 fires:

```
if (!objEarlierUnitProps.is_on_main_chain)
    throw Error("earlier unit is no longer on main chain");
``` [4](#0-3) 

This `throw` happens deep inside a chain of asynchronous DB callbacks (`storage.readUnitProps(db, earlier_unit, async function(...){...})`), with no surrounding `try/catch` and after `handleResult()` has already told the validation flow that the unit is valid. An uncaught exception thrown from inside such an async callback is not caught by any of the `async.series`/`mutex` error-handling paths in `validation.js` or `network.js` and results in a Node.js process crash (default behavior on uncaught exceptions), exactly analogous to the "entire service can panic if frontrun by another tx" bug class described in the report.

### Title
Race condition in `determineIfStableInLaterUnitsAndUpdateStableMcFlag` can crash the node when frontrun by a concurrent MC-rebuilding write - ([File: main_chain.js])

### Summary
`determineIfStableInLaterUnitsAndUpdateStableMcFlag()`, called from ordinary unit validation (`validateParents`), determines stability using one DB snapshot, releases control back to the caller, and only later (after acquiring the `handleJoint` mutex) re-validates that the earlier unit is still on the main chain. If a concurrently-processed unit rebuilds the main chain in between (via `updateMainChain`/`goDownAndUpdateMainChainIndex`), the delayed continuation's assumption becomes false and it executes an unguarded `throw Error("earlier unit is no longer on main chain")`.

### Finding Description
Unit validation for any newly posted unit that references a `last_ball_unit` which is not yet stable in the DB, but appears stable from the parents' perspective, triggers `determineIfStableInLaterUnitsAndUpdateStableMcFlag`. This function immediately returns its "stable" verdict to the validation pipeline (unblocking commit of the current unit), then asynchronously acquires the `handleJoint` lock to physically advance the stability point. Because the initial determination is not made under the `handleJoint` lock, an unrelated unit being validated/written concurrently (each unit's own validation uses a per-author-address mutex, not `handleJoint`, per `validation.js:357`) can complete a main-chain rebuild in the intervening window. When the delayed continuation resumes and re-reads `objEarlierUnitProps`, it may find `is_on_main_chain=0`, triggering an unguarded `throw`, deep in nested async callbacks with no error boundary.

### Impact Explanation
An uncaught exception thrown inside these deeply nested DB callbacks is not caught anywhere in the call chain and crashes the Node.js process. A single specially-timed pair of concurrently posted/relayed units (fully reachable by unprivileged unit posters — no special peer/hub/operator privileges are required) is sufficient to trigger it on any full node processing the traffic, which — if triggered broadly — can knock nodes offline and prevent the network from continuing to validate/confirm units, matching a "network unable to confirm new units" outcome.

### Likelihood Explanation
The trigger only requires ordinary unit posting patterns that create instability/branching around the last-ball point (common on any node processing concurrent traffic near the tip) combined with tight timing between two units' validations. This does not require a malicious peer, hub, or any elevated privilege — any two units racing through `validateParents` can hit it.

### Recommendation
In `determineIfStableInLaterUnitsAndUpdateStableMcFlag`, replace the unconditional `throw Error("earlier unit is no longer on main chain")` with a graceful bail-out (analogous to the EigenLayer fix's "return if the table has already been updated"): if `objEarlierUnitProps.is_on_main_chain` is false when the delayed continuation resumes, treat it the same as "the stability point moved while we were waiting for the lock" and simply `unlock()` without advancing, since a concurrent rebuild has already made this attempt obsolete.

### Proof of Concept
1. Node A is validating unit U1 whose `last_ball_unit` E is not yet stable in DB but is stable relative to U1's parents → `determineIfStableInLaterUnitsAndUpdateStableMcFlag(conn, E, parents_of_U1, ...)` is invoked; `handleResult(true, true)` fires immediately, allowing U1's validation/commit to proceed, while the function continues asynchronously toward acquiring the `handleJoint` lock.
2. Before that lock is acquired, unit U2 (posted concurrently, under a different author-address mutex) is validated and written via `writer.saveJoint` → `main_chain.updateMainChain`, causing a main-chain reorganization that sets `is_on_main_chain=0` for unit E (`main_chain.js:150-163`).
3. The delayed continuation for U1 now acquires the `handleJoint` lock and calls `storage.readUnitProps(db, E, ...)`, obtaining the updated props showing `is_on_main_chain=0`.
4. `main_chain.js:1219-1220` executes `throw Error("earlier unit is no longer on main chain")`, uncaught, crashing the Node.js process. [2](#0-1) [1](#0-0) [3](#0-2)

### Citations

**File:** validation.js (L802-812)
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
```

**File:** main_chain.js (L150-163)
```javascript
	function goDownAndUpdateMainChainIndex(last_main_chain_index, last_main_chain_unit){
		profiler.start();
		conn.query(
			//"UPDATE units SET is_on_main_chain=0, main_chain_index=NULL WHERE is_on_main_chain=1 AND main_chain_index>?", 
			"UPDATE units SET is_on_main_chain=0, main_chain_index=NULL WHERE main_chain_index>?", 
			[last_main_chain_index], 
			function(){
				for (var unit in storage.assocUnstableUnits){
					var o = storage.assocUnstableUnits[unit];
					if (o.main_chain_index > last_main_chain_index){
						o.is_on_main_chain = 0;
						o.main_chain_index = null;
					}
				}
```

**File:** main_chain.js (L1192-1223)
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
```
