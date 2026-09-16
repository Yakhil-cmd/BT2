Based on the investigation, I found a strong analog in ocore's main-chain stability logic that mirrors the kona-node bug: an "origin" reference (there, the L1 origin block; here, a DAG main-chain unit) can transiently disappear/change due to a legitimate reorg-like event, and the code panics via an unguarded `throw Error(...)` instead of returning a recoverable error.

### Title
Unhandled `throw Error` crash on main-chain reorg during stability advancement in `determineIfStableInLaterUnitsAndUpdateStableMcFlag` - (File: main_chain.js)

### Summary
`main_chain.determineIfStableInLaterUnitsAndUpdateStableMcFlag()` is invoked from unit validation (`validateParents`) whenever a freshly posted unit's `last_ball_unit` is not yet marked stable in the DB but appears stable from the perspective of the unit's parents. [1](#0-0)  After determining stability, the function releases its result callback and then, without the caller waiting, asynchronously reacquires the global `handleJoint` mutex to advance the stability point. [2](#0-1)  Once the lock is obtained, it re-reads the earlier unit's properties and assumes it must still be on the main chain — if not, it throws unconditionally:

```js
storage.readUnitProps(db, earlier_unit, async function(objEarlierUnitProps){
    if (!objEarlierUnitProps.is_on_main_chain)
        throw Error("earlier unit is no longer on main chain");
``` [3](#0-2) 

### Finding Description
Between the initial stability check and the moment the `handleJoint` lock is actually granted, other units can be validated and cause the main chain to be recomputed (`goUpFromUnit`/`updateMainChain` reassign `is_on_main_chain` on units when a competing branch attains a better witnessed level). [4](#0-3)  This is the DAG-analog of an L1 reorg: the "origin" unit that was on the main chain when first inspected can be displaced from the main chain while the current call is queued behind the lock.

The code already anticipates *one* kind of race — "the stability point moved while we were waiting for the lock" — and handles it gracefully by simply unlocking. [5](#0-4)  However, the closely related race where the unit is no longer on the main chain at all is not handled the same way; it hits an unconditional `throw Error(...)` inside a deeply nested async callback with no surrounding try/catch, which is uncaught and terminates the Node.js process (the same "unreachable"-style panic pattern flagged in the kona-node report, just implemented as `throw Error` instead of `unreachable!()`).

This function is reached purely by posting ordinary valid units whose `last_ball_unit` is unstable-but-provably-stable-from-parents — a state any unprivileged unit poster can create by choosing `last_ball`/`last_ball_unit` and parents appropriately, and by timing the submission of a competing higher-witnessed-level branch to shift the main chain while the first unit's stabilization call is waiting on the mutex.

### Impact Explanation
Because every full node evaluates unit validity and stability using the same deterministic algorithm over the same DAG, a unit sequence that triggers this race will trigger it identically on every full node that processes the same units in a similar interleaving. A crash here kills the node process handling core validation/stabilization, directly matching the report's accepted impact category of "node disagreement on validity or stability" and, if it propagates broadly, "network unable to confirm new units."

### Likelihood Explanation
This requires a specific timing window (main-chain rebuild occurring exactly while the `handleJoint` lock is being awaited for a previously-determined-stable-in-parents unit) rather than being deterministically reproducible from a single unit. It is more likely under load/contention (many competing units arriving), which an attacker can deliberately induce by racing a validation-heavy sequence of units with a competing best-parent branch. Given the asynchronous, lock-queued nature of the code, this is plausible but not trivially deterministic, which limits likelihood to medium.

### Recommendation
Handle the "earlier unit no longer on main chain" case the same way as the sibling "stability point moved" case: unlock and log/return gracefully (treat it as a transient condition and let stabilization be retried by a subsequent unit), instead of throwing an uncaught `Error` that crashes the process. This mirrors the kona-node fix of replacing the panic with a recoverable error and a reset/retry path.

### Proof of Concept
1. Node A validates unit U1, whose `last_ball_unit` X is currently unstable in the DB but is provably stable given U1's parents (`determineIfStableInLaterUnits` returns true). `determineIfStableInLaterUnitsAndUpdateStableMcFlag` returns `bStable=true` to the caller and proceeds asynchronously to acquire the `handleJoint` lock to advance stability. [6](#0-5) 
2. Before the lock is granted, an attacker submits additional units forming a competing branch with a higher witnessed level that causes `updateMainChain`/`goUpFromUnit` to rebuild the main chain such that X is no longer `is_on_main_chain`. [4](#0-3) 
3. When the queued call finally acquires the lock and re-reads X's properties, `objEarlierUnitProps.is_on_main_chain` is now falsy, hitting the unguarded throw and crashing the node process. [3](#0-2)

### Citations

**File:** validation.js (L802-810)
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
```

**File:** main_chain.js (L92-123)
```javascript
	function goUpFromUnit(unit){
		if (storage.isGenesisUnit(unit))
			return checkNotRebuildingStableMainChainAndGoDown(0, unit);
		
		profiler.start();
		findNextUpMainChainUnit(unit, function(best_parent_unit){
			storage.readUnitProps(conn, best_parent_unit, function(objBestParentUnitProps){
				var objBestParentUnitProps2 = storage.assocUnstableUnits[best_parent_unit] || storage.assocStableUnits[best_parent_unit];
				if (!objBestParentUnitProps2){
					if (storage.isGenesisUnit(best_parent_unit))
						objBestParentUnitProps2 = storage.assocStableUnits[best_parent_unit];
					else
						throw Error("unstable unit not found: "+best_parent_unit);
				}
				var objBestParentUnitProps2ForCheck = _.clone(objBestParentUnitProps2);
				delete objBestParentUnitProps2ForCheck.parent_units;
				delete objBestParentUnitProps2ForCheck.bAA;
				var objBestParentUnitPropsForCheck = _.clone(objBestParentUnitProps);
				delete objBestParentUnitPropsForCheck.bAA;
				delete objBestParentUnitPropsForCheck.parent_units;
				if (!storage.isGenesisUnit(best_parent_unit))
					delete objBestParentUnitProps2ForCheck.assocEarnedHeadersCommissionRecipients;
				if (!conf.bFaster && !_.isEqual(objBestParentUnitProps2ForCheck, objBestParentUnitPropsForCheck))
					throwError("different props, db: "+JSON.stringify(objBestParentUnitProps)+", unstable: "+JSON.stringify(objBestParentUnitProps2));
				if (!objBestParentUnitProps.is_on_main_chain)
					conn.query("UPDATE units SET is_on_main_chain=1, main_chain_index=NULL WHERE unit=?", [best_parent_unit], function(){
						objBestParentUnitProps2.is_on_main_chain = 1;
						objBestParentUnitProps2.main_chain_index = null;
						arrNewMcUnits.push(best_parent_unit);
						profiler.stop('mc-goUpFromUnit');
						goUpFromUnit(best_parent_unit);
					});
```

**File:** main_chain.js (L1195-1220)
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
```

**File:** main_chain.js (L1222-1223)
```javascript
					if (new_last_stable_mci <= last_stable_mci || objEarlierUnitProps.is_stable)
						return unlock("the stability point moved while we were waiting for the lock, last_stable_mci="+last_stable_mci+", new_last_stable_mci="+new_last_stable_mci);
```
