### Title
Unrecoverable deadlock of the global `handleJoint` mutex during main-chain stability advancement - (File: main_chain.js)

### Summary
`determineIfStableInLaterUnitsAndUpdateStableMcFlag()` in `main_chain.js` acquires the global `handleJoint` mutex and then, inside the locked callback, performs a `throw Error(...)` on an unexpected-state condition instead of releasing the lock and returning an error. Because virtually every code path that validates or writes a newly posted unit first acquires this same `handleJoint` lock (`network.js`, `composer.js`, `divisible_asset.js`, `indivisible_asset.js`, `writer.js`), an uncaught throw while the lock is held leaves the mutex permanently locked, exactly mirroring the CVE-2020-12771 pattern where a failed btree coalesce operation left a lock held and deadlocked the kernel. In ocore this stalls all future unit validation network‑wide.

### Finding Description
`validation.js` calls `main_chain.determineIfStableInLaterUnitsAndUpdateStableMcFlag()` while validating the `last_ball` stability of every incoming unit (called from `validateParents`/`validateHashTreeBall`-related logic), so this code path is exercised by any unprivileged unit poster whose unit references a `last_ball`. [1](#0-0) 

Inside the function, once a unit is found stable in later units but not yet marked stable in the DB, the code proceeds to acquire the `handleJoint` mutex and re-reads the unit's on-main-chain status: [2](#0-1) 

```js
storage.readUnitProps(db, earlier_unit, async function(objEarlierUnitProps){
    if (!objEarlierUnitProps.is_on_main_chain)
        throw Error("earlier unit is no longer on main chain");
    ...
```

If, between the initial stability computation and the point where the `handleJoint` lock is finally acquired, the main chain has reorganized so `earlier_unit` is no longer on the main chain (a state fully attacker-influenceable by posting units that shift the best-parent/main-chain selection), this `throw Error` fires *while the `handleJoint` lock is held* and *before* `unlock()` is ever called. The mutex implementation in `mutex.js` provides no timeout-based recovery for held locks (the `checkForDeadlocks()` watchdog is explicitly commented out because long-held locks are considered normal in multisig scenarios): [3](#0-2) 

Because `handleJoint` is the same lock acquired by `network.handleJoint`, `composer.getSavingCallbacks`, `divisible_asset.getSavingCallbacks`, `indivisible_asset.getSavingCallbacks`, and by `startRelay()` at node startup, once it is stuck locked, no further unit — from any peer or local API caller — can ever be validated or saved again: [4](#0-3) [5](#0-4) 

This is the direct analog of CVE-2020-12771: a failure mid-operation (`btree_gc_coalesce` failing / `main_chain` stability advancement hitting an unexpected reorg state) leaves a lock held indefinitely, deadlocking all subsequent operations that need the same lock.

### Impact Explanation
Once the `handleJoint` mutex is stuck, the entire node stops accepting and validating any new unit — a total halt of consensus progress on that node ("a network unable to confirm new units"). Since this is a shared mutex guarding the core validation/write pipeline, the effect is a full denial of service that persists until the process is manually restarted; any units already in flight or queued behind the lock never resolve.

### Likelihood Explanation
Triggering the specific interleaving (a concurrent main-chain reorg flipping `is_on_main_chain` for `earlier_unit` between the initial stability check and the delayed re-check under lock) requires precise timing, but it is a state entirely reachable by an unprivileged peer through ordinary unit posting that influences best-parent selection and alternate branches — no special privileges, hub role, or malicious peer/network position are needed. This is a race-condition class bug, so exploitation reliability depends on timing, but the condition is explicitly anticipated by the code itself (the check exists specifically to detect this case) yet handled with an unrecoverable `throw` instead of a safe unlock-and-retry.

### Recommendation
Wrap the `storage.readUnitProps` callback logic in a try/catch (or convert to async/await with try/catch) so that on the "earlier unit is no longer on main chain" condition (and any other unexpected error), the code calls `unlock()` before returning/throwing, or better, treats this as a recoverable transient condition (log and return, similar to the sibling early-return branch at the "stability point moved while we were waiting for the lock" case) rather than crashing/throwing while holding a global lock. Consider adding a bounded watchdog around long-held critical locks like `handleJoint` that logs/dumps diagnostics rather than leaving the mutex silently stuck.

### Proof of Concept
1. An attacker (or naturally occurring network conditions) crafts a sequence of units that cause the DAG's main chain to reorganize such that a unit `earlier_unit`, previously computed as stable-in-later-units, is no longer `is_on_main_chain` by the time `determineIfStableInLaterUnitsAndUpdateStableMcFlag()` re-reads its props after acquiring the `handleJoint` lock.
2. `storage.readUnitProps` returns `objEarlierUnitProps.is_on_main_chain === false`.
3. `throw Error("earlier unit is no longer on main chain")` executes inside the `mutex.lock(["handleJoint"], ...)` callback, before `unlock()` is reached.
4. The `handleJoint` lock in `mutex.js`'s `arrLockedKeyArrays` is never released via `release()`.
5. All subsequent `mutex.lock(['handleJoint'], ...)` calls from `network.handleJoint`, `composer`, `divisible_asset`, `indivisible_asset`, and `writer.saveJoint`'s AA-trigger-stabilization path queue indefinitely, and no new unit is ever validated again on that node.

### Citations

**File:** main_chain.js (L1190-1194)
```javascript
// It is assumed earlier_unit is not marked as stable yet
// If it appears to be stable, its MC index will be marked as stable, as well as all preceeding MC indexes
function determineIfStableInLaterUnitsAndUpdateStableMcFlag(conn, earlier_unit, arrLaterUnits, bStableInDb, handleResult){
	if (!handleResult)
		return new Promise(resolve => determineIfStableInLaterUnitsAndUpdateStableMcFlag(conn, earlier_unit, arrLaterUnits, bStableInDb, resolve));
```

**File:** main_chain.js (L1201-1223)
```javascript
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

**File:** mutex.js (L107-121)
```javascript
function checkForDeadlocks(){
	for (var i=0; i<arrQueuedJobs.length; i++){
		var job = arrQueuedJobs[i];
		if (Date.now() - job.ts > 30*1000)
			throw Error("possible deadlock on job "+require('util').inspect(job)+",\nproc:"+job.proc.toString()+" \nall jobs: "+require('util').inspect(arrQueuedJobs, {depth: null}));
	}
}

// long running locks are normal in multisig scenarios
//setInterval(checkForDeadlocks, 1000);

setInterval(function(){
	if (arrQueuedJobs.length > 0 || arrLockedKeyArrays.length > 0)
		console.log("queued jobs: " + JSON.stringify(arrQueuedJobs.map(function (job) { return job.arrKeys; })) + ", locked keys: " + JSON.stringify(arrLockedKeyArrays));
}, 10000);
```

**File:** network.js (L1165-1168)
```javascript
	var validate = function(){
		mutex.lock(['handleJoint'], function(unlock){
			if (ws && !conf.bLight)
				currentJointHost = ws.host;
```

**File:** composer.js (L735-739)
```javascript
			const validate_and_save_unlock = await mutex.lock('handleJoint');
			const combined_unlock = () => {
				validate_and_save_unlock();
				composer_unlock();
			};
```
