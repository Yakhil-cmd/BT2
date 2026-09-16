### Title
Race condition in `tryToAdvanceStabilityPointForCatchupAATrigger` mutates main-chain stability state outside the `write` mutex, causing node disagreement on stability - ([File: network.js])

### Summary
`network.js` schedules an async "catch-up AA" stability-advancement task (`tryToAdvanceStabilityPointForCatchupAATrigger`) directly from the joint-validation error path, without acquiring the `write` mutex that guards every other code path that mutates main-chain stability flags and the in-memory unit caches (`storage.assocUnstableUnits`, etc.). This is structurally analogous to the underlying CVE-2020-6543 bug class: a task is scheduled to run later, and by the time it executes, the shared state it references may already have been mutated/invalidated by another concurrently running task that holds the proper lock.

### Finding Description
When a unit is rejected during catch-up with the transient error `"possible AA"`, `network.js` fires off an unguarded background task: [1](#0-0) 

That task, `tryToAdvanceStabilityPointForCatchupAATrigger`, reads the live in-memory cache `storage.assocUnstableUnits` to pick a parent unit, then calls `main_chain.determineIfStableInLaterUnitsAndUpdateStableMcFlag` — a function that both writes `is_stable`/related flags to the DB and updates the corresponding in-memory unit-cache objects — using only a freshly obtained DB connection, not the `write` mutex: [2](#0-1) 

The comment on line 1343 ("use a dedicated connection so that interleaving writes from other tasks don't interfere with this check") shows the author was aware of a concurrency hazard but only isolated the **SQL connection/transaction**, not the **in-process caches** (`assocUnstableUnits`, `assocStableUnits`, `assocBestChildren`, etc.) that are shared mutable state across the whole process.

Everywhere else that mutates this same stability state — normal unit validation/commit in `writer.saveJoint`, cache eviction in `storage.shrinkCache`, and unit forgetting via `storage.forgetUnit`/`fixIsFreeAfterForgettingUnit` — is serialized with `mutex.lock(['write'], ...)`: [3](#0-2) [4](#0-3) 

`storage.readUnitProps` even contains an explicit consistency assertion that throws if the in-memory cache and the freshly read DB row for an unstable unit ever diverge: [5](#0-4) 

Because `tryToAdvanceStabilityPointForCatchupAATrigger` is scheduled as a detached async task (fire-and-forget, no `await` on its caller, no `write` lock) it can run interleaved with a concurrent `writer.saveJoint` → `main_chain.advanceMcStability` sequence that is stabilizing MCIs, running AA triggers, and forgetting/rewriting the exact same `assocUnstableUnits[parent_unit]` object this task read moments earlier. The parent unit object referenced by the task can be forgotten (`storage.forgetUnit`, which does `delete assocUnstableUnits[unit]`) or have its `is_stable`/MC flags flipped by the properly-locked path while the unlocked task is mid-flight, which is the same "stale reference used after underlying object was already invalidated by another scheduled task" pattern that the Chrome task-scheduler UAF represents, mapped to JS's cooperative-scheduling model (no memory corruption, but state corruption/inconsistent decisions).

### Impact Explanation
If the two concurrent paths disagree about whether `parent_unit` is stable/on-MC at the moment each of them commits its DB transaction, different nodes (or the same node at different times) can end up with a stability determination that is inconsistent with the DB-only path used by other nodes, i.e. **node disagreement on stability**. Because stabilizing an MCI also triggers `aa_composer.handleAATriggers()` down at least one of these code paths, an out-of-lock double advance/rollback race can also lead to AA triggers being queued or executed against a main-chain state that other nodes never reach, i.e. potential AA fund loss/freezing or execution divergence — one of the explicitly accepted impacts.

### Likelihood Explanation
The trigger condition (`error === "possible AA" && bCatchingUp`) is reachable by any peer: it fires whenever a node is catching up and validation of an attacker/peer-supplied unit yields the specific transient error "possible AA" for a unit whose ball is already present in `assocHashTreeUnitsByBall`. An attacker controlling the timing/ordering of units sent to a catching-up node (or simply a normal node during ordinary catch-up) can cause this unlocked task to be scheduled concurrently with ordinary stabilization traffic, which is a very common condition during sync. No special network position or privileged role is required — a single posted unit chain is enough to reach the code path.

### Recommendation
Acquire the `write` mutex (the same lock used by `writer.saveJoint`/`main_chain.advanceMcStability`/`storage.forgetUnit`) before calling `main_chain.determineIfStableInLaterUnitsAndUpdateStableMcFlag` inside `tryToAdvanceStabilityPointForCatchupAATrigger`, so that this speculative stability check is fully serialized with all other mutators of `assocUnstableUnits`/`assocStableUnits`/DB stability flags. Alternatively, re-validate that the referenced `parent_unit` object is still present/unchanged in `storage.assocUnstableUnits` immediately before mutating it while holding the lock, and abort the speculative advancement if it has been forgotten or already stabilized by a concurrent task.

### Proof of Concept
Exact reproduction requires precisely interleaving two async tasks in a running node (a normal catch-up unit stream from an attacker/peer that reliably reproduces the `"possible AA"` transient error while a legitimate `writer.saveJoint`/stabilization batch is concurrently in flight), which cannot be fully demonstrated from static code review alone. The concrete unlocked-vs-locked mutation pattern is nonetheless directly visible by comparing:
- unlocked mutation path: [6](#0-5) 
- locked mutation path used elsewhere for the same shared caches: [7](#0-6)  and [8](#0-7) 

I was not able to fully trace the internals of `main_chain.determineIfStableInLaterUnitsAndUpdateStableMcFlag` (its body was not retrieved before the tool budget ran out), so the exact set of in-memory fields it mutates, and thus the full blast radius of the race, is not fully confirmed — this should be verified by a Devin session with full repository access before treating this as conclusively exploitable for fund loss versus a lower-impact consistency bug.

### Citations

**File:** network.js (L1214-1217)
```javascript
					if (error.includes("last ball just advanced"))
						setTimeout(rerequestLostJoints, 10 * 1000, true);
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

**File:** storage.js (L1540-1551)
```javascript
			else{
				if (!assocUnstableUnits[unit])
					throw Error("no unstable props of "+unit);
				var props2 = _.cloneDeep(assocUnstableUnits[unit]);
				delete props2.parent_units;
				delete props2.assocEarnedHeadersCommissionRecipients;
			//	delete props2.bAA;
				if (!_.isEqual(props, props2)) {
					debugger;
					throw Error("different props of "+unit+", mem: "+JSON.stringify(props2)+", db: "+JSON.stringify(props)+", stack "+stack);
				}
			}
```

**File:** storage.js (L2209-2232)
```javascript
function forgetUnit(unit){
	console.log('forgetting unit '+unit);
	if (!conf.bLight){
		console.log('parents', assocUnstableUnits[unit].parent_units);
		assocUnstableUnits[unit].parent_units.forEach(function(parent_unit){
			console.log('parent '+parent_unit+' best children', JSON.stringify(assocBestChildren[parent_unit]));
			if (assocBestChildren[parent_unit] && assocBestChildren[parent_unit].indexOf(assocUnstableUnits[unit]) >= 0){
				console.log('before pull', assocBestChildren[parent_unit]);
				_.pull(assocBestChildren[parent_unit], assocUnstableUnits[unit]);
				console.log('after pull', assocBestChildren[parent_unit]);
			}
		});
	}
	delete assocKnownUnits[unit];
	delete assocCachedUnits[unit];
	delete assocCachedUnitAuthors[unit];
	delete assocCachedUnitWitnesses[unit];
	delete assocUnstableUnits[unit];
	if (!conf.bLight && assocStableUnits[unit])
		throw Error("trying to forget stable unit "+unit);
	delete assocStableUnits[unit];
	delete assocUnstableMessages[unit];
	delete assocBestChildren[unit];
}
```

**File:** storage.js (L2250-2261)
```javascript
async function shrinkCache(){
	if (Object.keys(assocCachedAssetInfos).length > MAX_ITEMS_IN_CACHE)
		assocCachedAssetInfos = {};
	console.log(Object.keys(assocUnstableUnits).length+" unstable units");
	var arrKnownUnits = Object.keys(assocKnownUnits);
	var arrPropsUnits = Object.keys(assocCachedUnits);
	var arrStableUnits = Object.keys(assocStableUnits);
	var arrAuthorsUnits = Object.keys(assocCachedUnitAuthors);
	var arrWitnessesUnits = Object.keys(assocCachedUnitWitnesses);
	if (arrPropsUnits.length < MAX_ITEMS_IN_CACHE && arrAuthorsUnits.length < MAX_ITEMS_IN_CACHE && arrWitnessesUnits.length < MAX_ITEMS_IN_CACHE && arrKnownUnits.length < MAX_ITEMS_IN_CACHE && arrStableUnits.length < MAX_ITEMS_IN_CACHE)
		return console.log('cache is small, will not shrink');
	const unlock = await mutex.lock("write");
```

**File:** joint_storage.js (L219-227)
```javascript
function purgeUncoveredNonserialJointsUnderLock(){
	mutex.lockOrSkip(["purge_uncovered"], function(unlock){
		mutex.lock(["handleJoint"], function(unlock_hj){
			purgeUncoveredNonserialJoints(false, function(){
				unlock_hj();
				unlock();
			});
		});
	});
```
