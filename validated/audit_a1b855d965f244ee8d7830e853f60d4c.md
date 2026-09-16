### Title
Missing lock coordination between `dryRunPrimaryAATrigger()` and `writer.saveJoint()` allows concurrent mutation of shared unstable-unit caches — (File: aa_composer.js, network.js)

### Summary
The Linux kernel bug fixed a race where `pvr_vm_map()` mutated a shared GPU VM structure without holding `vm_ctx->lock`, while all `drm_gpuva_find*()` lookups assumed that lock was held, causing a NULL-pointer dereference. The analogous pattern in ocore is `aa_composer.dryRunPrimaryAATrigger()`, which is invoked from `network.js` during unit validation (`ifOk`) and mutates the same in-memory caches (`storage.assocUnstableUnits`, `storage.assocBestChildren`, `storage.assocUnstableMessages`) that `writer.saveJoint()` mutates — but `saveJoint()` is the only path that acquires `mutex.lock(["write"])` before touching them.

### Finding Description
`writer.saveJoint()` acquires the global `"write"` mutex before mutating `storage.assocUnstableUnits`, `storage.assocBestChildren`, and `storage.assocUnstableMessages`: [1](#0-0) [2](#0-1) 

All the code paths that read these same caches (`readBestChildrenProps`, `forgetUnit`, `fixIsFreeAfterForgettingUnit`, etc.) are written to assume this "write" lock discipline is respected: [3](#0-2) [4](#0-3) 

However, `network.js`'s `ifOk` handler calls `aa_composer.dryRunPrimaryAATrigger()` for every submitted unit containing a primary AA trigger, and it does so **before** `writer.saveJoint()` is invoked and **without acquiring the `"write"` mutex**: [5](#0-4) 

`dryRunPrimaryAATrigger()` runs `handleTrigger()` against a `ROLLBACK`-ed DB transaction, then calls `revertResponsesInCaches()` to undo any cache mutations performed during the dry run: [6](#0-5) 

`revertResponsesInCaches()` itself directly mutates the shared caches via `storage.forgetUnit()` and `storage.fixIsFreeAfterForgettingUnit()`, again with no lock: [7](#0-6) 

Because these functions run across multiple `await`/callback boundaries (DB queries in `handleTrigger`), other async event-loop turns can interleave — including a concurrent `saveJoint()` call for a *different* unit that legitimately holds the `"write"` lock and is simultaneously pushing/pulling entries in `assocBestChildren`/`assocUnstableUnits` for units that share a parent with the unit being dry-run. Since `dryRunPrimaryAATrigger()` never checks or waits on `mutex.isAnyOfKeysLocked(["write"])`, its cache reads/writes and the locked writer's cache reads/writes are not mutually exclusive, unlike every other cache-mutating path in the codebase (`writer.js`, `storage.shrinkCache`, `storage.resetMemory`, `main_chain.js` stabilization) which all take the `"write"` lock first.

### Impact Explanation
If `dryRunPrimaryAATrigger()`'s temporary cache entries (added during `handleTrigger`, then removed by `revertResponsesInCaches`) interleave with a real `saveJoint()` for a sibling/child unit, `assocBestChildren[parent_unit]` arrays or `assocUnstableUnits` entries can be corrupted (entries pulled that shouldn't be, or best-parent/best-children bookkeeping left in an inconsistent state relative to the DB). This directly feeds `main_chain.js` stability and main-chain-index determination (`readBestChildrenProps`, `determineIfStableInLaterUnits...`), which decide whether an output is stable. A corrupted in-memory view of best children/free units can cause a node to diverge from other nodes on which unit is considered the best parent or when a unit becomes stable — i.e., node disagreement on validity/stability, and potentially a route to double-spend acceptance of an output believed final on one node but not another.

### Likelihood Explanation
This requires two AA-related units to be validated/submitted in close succession such that one unit's dry run (`conf.bDryRunNewTriggers` path) overlaps in the event loop with another unit's real `saveJoint()` write — a condition an unprivileged unit poster can trigger simply by broadcasting/posting units with primary AA triggers in quick succession, since AA triggers are routinely posted by any wallet. No special network position or privileges are required.

### Recommendation
Have `dryRunPrimaryAATrigger()` (and `revertResponsesInCaches()`) acquire `mutex.lock(["write"])` for the duration of its cache mutation and rollback, mirroring the fix pattern of acquiring the shared lock before any operation that mutates or reads structures assumed to be lock-protected — the same remediation approach as `pvr_vm_map()` acquiring `vm_ctx->lock` before touching the GPU VM.

### Proof of Concept
1. Node A receives unit U1 containing a primary AA trigger to AA address X; `network.js` `ifOk` begins `await aa_composer.dryRunPrimaryAATrigger(...)`, which starts mutating `storage.assocUnstableUnits`/`assocBestChildren` inside `handleTrigger` (async, spans DB query callbacks) without any lock.
2. Concurrently, unit U2 (a legitimate child of the same best-parent unit as U1) finishes validation and calls `writer.saveJoint()`, which acquires `mutex.lock(["write"])` and pushes into `storage.assocBestChildren[best_parent_unit]`.
3. Because U1's dry run holds no lock, its subsequent `revertResponsesInCaches()` (`_.pull(assocBestChildren[parent_unit], ...)`) can execute interleaved with step 2's push, leaving `assocBestChildren[parent_unit]` in a state inconsistent with the DB.
4. Subsequent calls to `main_chain.readBestChildrenProps()` — which cross-checks the in-memory cache against the DB and `throwError`s on mismatch — can crash the node, or (if the check path is bypassed) cause incorrect best-parent/stability computation, producing node disagreement on unit validity/stability.

### Citations

**File:** writer.js (L34-35)
```javascript
	const unlock = objValidationState.bUnderWriteLock ? () => { } : await mutex.lock(["write"]);
	console.log("got lock to write " + objUnit.unit);
```

**File:** writer.js (L596-602)
```javascript
			else
				storage.assocUnstableUnits[objUnit.unit] = objNewUnitProps;
			if (!bGenesis && storage.assocUnstableUnits[my_best_parent_unit]) {
				if (!storage.assocBestChildren[my_best_parent_unit])
					storage.assocBestChildren[my_best_parent_unit] = [];
				storage.assocBestChildren[my_best_parent_unit].push(objNewUnitProps);
			}
```

**File:** main_chain.js (L704-712)
```javascript
function readBestChildrenProps(conn, arrUnits, handleResult){
	if (arrUnits.every(function(unit){ return !!storage.assocUnstableUnits[unit]; })){
		var arrProps = [];
		arrUnits.forEach(function(unit){
			if (storage.assocBestChildren[unit])
				arrProps = arrProps.concat(storage.assocBestChildren[unit]);
		});
		return handleResult(arrProps);
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

**File:** network.js (L1271-1283)
```javascript
					if (conf.bDryRunNewTriggers && !conf.bLight && !objJoint.ball && objValidationState.count_primary_aa_triggers) {
						const outputAddresses = objJoint.unit.messages
							.filter(msg => msg.app === 'payment')
							.reduce((acc, msg) => acc.concat(msg.payload.outputs.map(output => output.address)), []);
						const rows = await db.query("SELECT address, definition FROM aa_addresses WHERE address IN (?)", [outputAddresses]);
						for (let { address, definition } of rows) {
							console.log(`dry run trigger for AA address ${address} in submitted unit ${unit}`);
							const trigger = aa_composer.getTrigger(objJoint.unit, address);
							// if it would crash, let it crash now, not when we execute the trigger for real
							await aa_composer.dryRunPrimaryAATrigger(trigger, address, JSON.parse(definition));
						}
					}
					writer.saveJoint(objJoint, objValidationState, null, function(){
```

**File:** aa_composer.js (L272-306)
```javascript
function dryRunPrimaryAATrigger(trigger, address, arrDefinition, onDone) {
	if (!onDone)
		return new Promise(resolve => dryRunPrimaryAATrigger(trigger, address, arrDefinition, resolve));
	console.log('dry run', address, trigger);
	db.takeConnectionFromPool(function (conn) {
		conn.query("BEGIN", function () {
			var batch = conf.bLight ? lightBatch : kvstore.batch();
			readLastStableMcUnit(conn, function (mci, objMcUnit) {
				trigger.unit = constants.GENESIS_UNIT; // objMcUnit.unit; // might cause duplicate trigger_unit in aa_triggers if objMcUnit is already a real trigger
				if (!trigger.address)
					trigger.address = objMcUnit.authors[0].address;
				trigger.initial_address = trigger.address;
				trigger.initial_unit = trigger.unit;
				var fPrepare = function (cb) {
					insertFakeOutputsIntoMcUnit(conn, objMcUnit, trigger.outputs, address, cb);
				};
				fPrepare(function () {
					var arrResponses = [];
					handleTrigger({
						bDryRun: true, // suppress events for a unit that will be rolled back
						conn, batch, trigger, params: {}, stateVars: {}, arrDefinition, address, mci, objMcUnit, bSecondary: false, arrResponses,
						onDone: function () {
							revertResponsesInCaches(arrResponses);
							batch.clear();
							conn.query("ROLLBACK", function () {
								conn.release();
								onDone(arrResponses);
							});
						},
					});
				});
			});
		});
	});
}
```

**File:** aa_composer.js (L1900-1916)
```javascript
function revertResponsesInCaches(arrResponses) {
	// remove the rolled back units from caches and correct is_free of their parents if necessary
	console.log('will revert responses ' + JSON.stringify(arrResponses, null, '\t'));
	var arrResponseUnits = [];
	arrResponses.forEach(function (objAAResponse) {
		if (objAAResponse.response_unit)
			arrResponseUnits.push(objAAResponse.response_unit);
	});
	console.log('will revert response units ' + arrResponseUnits.join(', '));
	if (arrResponseUnits.length > 0) {
		var first_unit = arrResponseUnits[0];
		var objFirstUnit = storage.assocUnstableUnits[first_unit];
		var parent_units = objFirstUnit.parent_units;
		arrResponseUnits.forEach(storage.forgetUnit);
		storage.fixIsFreeAfterForgettingUnit(parent_units);
	}
}
```
