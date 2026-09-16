### Title
Use-after-free-style cache corruption from unlocked AA dry-run trigger execution - ([File: aa_composer.js])

### Summary
`aa_composer.dryRunPrimaryAATrigger()` executes a full, real `handleTrigger()`/`validateAndSaveUnit()`/`writer.saveJoint()` pass against the live, process-wide in-memory caches (`storage.assocUnstableUnits`, `assocBestChildren`, `assocStableUnitsByMci`, etc.) and then "reverts" that state via `revertResponsesInCaches()` → `storage.forgetUnit()`, all **without holding the global `["write"]` mutex** that normally serializes every real unit/AA-trigger write against these same shared caches.

### Finding Description
`dryRunPrimaryAATrigger` is invoked from at least two unprivileged, network-reachable code paths:
- `network.js` `light/dry_run_aa` request handler, reachable by any light-client peer with arbitrary `params.trigger`/`params.address`. [1](#0-0) 
- the `bDryRunNewTriggers` path inside `handleJoint`'s `ifOk` callback, triggered whenever any unit with an output to an AA is posted by any peer. [2](#0-1) 

Inside `dryRunPrimaryAATrigger`, a connection is pulled from the pool and a transaction is opened, but no `mutex.lock(["write"])` is taken: [3](#0-2) 

`handleTrigger` → `validateAndSaveUnit` calls the *real* `validation.validate` and `writer.saveJoint`, which mutate the shared, module-level caches (`storage.assocUnstableUnits`, `assocBestChildren`, `assocStableUnitsByMci`, `is_free` flags, etc.) exactly as a genuine unit would: [4](#0-3) 

After the trigger finishes, `revertResponsesInCaches()` deletes the fabricated response units from `assocUnstableUnits` via `storage.forgetUnit` and then recomputes `is_free` on the *parent* units taken from whichever unit happened to be `arrResponseUnits[0]` at that moment: [5](#0-4) 

Because none of `takeConnectionFromPool`, `handleTrigger`, or `revertResponsesInCaches` acquire the `"write"` mutex, this whole read‑modify‑delete cycle on the global caches is **not serialized against concurrent real processing** — e.g. `handleAATriggers()` (which does take `mutex.lock(['aa_triggers'])`, a different lock) or `handleJoint`'s own `ifOk` writer path (which takes `"write"`) can run interleaved with a dry run on another connection/tick of the event loop. A concurrent dry run can therefore:
- insert transient objects into `assocUnstableUnits`/`assocBestChildren` that a real, concurrently-running `main_chain` stability/MC computation reads and treats as real DAG state, then
- have those objects deleted (`storage.forgetUnit`) out from under the real computation mid-flight, or have `fixIsFreeAfterForgettingUnit` flip `is_free` on units that a concurrent real path is simultaneously relying on to still be non-free/stable-pending, corrupting the in-memory cache state that all nodes are supposed to keep consistent with the DB.

This is the JS-level analog of the CVE's use-after-free class: an object (`objUnit`/`objAAResponse` entries) is created and shared into a global structure, then freed/removed via `forgetUnit` while another concurrent execution path may still hold a live reference to it or rely on the structure's prior state, producing corrupted/stale in-memory state rather than a crash (JS has GC, so there is no literal dangling pointer, but the effect is the same class of bug: use of an object/cache entry after another code path has invalidated it, driven by improper locking).

### Impact Explanation
If the temporary/fake cache mutations performed by an attacker-triggerable dry run (via `light/dry_run_aa`, reachable by any light client, or via `bDryRunNewTriggers` triggered by posting any unit with an AA-address output) race with genuine unit/AA-trigger processing, the shared in-memory caches (`assocUnstableUnits`, `assocBestChildren`, `is_free`, `assocStableUnitsByMci`) can end up diverging from the database's actual state. Since main-chain stability determination and AA-trigger execution rely directly on these caches, this can cause the affected node to disagree with the rest of the network on unit validity/stability, or corrupt its own view of AA balances/state variables used for subsequent real triggers — leading to double-processing or incorrect balance/asset accounting for AAs (a form of fund loss/freezing or double-spend risk at the node level).

### Likelihood Explanation
The `light/dry_run_aa` command is directly reachable by any connected light-client peer with no authentication, and the `bDryRunNewTriggers` path fires automatically for ordinary posted units with AA outputs — both are unprivileged, everyday interactions. Triggering the race requires timing (a concurrent real AA trigger or joint-write happening on the same node while the dry run's unlocked cache window is open), which is a plausible but not guaranteed condition on a busy node; the underlying missing-lock condition itself, however, is unconditionally present in the code.

### Recommendation
Wrap `dryRunPrimaryAATrigger`'s cache-mutating sequence (`handleTrigger` → `validateAndSaveUnit`/`writer.saveJoint` → `revertResponsesInCaches`) in the same `mutex.lock(["write"])` used by the real unit-processing path in `network.js`'s `handleJoint`, so dry runs and real writes to `storage.assocUnstableUnits`/`assocBestChildren`/etc. are mutually exclusive. Alternatively, make dry-run trigger execution operate on a fully isolated/cloned cache snapshot instead of the live, shared module-level caches, so `forgetUnit`/`fixIsFreeAfterForgettingUnit` cannot affect state visible to concurrent real processing.

### Proof of Concept
Conceptual PoC (requires timing control, hence "concurrency race", not a deterministic single-request PoC):
1. Attacker A (a light client) sends a `light/dry_run_aa` request with a trigger to an existing AA address, causing the target full node to run `aa_composer.dryRunPrimaryAATrigger` without the `"write"` lock, populating `storage.assocUnstableUnits`/`assocBestChildren` with fabricated response-unit entries.
2. Concurrently, a legitimate unit B posted by any peer (or the node's own `handleAATriggers` cycle) reads `storage.assocUnstableUnits`/`assocBestChildren`/`is_free` while the fabricated entries from step 1 are still present, basing MC/stability computations on this transient state.
3. The dry run completes and calls `revertResponsesInCaches`, deleting the fabricated units and recomputing `is_free` on their parents based on the state observed at that time — potentially conflicting with mutations made by step 2's concurrent processing, leaving `assocUnstableUnits`/`is_free` in a state inconsistent with the database.
4. Subsequent stability/AA-trigger computations on this node use the corrupted cache, causing divergence from peers that process the same units serially.

### Citations

**File:** network.js (L1271-1281)
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
```

**File:** network.js (L3939-3961)
```javascript
		case 'light/dry_run_aa':
			if (!params)
				return sendErrorResponse(ws, tag, "no params in light/dry_run_aa");
			if (!ValidationUtils.isValidAddress(params.address))
				return sendErrorResponse(ws, tag, "address not valid");
		
			storage.readAADefinition(db, params.address, null, function (arrDefinition) {
				if (!arrDefinition)
					return sendErrorResponse(ws, tag, "not an AA");
				aa_composer.validateAATriggerObject(params.trigger, function(error){
					if (error)
						return sendErrorResponse(ws, tag, error);
					aa_composer.dryRunPrimaryAATrigger(params.trigger, params.address, arrDefinition, function (arrResponses) {
						if (constants.COUNT_WITNESSES === 1) { // the temp unit might have rebuilt the MC
							db.executeInTransaction(function (conn, onDone) {
								storage.resetMemory(conn, onDone);
							});
						}
						if (ws.library_version === '0.4.2' && arrResponses.length === 1 && arrResponses[0].bounced && typeof arrResponses[0].response.error === 'object')
							arrResponses[0].response.error = arrResponses[0].response.error.message;
						sendResponse(ws, tag, arrResponses);
					});
				})
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

**File:** aa_composer.js (L1800-1837)
```javascript
	function validateAndSaveUnit(objUnit, cb) {
		var objJoint = { unit: objUnit, aa: true, aa_mci: mci };
		validation.validate(objJoint, {
			ifJointError: function (err) {
				throw Error("AA validation joint error: " + err);
			},
			ifUnitError: function (err) {
				console.log("AA validation unit error: " + err);
				return cb(err);
			},
			ifTransientError: function (err) {
				throw Error("AA validation transient error: " + err);
			},
			ifNeedHashTree: function () {
				throw Error("AA validation unexpected need hash tree");
			},
			ifNeedParentUnits: function (arrMissingUnits) {
				throw Error("AA validation unexpected dependencies: " + arrMissingUnits.join(", "));
			},
			ifOkUnsigned: function () {
				throw Error("AA validation returned ok unsigned");
			},
			ifOk: function (objAAValidationState, validation_unlock) {
				if (objAAValidationState.sequence !== 'good')
					throw Error("nonserial AA");
				validation_unlock();
				objAAValidationState.bUnderWriteLock = true;
				objAAValidationState.conn = conn;
				objAAValidationState.batch = batch;
				objAAValidationState.initial_trigger_mci = mci;
				objAAValidationState.bDryRun = trigger_opts.bDryRun;
				writer.saveJoint(objJoint, objAAValidationState, null, function(err){
					if (err)
						throw Error('AA writer returned error: ' + err);
					cb();
				});
			}
		}, conn);
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
