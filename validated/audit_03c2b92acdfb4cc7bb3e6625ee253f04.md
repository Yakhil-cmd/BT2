## Title
Concurrent dry-run AA trigger execution races with real unit writes on shared in-memory caches without holding the `write` lock - (File: `aa_composer.js`)

### Summary
`aa_composer.dryRunPrimaryAATrigger()` (and `estimatePrimaryAATrigger()`) execute an AA trigger and internally call `writer.saveJoint()` to persist the temporary response unit, then roll back the DB transaction and manually "undo" the effect on process-wide in-memory caches via `revertResponsesInCaches()`. Unlike the real trigger-execution path (`handleAATriggers`, serialized under the `mutex.lock(['aa_triggers'])` key) or ordinary unit validation/write (`network.js` `handleJoint` → `writer.saveJoint`, serialized under `mutex.lock(['write'])`), the dry-run path never takes the `write` (or any) mutex before mutating `storage.assocUnstableUnits`, `storage.assocBestChildren`, and `storage.assocUnstableMessages`. This mirrors the root cause of CVE-2022-48941: two logically distinct "teardown"/"setup" style operations (here: dry-run trigger simulate+rollback vs. real unit commit) touch the same shared mutable state without a common lock, allowing them to race and corrupt shared state.

### Finding Description
`writer.saveJoint()` protects its mutation of the process-wide unit caches with the `write` mutex key, unless the caller explicitly opts out via `objValidationState.bUnderWriteLock = true`: [1](#0-0) 

The AA composer's `validateAndSaveUnit()` (used by both the real trigger path and dry runs) always sets `bUnderWriteLock = true`, which makes `writer.saveJoint()` skip acquiring the `write` lock entirely: [2](#0-1) 

For the *real* AA-trigger path, this is safe because the whole batch of primary triggers is already serialized by `mutex.lock(['aa_triggers'])` in `handleAATriggers()`: [3](#0-2) 

However, `dryRunPrimaryAATrigger()` (used for the network-exposed `light/dry_run_aa` request) and `estimatePrimaryAATrigger()` invoke `handleTrigger()`/`validateAndSaveUnit()` directly, on their own DB connection, **without acquiring either the `aa_triggers` or `write` mutex key**: [4](#0-3) 

While `writer.saveJoint()` runs (unlocked, because `bUnderWriteLock` is set) it still unconditionally mutates the shared, process-global caches used by every unit write and by main-chain/stability computation, regardless of `bDryRun`: [5](#0-4) 

After the dry run's DB transaction is rolled back, `dryRunPrimaryAATrigger` tries to manually reverse this cache mutation: [6](#0-5) 

Because a normal, real unit being validated by any peer goes through `network.js`'s `handleJoint`/`writer.saveJoint`, which *does* take the `write` lock: [7](#0-6) 

and this real path reads and pushes into the very same `storage.assocBestChildren[my_best_parent_unit]` and `storage.assocUnstableUnits` structures that the unlocked dry-run path is simultaneously writing to and then deleting from, the two code paths can interleave arbitrarily: the dry run can insert a temporary fake unit keyed by `constants.GENESIS_UNIT` into `assocUnstableUnits`/`assocBestChildren` at the exact moment the locked writer is iterating/pushing to the same parent's children array, or `revertResponsesInCaches`'s `storage.forgetUnit` can run concurrently with the locked writer's read of `assocUnstableUnits[my_best_parent_unit]`, `assocBestChildren`, or `assocUnstableMessages`, silently corrupting these shared JS objects (lost pushes, use of stale/deleted parent entries, or thrown exceptions from `objFirstUnit.parent_units` being undefined if the entry was already reused/removed).

### Impact Explanation
`storage.assocUnstableUnits` / `assocBestChildren` / `assocUnstableMessages` back main-chain determination, best-parent selection, witnessed-level computation, and stability advancement (`main_chain.updateMainChain`, `determineIfStableInLaterUnitsAndUpdateStableMcFlag`). Corruption of these caches from an unsynchronized concurrent dry run can cause a node to compute an incorrect main chain / stability point relative to its peers, i.e., node disagreement on unit validity or stability, or crash the process (unhandled exception thrown from the corrupted cache state), which for network-critical full nodes constitutes a denial of confirmation service. This is reachable by any unauthenticated peer that connects to the node and issues a `light/dry_run_aa` request, requiring no privileges.

### Likelihood Explanation
The `light/dry_run_aa` request is served to any connected peer without authentication: [8](#0-7) 

A peer can trigger the vulnerable dry-run path essentially at will by repeatedly sending `light/dry_run_aa` requests targeting any AA address, and simply needs this to coincide in time with ordinary, continuously occurring unit writes/AA trigger executions on the target node (which happen constantly on any node processing network traffic). No special timing precision beyond "send while the node is busy validating/writing units" is required, making the race practically triggerable.

### Recommendation
Serialize `dryRunPrimaryAATrigger()` and `estimatePrimaryAATrigger()` against real unit writes and AA trigger execution by having them acquire the same `write` (and/or `aa_triggers`) mutex key used by `writer.saveJoint()` and `handleAATriggers()` before mutating any shared caches, or by ensuring dry-run execution never touches the shared global caches at all (e.g., work on cloned/scratch data structures rather than `storage.assocUnstableUnits`/`assocBestChildren`/`assocUnstableMessages` directly, only merging into the real caches under lock when not a dry run).

### Proof of Concept
1. Start a full node and let it continuously receive/process units from peers (normal operation, unit writes going through `network.js handleJoint → writer.saveJoint`, protected by `mutex.lock(['write'])`).
2. As an unauthenticated peer, repeatedly send `light/dry_run_aa` requests (see `network.js` case `'light/dry_run_aa'`) for any existing AA address with a synthetic trigger.
3. `aa_composer.dryRunPrimaryAATrigger` runs `handleTrigger`→`validateAndSaveUnit`→`writer.saveJoint` on its own connection with `bUnderWriteLock=true`, mutating `storage.assocUnstableUnits`/`assocBestChildren`/`assocUnstableMessages`, then rolls back and calls `revertResponsesInCaches` to delete the temporary entries — none of this is protected by the `write` lock.
4. Because real unit processing concurrently reads/writes the same structures under the `write` lock, interleaving the two produces inconsistent cache state (e.g., `assocBestChildren` losing a legitimately pushed child, or `revertResponsesInCaches` removing an entry that a concurrently-running real write is still relying on), which can be observed as thrown exceptions (`objFirstUnit.parent_units` undefined) or as divergent main-chain/stability computations between nodes subjected to different interleavings.

### Citations

**File:** writer.js (L24-35)
```javascript
async function saveJoint(objJoint, objValidationState, preCommitCallback, onDone) {
	var objUnit = objJoint.unit;
	console.log("\nsaving unit "+objUnit.unit);
	var arrQueries = [];
	var commit_fn;
	if (objValidationState.conn && !objValidationState.batch)
		throw Error("conn but not batch");
	var bInLargerTx = (objValidationState.conn && objValidationState.batch);
	const bCommonOpList = objValidationState.last_ball_mci >= constants.v4UpgradeMci;

	const unlock = objValidationState.bUnderWriteLock ? () => { } : await mutex.lock(["write"]);
	console.log("got lock to write " + objUnit.unit);
```

**File:** writer.js (L590-613)
```javascript
			var batch = bCordova ? null : (bInLargerTx ? objValidationState.batch : kvstore.batch());
			if (bGenesis){
				storage.assocStableUnits[objUnit.unit] = objNewUnitProps;
				storage.assocStableUnitsByMci[0] = [objNewUnitProps];
				console.log('storage.assocStableUnitsByMci', storage.assocStableUnitsByMci)
			}
			else
				storage.assocUnstableUnits[objUnit.unit] = objNewUnitProps;
			if (!bGenesis && storage.assocUnstableUnits[my_best_parent_unit]) {
				if (!storage.assocBestChildren[my_best_parent_unit])
					storage.assocBestChildren[my_best_parent_unit] = [];
				storage.assocBestChildren[my_best_parent_unit].push(objNewUnitProps);
			}
			if (objUnit.messages) {
				objUnit.messages.forEach(function(message) {
					if (['data_feed', 'definition', 'system_vote', 'system_vote_count'].includes(message.app)) {
						if (!storage.assocUnstableMessages[objUnit.unit])
							storage.assocUnstableMessages[objUnit.unit] = [];
						storage.assocUnstableMessages[objUnit.unit].push(message);
						if (message.app === 'system_vote' && !objValidationState.bDryRun)
							eventBus.emit('system_var_vote', message.payload.subject, message.payload.value, arrAuthorAddresses, objUnit.unit, 0);
					}
				});
			}
```

**File:** aa_composer.js (L59-89)
```javascript
function handleAATriggers(onDone) {
	if (!onDone)
		return new Promise(resolve => handleAATriggers(resolve));
	mutex.lock(['aa_triggers'], function (unlock) {
		db.query(
			"SELECT aa_triggers.mci, aa_triggers.unit, address, definition \n\
			FROM aa_triggers \n\
			CROSS JOIN units USING(unit) \n\
			CROSS JOIN aa_addresses USING(address) \n\
			ORDER BY aa_triggers.mci, level, aa_triggers.unit, address",
			function (rows) {
				var arrPostedUnits = [];
				async.eachSeries(
					rows,
					function (row, cb) {
						console.log('handleAATriggers', row.unit, row.mci, row.address);
						var arrDefinition = JSON.parse(row.definition);
						handlePrimaryAATrigger(row.mci, row.unit, row.address, arrDefinition, arrPostedUnits, cb);
					},
					function () {
						arrPostedUnits.forEach(function (objUnit) {
							eventBus.emit('new_aa_unit', objUnit);
						});
						unlock();
						onDone();
					}
				);
			}
		);
	});
}
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

**File:** aa_composer.js (L1822-1837)
```javascript
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

**File:** network.js (L3939-3963)
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
			});
			break;
```
