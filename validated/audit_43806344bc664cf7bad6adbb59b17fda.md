### Title
Missing `aa_triggers` mutex lock in `dryRunPrimaryAATrigger` allows concurrent corruption of shared AA state/balance caches - (File: aa_composer.js)

### Summary
`aa_composer.js` serializes all *real* AA trigger executions behind `mutex.lock(['aa_triggers'], …)` in `handleAATriggers()`/`handlePrimaryAATrigger()` [1](#0-0)  because `handleTrigger()` reads and mutates process-wide, shared in-memory caches (`storage.assocUnstableUnits`, `storage.assocStableUnits`, `storage.assocUnstableMessages`, `storage.assocBestChildren`, `storage.assocStableUnitsByMci`, and AA state-var objects with `.value/.old_value/.updated` flags). However, `dryRunPrimaryAATrigger()`, which runs the exact same `handleTrigger()` logic against those same shared caches, never acquires the `aa_triggers` (or `write`) mutex before running [2](#0-1) .

### Finding Description
`dryRunPrimaryAATrigger` opens its own DB connection/transaction and calls `handleTrigger({ bDryRun: true, conn, batch, trigger, stateVars: {}, arrDefinition, address, mci, objMcUnit, arrResponses, onDone })`, then rolls back the transaction and calls `revertResponsesInCaches(arrResponses)` to undo in-memory side effects [2](#0-1) . The accompanying unit tests explicitly assert that after a dry run, `storage.assocUnstableUnits`, `storage.assocStableUnits`, `storage.assocUnstableMessages`, `storage.assocBestChildren` and `storage.assocStableUnitsByMci` must be restored to their pre-run snapshot [3](#0-2) , confirming that `handleTrigger()` actively mutates these *shared, global, non-connection-scoped* caches during execution and relies on a best-effort revert afterward rather than true isolation.

This function is reachable by two unprivileged, unauthenticated paths:
1. `network.js` `'light/dry_run_aa'` request handler — any connected peer (including light clients) can submit an arbitrary `address` + `trigger` and trigger a full dry run with zero locking [4](#0-3) .
2. The `conf.bDryRunNewTriggers` path inside `handleJoint`’s `ifOk` callback, invoked for every newly posted unit that outputs to an AA address, again with no lock, and running concurrently with (and even before) the actual `writer.saveJoint()`/`['write']`-locked commit path [5](#0-4) .

Because Node.js is single-threaded but `handleTrigger()` contains many `await`/callback yield points (DB reads for balances, state vars, remote AA calls, etc.), two or more of these unlocked dry-run executions — or a dry run interleaved with a real, `aa_triggers`-locked execution — can interleave their reads/writes to the same shared cache objects. This is analogous to the Janus race: a shared, mutable "session"-like structure (here, the in-memory AA state/balance caches) is claimed and mutated by multiple concurrent code paths without the mutex the codebase itself designed for exactly this purpose (`['aa_triggers']`), because one specific caller (`dryRunPrimaryAATrigger`) opts out of it.

### Impact Explanation
An interleaved dry run can leave stale or corrupted values in the shared state-var/balance caches used by the *real* AA trigger executor after a partial or mis-timed revert, or can read a snapshot mid-mutation from a concurrently running real trigger. Since these caches directly drive computed AA state variables and balances that get written into the database by the real trigger path, corruption here can lead to incorrect AA state/balance being persisted (AA fund loss or freezing), or divergent in-memory state between nodes/processes handling triggers at different times, leading to disagreement on AA outcomes across implementations.

### Likelihood Explanation
The `'light/dry_run_aa'` command is reachable by any peer without authentication and can be invoked repeatedly and rapidly for any deployed AA, and `conf.bDryRunNewTriggers` fires automatically for ordinary AA-directed unit submissions. Triggering concurrent overlapping dry runs (or a dry run concurrent with a real trigger firing from a newly stabilized MCI) only requires normal network timing, not any privileged access, making the race condition realistically triggerable by a single attacker sending closely-timed requests.

### Recommendation
Serialize `dryRunPrimaryAATrigger` (and the `light/dry_run_aa` handler) behind the same `mutex.lock(['aa_triggers'])` used by `handleAATriggers()`/`handlePrimaryAATrigger()`, or refactor `handleTrigger()` so dry runs operate exclusively on deep-cloned, request-local copies of the shared caches instead of mutating the global `storage.assoc*` structures directly and relying on a post-hoc revert.

### Proof of Concept
Not able to fully construct a deterministic reproduction without runtime access; the analysis is based on static code paths: `dryRunPrimaryAATrigger` lacks the `mutex.lock(['aa_triggers'])` present in `handleAATriggers`/`handlePrimaryAATrigger`, and is reachable unauthenticated via `'light/dry_run_aa'` and automatically via `conf.bDryRunNewTriggers` on unit submission, both of which run `handleTrigger()` against the same shared in-memory caches that the locked path was designed to protect. Full confirmation of exact shared-object aliasing inside `storage.js`'s state-var cache implementation could not be completed within the available search budget, so this should be validated further (e.g., with a live two-concurrent-dry-run test against the same AA address) before treating it as fully confirmed.

### Citations

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

**File:** test/aa_composer.test.js (L271-283)
```javascript
	aa_composer.dryRunPrimaryAATrigger(trigger, address, aa, (arrResponses) => {
		t.deepEqual(arrResponses.length, 1);
		t.deepEqual(arrResponses[0].bounced, false);
		t.deepEqual(arrResponses[0].updatedStateVars[address].count.delta, 1);
		t.deepEqual(arrResponses[0].updatedStateVars[address].unit.value, false);
		fixCache();
		t.deepEqual(storage.assocUnstableUnits, old_cache.assocUnstableUnits);
		t.deepEqual(storage.assocStableUnits, old_cache.assocStableUnits);
		t.deepEqual(storage.assocUnstableMessages, old_cache.assocUnstableMessages);
		t.deepEqual(storage.assocBestChildren, old_cache.assocBestChildren);
		t.deepEqual(storage.assocStableUnitsByMci, old_cache.assocStableUnitsByMci);
		t.end();
	});
```

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
