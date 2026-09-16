Based on my investigation, I found a concrete analog of the Algernon race-condition bug class in `dryRunPrimaryAATrigger`, which is reachable by any unprivileged light-client peer via the `light/dry_run_aa` network command, and which mutates process-wide shared caches (`storage.assocUnstableUnits`, `assocStableUnits`, `assocUnstableMessages`, `assocBestChildren`, `assocStableUnitsByMci`, and the module-level `lightBatch`) without any mutex serializing concurrent invocations.

### Title
Unsynchronized concurrent AA dry-runs corrupt shared in-memory DAG caches - (File: aa_composer.js)

### Summary
`dryRunPrimaryAATrigger()` (`aa_composer.js:272-306`), invoked from the unauthenticated `light/dry_run_aa` network handler (`network.js:3939-3963`), executes a full AA trigger simulation against a temporary/fake unit and mutates shared, process-global mutable state (`storage.assocUnstableUnits`, `assocStableUnits`, `assocBestChildren`, `assocStableUnitsByMci`, `assocUnstableMessages`, and, in light mode, the shared `lightBatch`) without acquiring any of the `mutex.js` locks that protect the rest of the write/validation pipeline (`'write'`, `'handleJoint'`, `'aa_triggers'`). Every other code path that touches these same caches (`writer.js` `saveJoint`, `aa_composer.js` `handleAATriggers`/`handlePrimaryAATrigger`, `main_chain.js` `stabilizeMci`) is guarded by `mutex.lock(["write"])` or `mutex.lock(['aa_triggers'])`. `dryRunPrimaryAATrigger` is not.

### Finding Description
The Algernon CVE describes a shared, non-thread-safe VM state (`gopher-lua`'s `LState`) that is mutated by concurrent handler goroutines because the mutex guarding it is released before the code that actually uses the shared state executes. The root cause generalizes to: *a shared, mutable, unsynchronized execution context can be entered from two logically-concurrent request handlers, so one handler's temporary/speculative mutations bleed into or corrupt the state seen by the other.*

In ocore, this maps onto `dryRunPrimaryAATrigger`:
- It is reachable directly by any connected light-client peer sending `light/dry_run_aa` — no authentication, no rate limiting beyond the generic anti-spam layer, and crucially, no `mutex.lock(["write"])`/`mutex.lock(['aa_triggers'])` wrapping at all (compare to `handleAATriggers` at `aa_composer.js:59-89`, which always takes `mutex.lock(['aa_triggers'])`, and `writer.saveJoint` at `writer.js:34`, which always takes `mutex.lock(["write"])`).
- Inside, it calls `insertFakeOutputsIntoMcUnit` and `handleTrigger` with `bDryRun: true`, which execute the AA's oscript/ojson logic against `storage.readLastStableMcUnit`'s cached MC unit and then call `revertResponsesInCaches(arrResponses)` to "undo" mutations to `storage.assocUnstableUnits` / `assocStableUnits` / `assocBestChildren` / `assocStableUnitsByMci` afterward.
- Because there is no lock, nothing prevents a second concurrent `light/dry_run_aa` request (or a real incoming unit being validated/written via `writer.saveJoint`, which *does* hold the write lock but reads/writes the very same `storage.assoc*` caches) from interleaving with the first dry run's temporary cache mutations. Two overlapping dry-runs (or a dry-run interleaved with a real stabilization) can read each other's half-applied fake unit state, and `revertResponsesInCaches` for one dry run can revert cache entries that the concurrently-running second dry run (or worse, a real trigger execution) depends on, leaving `storage.assocUnstableUnits`/`assocStableUnits` permanently inconsistent with the DB after both complete — analogous to VM corruption from two overlapping executions against one shared context.
- The test suite (`test/aa_composer.test.js`) explicitly asserts, after every single dry run, that `storage.assocUnstableUnits`, `assocStableUnits`, `assocUnstableMessages`, `assocBestChildren`, and `assocStableUnitsByMci` are restored to their pre-dry-run snapshot — confirming these are exactly the shared mutable caches at risk, and that the code's correctness assumption is strictly single-threaded/serialized execution of `dryRunPrimaryAATrigger`, an assumption the network handler does not enforce for concurrent peer requests. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) 

### Impact Explanation
If two `light/dry_run_aa` requests for AAs that touch overlapping DAG state (or a dry-run interleaved with a genuine trigger execution driven by `handleAATriggers`, which is unlocked with respect to `dryRunPrimaryAATrigger`) run concurrently, the shared caches `storage.assocUnstableUnits`/`assocStableUnits`/`assocBestChildren`/`assocStableUnitsByMci` can end up corrupted (stale, partially reverted, or containing the wrong fake unit's data). Since main-chain stability determination, AA trigger selection, and balance/state-var evaluation in real (non-dry-run) unit validation and AA execution (`main_chain.js`, `storage.js`, `aa_composer.js` real-trigger path) all read these same caches, corruption here can propagate into real consensus-relevant computations — potentially causing a node to disagree with peers about validity/stability of units, or to compute wrong AA balances/state, i.e., AA fund loss or freezing.

### Likelihood Explanation
`light/dry_run_aa` is served by every full node to any connected light-wallet peer without special privilege, and JS's event loop interleaves I/O-bound callbacks (DB queries, `kvstore` operations) freely, so two dry-run requests for AAs sharing dependent state (e.g., calling each other, or both referencing the same "unit[...]" lookups against `storage.assocUnstableUnits`) can genuinely interleave their DB/cache callbacks. This requires no privileged access — only sending oscript-triggering messages to a public network handler — matching the "modest concurrency, immediately reproducible" profile of the original Algernon finding.

### Recommendation
Serialize `dryRunPrimaryAATrigger` (and by extension the `light/dry_run_aa` handler) with the same `mutex.lock(['aa_triggers'])` / `mutex.lock(["write"])` discipline used by `handleAATriggers` and `writer.saveJoint`, so that no two dry runs — and no dry run and a real trigger/validation/write — can concurrently mutate `storage.assoc*` caches. Alternatively, make dry-run execution operate over a deep-cloned, isolated snapshot of the relevant caches instead of the live shared caches, eliminating the need for `revertResponsesInCaches` to restore global state after the fact.

### Proof of Concept
1. Deploy two AAs, `A` and `B`, where `A`'s oscript reads `unit[response_unit]`/state vars that were most recently written by a prior dry run's temporary fake unit (as exercised by `test/aa_composer.test.js`'s "chain of AAs" test, `aa_composer.js:272-306`).
2. From a light-client connection, concurrently fire two `light/dry_run_aa` requests — one for `A`, one for `B` — such that the first request's `insertFakeOutputsIntoMcUnit`/`handleTrigger` mutation of `storage.assocUnstableUnits`/`assocStableUnits` (inside `dryRunPrimaryAATrigger`, before `revertResponsesInCaches` runs) is observed mid-flight by the second request's `handleTrigger` evaluation, before the first request's `revertResponsesInCaches`/`ROLLBACK` executes.
3. Observe that the second dry run's `arrResponses` (balances/state vars) reflect the first dry run's not-yet-reverted fake unit, and/or that after both complete, `storage.assocUnstableUnits`/`assocStableUnits` no longer match the pre-dry-run snapshot (violating the invariant explicitly checked by `test/aa_composer.test.js` after every single dry run) — demonstrating cache corruption from the lack of synchronization around the shared, non-reentrant execution context.

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
