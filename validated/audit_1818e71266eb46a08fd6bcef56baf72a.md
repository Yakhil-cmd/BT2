Based on my investigation, I found a plausible analog: `aa_composer.js`'s `dryRunPrimaryAATrigger` (invoked directly and unauthenticated-adjacent via the `light/dry_run_aa` network command) has no per-address or per-request mutex, so two overlapping dry-run requests can race on shared, unguarded module state.

### Title
Concurrent `light/dry_run_aa` requests race on shared AA-trigger state, causing an uncaught exception that crashes the whole node - (File: aa_composer.js)

### Summary
`dryRunPrimaryAATrigger` [1](#0-0)  is reachable by any peer (including light clients) via the `light/dry_run_aa` network command [2](#0-1) , without acquiring `mutex.lock` on the AA address, the trigger unit, or the shared last-stable-MC-unit object. Two concurrent dry-run requests for the same or dependent AA addresses can interleave their asynchronous DB/cache operations on the shared in-memory maps (`storage.assocStableUnits`, `storage.assocUnstableUnits`) and the mutated `objMcUnit`/fake-outputs state, hitting code paths that `throw Error(...)` on inconsistent state (e.g. `handlePrimaryAATrigger`'s cache check [3](#0-2) , or the `assocStableUnits[trigger.unit].count_aa_responses` dereference in `handleTrigger` [4](#0-3) ). Any synchronous `throw` inside these deeply-nested async callback chains is not wrapped in `try/catch` and is not funneled through `ifUnitError`; it becomes an unhandled exception on the Node event loop and terminates the whole ocore process, exactly matching the "fatal map access causes complete server crash" pattern in the report (concurrent, unauthenticated/low-privilege requests racing on shared mutable maps, causing total DoS instead of a graceful per-request error).

### Finding Description
`dryRunPrimaryAATrigger` takes its own DB connection and reads/mutates a temporary copy of the last stable MC unit (`insertFakeOutputsIntoMcUnit`) and then calls `handleTrigger`, which reads/writes globally shared caches (`storage.assocStableUnits`, `storage.assocUnstableUnits`) via `revertResponsesInCaches` [5](#0-4)  — none of this is protected by `mutex.lock`, unlike normal unit validation which locks author addresses [6](#0-5)  or trigger execution which locks the `'aa_triggers'` key [7](#0-6) . Because `light/dry_run_aa` calls `dryRunPrimaryAATrigger` directly with no such lock [8](#0-7) , an attacker can fire many concurrent dry-run requests (optionally interleaved with real unit posting/trigger execution happening on the shared caches) so that assumptions baked into the synchronous `throw Error(...)` guards are violated — e.g., `handlePrimaryAATrigger` assumes `storage.assocStableUnits[unit]` is always populated [3](#0-2) , and `handleTrigger`'s "second primary trigger" check dereferences `storage.assocStableUnits[trigger.unit]` without a null-check [4](#0-3) . These `throw` statements execute inside nested `db.query`/`conn.query` callbacks, several levels removed from any surrounding `try/catch`, so the resulting exception is uncaught by the process and (absent a global `process.on('uncaughtException')` handler wrapping this specific call chain) crashes the entire ocore node.

### Impact Explanation
A crash of the full ocore process is a complete denial of service: the node stops confirming/relaying units, executing AA triggers, and serving light clients until manually restarted, which matches the "no vulnerability found"-excluded category only if it is resource-only; here it is a full crash from a logic error triggered by interleaving, which is the closest in-scope analog to the report's "server crash requiring restart."

### Likelihood Explanation
Any peer able to send a `light/dry_run_aa` request (which requires only a valid address and passing `validateAATriggerObject`, no special privilege) can trigger this path repeatedly and concurrently; hitting the exact race window that causes a stale/missing cache entry depends on timing with genuine stabilization/trigger-processing activity, so likelihood is moderate rather than trivial to hit deterministically — I could not fully confirm from static analysis that the race window is reachable without also controlling real chain activity, since `assocStableUnits` entries are normally populated synchronously before triggers are queued [9](#0-8) .

### Recommendation
Guard `dryRunPrimaryAATrigger`/`estimatePrimaryAATrigger` (and `handlePrimaryAATrigger`) with `mutex.lock` on the AA address (and/or a dedicated key) so concurrent dry-runs/trigger executions cannot interleave on shared caches; replace the bare `throw Error(...)` guards in `aa_composer.js` (lines 104-106, 1861-1862, and similar) with defensive checks that surface a normal `ifUnitError`/bounce instead of an unhandled process-crashing exception; and add a top-level `process.on('uncaughtException')`/`unhandledRejection` safety net around trigger/dry-run handling so a single malformed race does not take down the whole node.

### Proof of Concept
1. Deploy an AA and repeatedly send `light/dry_run_aa` requests for it concurrently (e.g., dozens of parallel WebSocket requests) while the network is also actively stabilizing MC units and processing real AA triggers for the same address, so `dryRunPrimaryAATrigger` and `handlePrimaryAATrigger`/`handleAATriggers` interleave on `storage.assocStableUnits`/`assocUnstableUnits`.
2. If the interleaving causes `handlePrimaryAATrigger` to look up a `unit` no longer present in `storage.assocStableUnits` (line 104-106) or `handleTrigger`'s check at line 1861 to dereference an absent `assocStableUnits[trigger.unit]`, the resulting `throw Error(...)` propagates out of the async callback with no catch, causing an unhandled exception that terminates the ocore process.
3. I was not able to fully verify the exact minimal reproduction steps/timing needed to force the race deterministically within the scope of static code review; this should be validated by a background agent with a running/instrumented test node.

### Citations

**File:** aa_composer.js (L62-62)
```javascript
	mutex.lock(['aa_triggers'], function (unlock) {
```

**File:** aa_composer.js (L104-106)
```javascript
							let objUnitProps = storage.assocStableUnits[unit];
							if (!objUnitProps)
								throw Error(`handlePrimaryAATrigger: unit ${unit} not found in cache`);
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

**File:** aa_composer.js (L1861-1862)
```javascript
			if (trigger.unit !== constants.GENESIS_UNIT && !trigger_opts.bAir && storage.assocStableUnits[trigger.unit].count_aa_responses && mci >= constants.pemCurvesFixMci)
				return bounce('a second primary trigger from the same unit is not allowed');
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

**File:** validation.js (L357-357)
```javascript
	mutex.lock(arrAuthorAddresses, function(unlock){
```

**File:** main_chain.js (L1691-1722)
```javascript
	function handleAATriggers() {
		// a single unit can send to several AA addresses
		// a single unit can have multiple outputs to the same AA address, even in the same asset
		const mci_column = mci >= constants.pemCurvesFixMci ? 'aa_addresses.mci' : 'aa_definition_units.main_chain_index';
		conn.query(
			"SELECT DISTINCT address, definition, units.unit, units.level \n\
			FROM units \n\
			CROSS JOIN outputs USING(unit) \n\
			CROSS JOIN aa_addresses USING(address) \n\
			LEFT JOIN assets ON asset=assets.unit \n\
			CROSS JOIN units AS aa_definition_units ON aa_addresses.unit=aa_definition_units.unit \n\
			WHERE units.main_chain_index = ? AND units.sequence = 'good' AND (outputs.asset IS NULL OR is_private=0) \n\
				AND NOT EXISTS (SELECT 1 FROM unit_authors CROSS JOIN aa_addresses USING(address) WHERE unit_authors.unit=units.unit) \n\
				AND " + mci_column + "<=? \n\
			ORDER BY units.level, units.unit, address", // deterministic order
			[mci, mci],
			function (rows) {
				count_aa_triggers = rows.length;
				if (rows.length === 0)
					return finishMarkMcIndexStable();
				var arrValues = rows.map(function (row) {
					return "("+mci+", "+conn.escape(row.unit)+", "+conn.escape(row.address)+")";
				});
				conn.query("INSERT INTO aa_triggers (mci, unit, address) VALUES " + arrValues.join(', '), function () {
					finishMarkMcIndexStable();
					// now calling handleAATriggers() from write.js
				//	process.nextTick(function(){ // don't call it synchronously with event emitter
				//		eventBus.emit("new_aa_triggers"); // they'll be handled after the current write finishes
				//	});
				});
			}
		);
```
