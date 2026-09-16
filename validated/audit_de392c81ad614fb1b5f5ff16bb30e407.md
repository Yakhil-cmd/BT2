### Title
Unlocked `light/dry_run_aa` Request Races Real AA Trigger Execution, Corrupting Shared In-Memory Unit/State Caches - (File: network.js, aa_composer.js)

### Summary
The `light/dry_run_aa` network command lets any connected peer (light client, not necessarily authenticated or privileged) trigger a full AA execution simulation via `aa_composer.dryRunPrimaryAATrigger`. Unlike the real AA-trigger execution path, which is always serialized behind the `mutex.lock(['aa_triggers'], ...)` lock in `handleAATriggers`, the dry-run path takes **no lock at all** before mutating the same shared, process-global JS caches (`storage.assocStableUnits`, `storage.assocUnstableUnits`, cached MC-unit objects) that the real trigger-processing pipeline concurrently reads and writes. This is structurally the same bug class as CVE-2026-33009: an externally-reachable command handler mutates shared mutable context without the lock/mutex that protects the same context elsewhere in the codebase.

### Finding Description
`handleAATriggers` explicitly acquires the `'aa_triggers'` mutex before calling `handlePrimaryAATrigger`, which then reads and mutates the shared unit-props cache in place: [1](#0-0) [2](#0-1) 

This same execution engine, `handleTrigger`, is invoked by `dryRunPrimaryAATrigger` — but this function takes **no mutex lock** at all, only a DB transaction that is rolled back at the end: [3](#0-2) 

`dryRunPrimaryAATrigger` is directly reachable from the network layer by any connected peer sending a `light/dry_run_aa` request — no lock is taken in the network handler either, in contrast to sibling handlers such as `light/get_link_proofs`, which explicitly serialize themselves with `mutex.lock(['get_link_proofs_request'], ...)`: [4](#0-3) [5](#0-4) 

Inside `handleTrigger`, execution mutates process-wide caches that are **not** protected by the SQL transaction/ROLLBACK boundary used for the dry run: `revertResponsesInCaches` calls `storage.forgetUnit` and `storage.fixIsFreeAfterForgettingUnit` directly on the shared in-memory unit-cache objects: [6](#0-5) 

If a real AA trigger is being processed by `handleAATriggers` (holding the `'aa_triggers'` mutex, but that mutex is irrelevant to a concurrent dry run) at the same moment a peer's `light/dry_run_aa` request executes `handleTrigger` → `revertResponsesInCaches` → `storage.forgetUnit`/`fixIsFreeAfterForgettingUnit`, both code paths concurrently read/write the same `storage.assocStableUnits`/`assocUnstableUnits` entries and the `is_free` flags of parent units, with zero coordination. This is a direct JS analog of the EVerest bug: two independently-triggered code paths (one externally, unprivileged-message-triggered) mutate `Charger::shared_context`-equivalent global state without any lock.

### Impact Explanation
Node.js callback interleaving means these operations are not truly "concurrent" at the instruction level, but they are unserialized with respect to each other across asynchronous I/O boundaries (DB queries, kvstore batches). A dry run interleaved with a real trigger can:
- Corrupt `storage.assocStableUnits[unit].count_aa_responses` bookkeeping or the `is_free` flags maintained by `fixIsFreeAfterForgettingUnit`, which are used elsewhere to decide unit selection/inclusion — leading to nodes disagreeing on which units are free/stable, i.e., **node disagreement on validity or stability**.
- Trigger the `throw Error` at `handlePrimaryAATrigger: unit ${unit} not found in cache` (aa_composer.js:106) if a concurrent dry run's cache-forgetting operation removes an entry the real trigger handler expects to still be present. An uncaught `throw` inside an async callback in this codebase is not wrapped in a domain/try-catch and crashes the Node.js process — a **remote, unauthenticated DoS** triggerable by any peer that can open a light connection and send `light/dry_run_aa`, satisfying the CVSS profile (AV:N/AC:L/PR:N/UI:N, integrity/availability impact) of the referenced CVE.

### Likelihood Explanation
`light/dry_run_aa` requires only an established peer connection sending `{command: 'light/dry_run_aa', params: {trigger, address}}` — no proof-of-work, no authentication, and no rate limiting is visible in the handler itself. Because full nodes routinely process stabilizing AA triggers on every new stable MC unit (a frequent, continuous background activity via `writer.js`'s `handleAATriggers()` calls after stabilization), the window for interleaving with an attacker-issued dry run is not narrow — it recurs on every stabilization event that touches AA units. This makes the race practically triggerable by an attacker who simply floods `light/dry_run_aa` requests against an AA address that is also being actively triggered.

### Recommendation
Serialize `dryRunPrimaryAATrigger` (and `estimatePrimaryAATrigger`) behind the same `'aa_triggers'` mutex key used by `handleAATriggers`/`handlePrimaryAATrigger`, or introduce a dedicated read/estimate lock that is mutually exclusive with real trigger execution before any code path is allowed to call `handleTrigger`/`revertResponsesInCaches`/`storage.forgetUnit`. Additionally, ensure any `throw Error` reachable from externally-triggerable async paths is converted into a graceful error response rather than an uncaught process-crashing exception.

### Proof of Concept
1. Deploy an AA and cause continuous unit stabilization on it so that `handleAATriggers` is regularly invoked on the full node.
2. As a peer, repeatedly send `light/dry_run_aa` requests (network.js:3939) against the same AA address while real triggers are stabilizing, so `dryRunPrimaryAATrigger`'s `handleTrigger`/`revertResponsesInCaches` executes concurrently with `handlePrimaryAATrigger`'s cache mutation of `storage.assocStableUnits[unit]`.
3. Observe either (a) inconsistent `is_free`/cache state across peers leading to validity/stability disagreement, or (b) the uncaught `throw Error("handlePrimaryAATrigger: unit ${unit} not found in cache")` crashing the node process — a full node DoS from a single unauthenticated light-client message, mirroring the unlocked `Charger::shared_context` corruption in CVE-2026-33009.

### Citations

**File:** aa_composer.js (L59-63)
```javascript
function handleAATriggers(onDone) {
	if (!onDone)
		return new Promise(resolve => handleAATriggers(resolve));
	mutex.lock(['aa_triggers'], function (unlock) {
		db.query(
```

**File:** aa_composer.js (L102-109)
```javascript
						conn.query("DELETE FROM aa_triggers WHERE mci=? AND unit=? AND address=?", [mci, unit, address], async function(){
							await conn.query("UPDATE units SET count_aa_responses=IFNULL(count_aa_responses, 0)+? WHERE unit=?", [arrResponses.length, unit]);
							let objUnitProps = storage.assocStableUnits[unit];
							if (!objUnitProps)
								throw Error(`handlePrimaryAATrigger: unit ${unit} not found in cache`);
							if (!objUnitProps.count_aa_responses)
								objUnitProps.count_aa_responses = 0;
							objUnitProps.count_aa_responses += arrResponses.length;
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

**File:** aa_composer.js (L1900-1915)
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
```

**File:** network.js (L3686-3699)
```javascript
		case 'light/get_link_proofs':
			mutex.lock(['get_link_proofs_request'], function(unlock){
				if (!ws || ws.readyState !== ws.OPEN) // may be already gone when we receive the lock
					return process.nextTick(unlock);
				light.prepareLinkProofs(params, {
					ifError: function(err){
						sendErrorResponse(ws, tag, err);
						unlock();
					},
					ifOk: function(objResponse){
						sendResponse(ws, tag, objResponse);
						unlock();
					}
				});
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
