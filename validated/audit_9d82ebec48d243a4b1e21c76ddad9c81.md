### Title
Use-after-free-style race condition on shared unit caches during concurrent AA trigger dry-runs - (File: `aa_composer.js`)

### Summary
`network.js` triggers `aa_composer.dryRunPrimaryAATrigger()` **without any mutex/lock** for every freshly validated, not-yet-saved unit that targets an AA address, whenever `conf.bDryRunNewTriggers` is enabled [1](#0-0) . This dry run mutates process-global, non-transactional in-memory caches in `storage.js` (`assocUnstableUnits`, `assocBestChildren`, `assocKnownUnits`, `assocCachedUnits`, …) while composing candidate AA response units, and only cleans them up at the very end via `revertResponsesInCaches()` [2](#0-1) , which calls `storage.forgetUnit()` to delete the cache entries and splice the forgotten unit's object out of its parents' `assocBestChildren` arrays by reference identity [3](#0-2) .

Because this whole flow spans multiple asynchronous DB round-trips (`pickParents()`, `updateInitialAABalances()`, `sendUnit()`, etc.) and is not serialized against other concurrent dry runs, an attacker who posts two or more units carrying AA triggers in quick succession can cause two `handleTrigger()`/`dryRunPrimaryAATrigger()` executions to interleave over the same shared caches. One execution can delete (`forgetUnit`) or otherwise mutate a cache object (e.g., `assocUnstableUnits[parent_unit]`, `assocBestChildren[parent_unit]`) that a second, still in-flight execution has already captured a reference to and will dereference later (e.g., `objFirstUnit.parent_units` in `revertResponsesInCaches`) [4](#0-3) . This is functionally analogous to the Samba SMB1 use-after-free: a shared, reference-counted-by-convention in-memory object is freed by one handler while another concurrent handler still holds and dereferences it.

### Finding Description
- `dryRunPrimaryAATrigger()` takes a DB connection and begins a SQL transaction, but never acquires any `mutex.lock()` (unlike other trigger/write paths in the codebase that serialize on `'write'` or `'handleJoint'`) [5](#0-4) .
- `network.js`'s `handleJoint` `ifOk` handler calls this unlocked dry run directly and `await`s it inline in the per-unit validation success path, for every unit whose payment outputs go to a known AA address [1](#0-0) . Any unprivileged peer can post such a unit; no special role is required.
- During the dry run, `handleTrigger()` composes and "saves" candidate response units, which (per the need for `revertResponsesInCaches`/`forgetUnit` to undo them) get inserted into the shared, global `storage.js` caches (`assocUnstableUnits`, `assocBestChildren`), the same caches used by the real, authoritative unit-validation/stabilization pipeline (`validateParents`, `main_chain.js` stability determination, etc.).
- At the end of the dry run, `revertResponsesInCaches()` reads `storage.assocUnstableUnits[first_unit]` to get `parent_units`, then calls `storage.forgetUnit()` for every generated response unit, and finally calls `storage.fixIsFreeAfterForgettingUnit(parent_units)` [2](#0-1) .
- `storage.forgetUnit()` mutates `assocBestChildren[parent_unit]` using `_.pull(assocBestChildren[parent_unit], assocUnstableUnits[unit])` — an operation that depends on the referenced object still existing and being the exact same object recorded earlier — then unconditionally deletes the unit from every cache (`assocKnownUnits`, `assocCachedUnits`, `assocUnstableUnits`, `assocStableUnits`, `assocUnstableMessages`, `assocBestChildren`) [3](#0-2) .
- Because none of this is guarded by a lock, a second concurrent dry run (or the real primary-trigger execution path) touching the same MC-adjacent parent units can race with the first: it can `forgetUnit()` a shared parent/child object, or otherwise rewrite `assocBestChildren`, while the first flow still holds now-stale references (e.g., `arrPrevParentUnitProps` captured in `validateParents`-style parent walking inside `handleTrigger`'s own `pickParents()` at aa_composer.js:875-907, or the `objFirstUnit` captured at aa_composer.js:1911). A subsequent dereference of the stale/deleted object is the "use-after-free."

### Impact Explanation
Corruption of `assocBestChildren`/`assocUnstableUnits` is not just a crash risk — these are the exact in-memory structures used elsewhere to compute `is_free`, best-parent/best-child selection, and eventually main-chain stability (`main_chain.js`, `storage.fixIsFreeAfterForgettingUnit`). If a race causes a live, still-pending unit's parent object to be spliced out of `assocBestChildren` incorrectly, or a still-referenced unit object to be deleted from `assocUnstableUnits` while another code path expects it, the affected node's view of DAG freeness/stability can diverge from honest peers — i.e., **node disagreement on validity/stability**. It can also crash the node process (uncaught `TypeError` on `undefined.parent_units`), which for validator/witness nodes is a denial-of-availability that can stall confirmation of new units on that node until it resyncs.

### Likelihood Explanation
The dry-run call is reachable by any unprivileged peer who posts a unit whose payment output targets an existing AA address (`conf.bDryRunNewTriggers` gate) [1](#0-0) ; no privileged role, hub cooperation, or malicious peer/network assumption is needed — a normal wallet/AA-trigger sender suffices. Triggering the race reliably requires posting multiple AA-triggering units in overlapping time windows so their asynchronous DB round-trips interleave, which is straightforward to script but timing-sensitive, and I could not fully trace every intermediate mutation point (`sendUnit`/`validateAndSaveUnit` internals were not retrieved before the iteration budget ran out), so the precise object(s) exposed to the race are inferred from the existence and behavior of `revertResponsesInCaches`/`forgetUnit` rather than a fully step-through-verified trace.

### Recommendation
Serialize `dryRunPrimaryAATrigger()` (and any other unlocked path that mutates `storage.js`'s shared unit caches) behind the same `mutex.lock(['write'])`/`mutex.lock(['handleJoint'])` discipline used by the real save/stabilization paths, or give dry runs their own deep-cloned/sandboxed cache snapshot instead of mutating the shared global caches in place. At minimum, `revertResponsesInCaches()`/`forgetUnit()` should defensively check that referenced objects still exist before dereferencing (`objFirstUnit && objFirstUnit.parent_units`) and should not delete cache entries that a concurrent in-flight AA execution still depends on.

### Proof of Concept
Not independently executed; based on static analysis only, since the exact interleaving window (which asynchronous callback points in `handleTrigger`'s DB queries realistically allow the Node event loop to service a second concurrent `dryRunPrimaryAATrigger` call for a different unit) was not fully traced due to remaining tool-call budget. A concrete PoC would: (1) post AA-triggering unit A targeting AA address X with a chain of on-MC parents; (2) immediately post AA-triggering unit B targeting AA address Y sharing a nearby MC parent selected by `pickParents()`; (3) observe whether `assocBestChildren`/`assocUnstableUnits` end up missing entries for still-live units or whether the node throws inside `revertResponsesInCaches`/`forgetUnit`, and compare the resulting free/stable unit set against a node that serializes the two triggers.

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
