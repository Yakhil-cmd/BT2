### Title
Race condition / shared-cache corruption from unlocked AA dry-run writes — ([File: aa_composer.js])

### Summary
`dryRunPrimaryAATrigger` executes a full, real AA-trigger simulation — including actual DB writes and in-memory cache mutations via `writer.saveJoint` — without ever acquiring the process-wide `"write"` mutex that protects the same shared in-memory structures (`storage.assocUnstableUnits`, `storage.assocBestChildren`, main-chain indexing state) everywhere else in the codebase. This mirrors the root cause of CVE-2023-2162: an object/structure is created and mutated on one path while a concurrently-running, differently-synchronized path (or the object's own premature "free"/rollback) can read or reuse the same structure in an inconsistent state.

### Finding Description
`dryRunPrimaryAATrigger` takes a DB connection and begins a transaction, but never calls `mutex.lock(["write"])`: [1](#0-0) 

It then calls `handleTrigger`, which — for a template/non-base-AA — eventually calls `validateAndSaveUnit`. That function's `ifOk` handler unconditionally forces `bUnderWriteLock = true` before invoking `writer.saveJoint`, regardless of whether the caller actually holds the write lock: [2](#0-1) 

`writer.saveJoint` trusts this flag and skips acquiring the `"write"` mutex whenever `bUnderWriteLock` is set: [3](#0-2) 

Yet `saveJoint`, once inside, freely mutates the same global caches that are normally serialized by that mutex — e.g. registering the new unit in `storage.assocUnstableUnits` and pushing into `storage.assocBestChildren`: [4](#0-3) 
and marking parent units' `is_free` flag in place: [5](#0-4) 

It further triggers `main_chain.updateMainChain`, which walks and mutates `storage.assocUnstableUnits[...]` (`main_chain_index`, `is_on_main_chain`, `latest_included_mc_index`) in place, assuming exclusive access: [6](#0-5) [7](#0-6) 

All real, chain-affecting unit processing (`handleAATriggers` → `handlePrimaryAATrigger`, and normal joint validation/writing) is expected to run under the `"write"` mutex; `dryRunPrimaryAATrigger` is the one path that manufactures real DB rows and cache entries for these same structures while holding no such lock, then "cleans up" only via a best-effort, ad hoc reversal: [8](#0-7) 
and `storage.forgetUnit`, which itself assumes the deleted unit's cache entry is intact and consistent (`assocUnstableUnits[unit].parent_units`) when un-registering it from `assocBestChildren`: [9](#0-8) 

If a real unit save (holding the `"write"` lock) interleaves with a dry run's unlocked mutation of the very same maps (e.g., both touch `assocBestChildren[parent_unit]`, or main-chain recomputation walks `assocUnstableUnits` while dry-run entries are being added/removed), the shared JS objects can be observed or mutated in a torn, half-updated state — structurally the same defect class as the kernel UAF: an object registered/mutated by one flow is concurrently accessed by another flow that assumes exclusive ownership, because the locking discipline was bypassed.

### Impact Explanation
Corruption of `assocUnstableUnits` / `assocBestChildren` / main-chain-index bookkeeping can cause a node to compute an incorrect best-parent, level, or main-chain index for a genuinely posted unit, or to leave inconsistent `is_free`/`is_on_main_chain` flags. This can lead nodes to disagree on unit validity or stability determination, and — because AA balance/state computation in `handleTrigger`/`updateMainChain` depends on this same cache being coherent — can also cause an AA's computed balances or trigger ordering to diverge from the correct, single-writer-serialized outcome, risking AA fund loss/incorrect fund movement. Both outcomes fall within the accepted impact categories (node disagreement on validity/stability; AA fund loss).

### Likelihood Explanation
`dryRunPrimaryAATrigger` is designed to be invoked with attacker-controlled `trigger` data (arbitrary `data`/`outputs`) against any existing AA address, with no requirement that the trigger correspond to a real posted unit — this is the standard "preview an AA call" surface reachable by any unprivileged caller who can request a dry run. Because it performs a full write-path execution (`validateAndSaveUnit` → `writer.saveJoint`, later rolled back) but never takes the `"write"` mutex, any concurrently arriving real unit (which does take the lock) creates the race window described above. Note: I could not fully trace, within the tool budget, whether the *real* `handleAATriggers()` call path (invoked from `writer.js:727` during stabilization) is itself nested inside the outer `saveJoint`'s `"write"` lock scope before that lock is released — that detail should be double-checked by whoever verifies/fixes this, since it affects the width of the race window for that specific path. The dry-run path's total lack of any write-lock acquisition, however, is unambiguous from the code shown above.

### Recommendation
Have `dryRunPrimaryAATrigger` (and any other caller of `handleTrigger`/`validateAndSaveUnit` that is not already executing under `writer.saveJoint`'s own write-lock acquisition) explicitly acquire `mutex.lock(["write"])` for the duration of the simulated execution and rollback, the same way real unit processing does, instead of relying on the `bUnderWriteLock` flag being force-set inside `validateAndSaveUnit`. Alternatively, make `bUnderWriteLock` reflect whether the lock is actually held by the calling context rather than being unconditionally set to `true`.

### Proof of Concept
1. Node A has a running instance of ocore processing real incoming joints (each acquiring `mutex.lock(["write"])` via `writer.saveJoint`).
2. An attacker (or any user with a light wallet) repeatedly calls the dry-run AA endpoint against a busy AA address (`aa_composer.dryRunPrimaryAATrigger(trigger, address, arrDefinition, cb)`), supplying attacker-chosen `trigger.data`/`trigger.outputs`.
3. Because `dryRunPrimaryAATrigger` never calls `mutex.lock(["write"])` (see `aa_composer.js:272-306`) but still runs `writer.saveJoint` with `bUnderWriteLock=true` (see `aa_composer.js:1822-1836`, `writer.js:24-35`), its cache mutations (`writer.js:595-602`, `main_chain.js:150-163`, `main_chain.js:1296-1307`) interleave, unsynchronized, with a concurrently write-locked real unit save touching the same `storage.assocUnstableUnits`/`assocBestChildren` entries.
4. Repeating this under load increases the probability of observing/mutating a torn cache entry (e.g., a `parent_unit`'s `assocBestChildren` array missing an expected child, or a `main_chain_index` computed from a partially updated `assocUnstableUnits` set), which can propagate into main-chain stabilization and AA state computation for real units — reproducible as intermittent `assocUnstableUnits`/`assocBestChildren` inconsistency assertions already present as sanity `throw Error(...)` checks elsewhere in `storage.js`/`main_chain.js` (e.g. `storage.js:1547-1550`), confirming the code's own author expected these structures to be exclusively guarded.

### Citations

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

**File:** aa_composer.js (L1822-1836)
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

**File:** writer.js (L119-127)
```javascript
			conn.addQuery(arrQueries, "UPDATE units SET is_free=0 WHERE unit IN(?)", [objUnit.parent_units], function(result){
				// in sqlite3, result.affectedRows actually returns the number of _matched_ rows
				var count_consumed_free_units = result.affectedRows;
				console.log(count_consumed_free_units+" free units consumed");
				objUnit.parent_units.forEach(function(parent_unit){
					if (storage.assocUnstableUnits[parent_unit])
						storage.assocUnstableUnits[parent_unit].is_free = 0;
				})
			});
```

**File:** writer.js (L595-602)
```javascript
			}
			else
				storage.assocUnstableUnits[objUnit.unit] = objNewUnitProps;
			if (!bGenesis && storage.assocUnstableUnits[my_best_parent_unit]) {
				if (!storage.assocBestChildren[my_best_parent_unit])
					storage.assocBestChildren[my_best_parent_unit] = [];
				storage.assocBestChildren[my_best_parent_unit].push(objNewUnitProps);
			}
```

**File:** main_chain.js (L150-163)
```javascript
	function goDownAndUpdateMainChainIndex(last_main_chain_index, last_main_chain_unit){
		profiler.start();
		conn.query(
			//"UPDATE units SET is_on_main_chain=0, main_chain_index=NULL WHERE is_on_main_chain=1 AND main_chain_index>?", 
			"UPDATE units SET is_on_main_chain=0, main_chain_index=NULL WHERE main_chain_index>?", 
			[last_main_chain_index], 
			function(){
				for (var unit in storage.assocUnstableUnits){
					var o = storage.assocUnstableUnits[unit];
					if (o.main_chain_index > last_main_chain_index){
						o.is_on_main_chain = 0;
						o.main_chain_index = null;
					}
				}
```

**File:** main_chain.js (L1296-1307)
```javascript
	for (var unit in storage.assocUnstableUnits){
		var o = storage.assocUnstableUnits[unit];
		if (o.main_chain_index === mci && o.is_stable === 0){
			o.is_stable = 1;
			storage.assocStableUnits[unit] = o;
			storage.assocStableUnitsByMci[mci].push(o);
			arrStabilizedUnits.push(unit);
		}
	}
	arrStabilizedUnits.forEach(function(unit){
		delete storage.assocUnstableUnits[unit];
	});
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
