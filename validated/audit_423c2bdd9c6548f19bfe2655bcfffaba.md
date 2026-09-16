### Title
Unit properties cache published with unfinalized `level`/`witnessed_level` before DB writes complete, allowing consensus-relevant reads of stale data - ([File: writer.js])

### Summary
`writer.js`'s `saveJoint()` builds `objNewUnitProps` with `level` and `witnessed_level` deliberately left `null` for non-genesis units [1](#0-0)  and immediately publishes this incomplete object into the shared, globally-read caches `storage.assocUnstableUnits` / `storage.assocStableUnits` [2](#0-1) , *before* the SQL queries that assign the unit's real `level` and `witnessed_level` (`updateLevel`, `updateWitnessedLevel`) have executed [3](#0-2) [4](#0-3) . This is the same bug class as CVE-2026-45862: a reference to a not-yet-fully-populated structure is made visible to other consumers before its backing content is committed.

### Finding Description
`saveJoint()` constructs `objNewUnitProps` with `level: bGenesis ? 0 : null` and, unless `conf.bFaster`, `witnessed_level: null` [1](#0-0) . It then synchronously assigns this half-built object into the process-wide caches read by every other concurrently-running validation:

- `storage.assocUnstableUnits[objUnit.unit] = objNewUnitProps;` (non-genesis) [2](#0-1) 

Only afterward does the code run `arrQueries` (the base INSERT/UPDATE batch) and then the `arrOps` pipeline that fills in the real values: `updateBestParent`, `updateLevel`, and `updateWitnessedLevel`, each of which mutates `objNewUnitProps.level` / `.witnessed_level` only after its own `UPDATE units SET level=...` / `witnessed_level=...` query returns [5](#0-4) [6](#0-5) .

Meanwhile, `storage.readUnitProps()` — used pervasively throughout validation and main-chain code — will, when `conf.bFaster` is enabled, short-circuit straight to the in-memory cache without touching the DB: `if (conf.bFaster && assocUnstableUnits[unit]) return handleProps(assocUnstableUnits[unit]);` [7](#0-6) . Consumers such as `determineBestParent()`'s OP tie-breaker (`level_diff: props.level - props.witnessed_level`) [8](#0-7) , `updateWitnessedLevelByWitnesslist()` [9](#0-8) , and main-chain stability routines (`readPropsOfUnits`, `determineIfStableInLaterUnits`) all rely on `level`/`witnessed_level` being correct integers, not `null`.

Because `saveJoint()` for a given unit only holds the `["write"]` mutex for its own writer path, but `validation.validate()` for a *different* incoming unit does not require that same lock and can run interleaved on the Node.js event loop, another unit's validation that references the just-being-written unit as a parent (a completely normal, unprivileged scenario — any node can legitimately receive two units in flight where one is a fresh parent of another) can call `readUnitProps`/`readStaticUnitProps` and observe `level: null` or `witnessed_level: null` while the true values are still being computed and committed. This is structurally identical to the kernel bug: a pointer/reference to a structure (`objNewUnitProps`) is published to a globally-visible location before the structure's content is fully written, creating a window where consumers observe stale/incomplete data.

### Impact Explanation
`level` and `witnessed_level` feed directly into best-parent selection, witnessed-level propagation, and main-chain stability determination (`determineBestParent`, `updateWitnessedLevelByWitnesslist`, `determineIfStableInLaterUnits`). If a concurrently-running validation path observes `null` in place of the real value during the race window, arithmetic such as `level - witnessed_level` produces `NaN`, and comparisons involving `null` can silently resolve incorrectly (e.g. `null < X` behaves inconsistently for ordering-sensitive tie-breaks). This can cause two nodes — or the same node handling units in a different relative order — to compute different best parents or different stability points for the same DAG state, i.e. node disagreement on validity/stability, which is one of the explicitly accepted impacts of this class of bug. It does not require a malicious peer or hub: it can be triggered purely by ordinary concurrent unit arrival that any unprivileged poster's units can participate in.

### Likelihood Explanation
The window is real but narrow: it exists only between the cache-publish line [2](#0-1)  and the completion of `updateLevel`/`updateWitnessedLevel` [10](#0-9) , and only affects readers that hit the fast in-memory path (`conf.bFaster`) or otherwise read `assocUnstableUnits` directly rather than re-querying the DB. Triggering it deterministically requires carefully timed concurrent unit submission so that a second unit's validation/level computation walks through the still-being-written parent during this exact interval — feasible for a determined unprivileged actor controlling submission timing of multiple units, but not trivially "always on."

### Recommendation
Do not publish `objNewUnitProps` into `storage.assocUnstableUnits`/`assocStableUnits` until all its consensus-relevant fields (`level`, `witnessed_level`, `best_parent_unit`) have been finalized, or gate any cache reads that occur before that point so they fall back to the DB rather than returning a partially-initialized object. At minimum, `readUnitProps`'s `conf.bFaster` fast path should verify `level !== null && witnessed_level !== null` before trusting the cached entry.

### Proof of Concept
Not independently reproducible from static analysis alone — exploitation depends on precise interleaving of two units' validation/writing on the event loop, which requires runtime timing control not verifiable through code inspection. The described race window and the responsible code paths are cited above; a background Devin session with the full repo/test harness would be needed to construct and time a reliable concurrent-submission PoC (e.g. rapidly posting a unit and a child unit referencing it as parent while `conf.bFaster` is enabled) and confirm whether the resulting `level`/`witnessed_level` mismatch actually propagates into a divergent best-parent or stability decision.

### Citations

**File:** writer.js (L451-516)
```javascript
		function determineMaxLevel(handleMaxLevel){
			var max_level = 0;
			async.each(
				objUnit.parent_units, 
				function(parent_unit, cb){
					storage.readStaticUnitProps(conn, parent_unit, function(props){
						if (props.level > max_level)
							max_level = props.level;
						cb();
					});
				},
				function(){
					handleMaxLevel(max_level);
				}
			);
		}
		
		function updateLevel(cb){
			if (bGenesis)
				return cb();
			conn.cquery("SELECT MAX(level) AS max_level FROM units WHERE unit IN(?)", [objUnit.parent_units], function(rows){
				if (!conf.bFaster && rows.length !== 1)
					throw Error("not a single max level?");
				determineMaxLevel(function(max_level){
					if (conf.bFaster)
						rows = [{max_level: max_level}]
					if (max_level !== rows[0].max_level)
						throwError("different max level, sql: "+rows[0].max_level+", props: "+max_level);
					objNewUnitProps.level = max_level + 1;
					conn.query("UPDATE units SET level=? WHERE unit=?", [rows[0].max_level + 1, objUnit.unit], function(){
						cb();
					});
				});
			});
		}
		
		
		function updateWitnessedLevel(cb){
			if (bGenesis)
				return cb();
			profiler.start();
			if (bCommonOpList)
				updateWitnessedLevelByWitnesslist(storage.getOpList(objValidationState.last_ball_mci), cb);
			else if (objUnit.witnesses)
				updateWitnessedLevelByWitnesslist(objUnit.witnesses, cb);
			else
				storage.readWitnessList(conn, objUnit.witness_list_unit, function(arrWitnesses){
					updateWitnessedLevelByWitnesslist(arrWitnesses, cb);
				});
		}
		
		// The level at which we collect at least 7 distinct witnesses while walking up the main chain from our unit.
		// The unit itself is not counted even if it is authored by a witness
		function updateWitnessedLevelByWitnesslist(arrWitnesses, cb){
			var arrCollectedWitnesses = [];
			var count = 0;
			
			function setWitnessedLevel(witnessed_level){
				profiler.start();
				if (witnessed_level !== objValidationState.witnessed_level)
					throwError("different witnessed levels, validation: "+objValidationState.witnessed_level+", writer: "+witnessed_level);
				objNewUnitProps.witnessed_level = witnessed_level;
				conn.query("UPDATE units SET witnessed_level=? WHERE unit=?", [witnessed_level, objUnit.unit], function(){
					profiler.stop('write-wl-update');
					cb();
				});
```

**File:** writer.js (L519-534)
```javascript
			function addWitnessesAndGoUp(start_unit){
				count++;
				if (count % 100 === 0)
					return setImmediate(addWitnessesAndGoUp, start_unit);
				profiler.start();
				storage.readStaticUnitProps(conn, start_unit, function(props){
					profiler.stop('write-wl-select-bp');
					var best_parent_unit = props.best_parent_unit;
					var level = props.level;
					if (level === null)
						throw Error("null level in updateWitnessedLevel");
					if (level === 0) // genesis
						return setWitnessedLevel(0);
					profiler.start();
					storage.readUnitAuthors(conn, start_unit, function(arrAuthors){
						profiler.stop('write-wl-select-authors');
```

**File:** writer.js (L562-568)
```javascript
			level: bGenesis ? 0 : null,
			latest_included_mc_index: null,
			main_chain_index: bGenesis ? 0 : null,
			is_on_main_chain: bGenesis ? 1 : 0,
			is_free: 1,
			is_stable: bGenesis ? 1 : 0,
			witnessed_level: bGenesis ? 0 : (conf.bFaster ? objValidationState.witnessed_level : null),
```

**File:** writer.js (L591-597)
```javascript
			if (bGenesis){
				storage.assocStableUnits[objUnit.unit] = objNewUnitProps;
				storage.assocStableUnitsByMci[0] = [objNewUnitProps];
				console.log('storage.assocStableUnitsByMci', storage.assocStableUnitsByMci)
			}
			else
				storage.assocUnstableUnits[objUnit.unit] = objNewUnitProps;
```

**File:** writer.js (L614-654)
```javascript
			addInlinePaymentQueries(function(){
				async.series(arrQueries, function(){
					profiler.stop('write-raw');
					var arrOps = [];
					if (1 || objUnit.parent_units){ // genesis too
						if (!conf.bLight){
							if (objValidationState.bAA) {
								if (!objValidationState.initial_trigger_mci)
									throw Error("no initial_trigger_mci");
								var arrAADefinitionPayloads = objUnit.messages.filter(function (message) { return (message.app === 'definition'); }).map(function (message) { return message.payload; });
								if (arrAADefinitionPayloads.length > 0) {
									arrOps.push(function (cb) {
										console.log("inserting new AAs defined by an AA after adding " + objUnit.unit);
										storage.insertAADefinitions(conn, arrAADefinitionPayloads, objUnit.unit, objValidationState.initial_trigger_mci, objValidationState.initial_trigger_mci, true, cb, objValidationState.bDryRun);
									});
								}
							}
							if (!conf.bFaster)
								arrOps.push(updateBestParent);
							arrOps.push(updateLevel);
							if (!conf.bFaster)
								arrOps.push(updateWitnessedLevel);
							// will throw just after the upgrade
						//	if (!objValidationState.last_ball_timestamp && objValidationState.last_ball_mci >= constants.timestampUpgradeMci && !bGenesis)
						//		throw Error("no last_ball_timestamp");
							if (objValidationState.bHasSystemVoteCount && objValidationState.sequence === 'good') {
								const m = objUnit.messages.find(m => m.app === 'system_vote_count');
								if (!m)
									throw Error(`system_vote_count message not found`);
								if (m.payload === 'op_list')
									arrOps.push(cb => main_chain.applyEmergencyOpListChange(conn, objUnit.timestamp, cb));
							}
							arrOps.push(function(cb){
								console.log("updating MC after adding "+objUnit.unit);
								main_chain.updateMainChain(conn, batch, null, objUnit.unit, objValidationState.bAA, (_arrStabilizedMcis, _bStabilizedAATriggers) => {
									arrStabilizedMcis = _arrStabilizedMcis;
									bStabilizedAATriggers = _bStabilizedAATriggers;
									cb();
								});
							});
						}
```

**File:** storage.js (L1497-1505)
```javascript
function readUnitProps(conn, unit, handleProps){
	if (!unit)
		throw Error(`readUnitProps bad unit ` + unit);
	if (!handleProps)
		return new Promise(resolve => readUnitProps(conn, unit, resolve));
	if (assocStableUnits[unit])
		return handleProps(assocStableUnits[unit]);
	if (conf.bFaster && assocUnstableUnits[unit])
		return handleProps(assocUnstableUnits[unit]);
```

**File:** storage.js (L2055-2072)
```javascript
	if (bTieBreakerPrefersOP) {
		let arrParentProps = [];
		async.eachSeries(
			objUnit.parent_units,
			function (parent_unit, cb) {
				if (isGenesisUnit(parent_unit)) { // for AA dry-run in tests
					arrParentProps.push({ unit: parent_unit, witnessed_level: 0, level_diff: 0, isOP: true });
					return cb();
				}
				readUnitProps(conn, parent_unit, function (props) {
					arrParentProps.push({
						unit: parent_unit,
						witnessed_level: props.witnessed_level,
						level_diff: props.level - props.witnessed_level,
						isOP: _.intersection(props.author_addresses, arrWitnesses).length > 0,
					});
					cb();
				});
```
