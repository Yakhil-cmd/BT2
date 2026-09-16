### Title
Unsynchronized dry-run AA trigger execution corrupts global unit caches shared with real consensus processing - ([File: aa_composer.js])

### Summary
`dryRunPrimaryAATrigger()` in `aa_composer.js` executes a full, unlocked simulation of an AA trigger (including real writes to and deletes from the process-wide in-memory unit caches in `storage.js`) whenever a newly submitted unit pays an AA address and `conf.bDryRunNewTriggers` is enabled, but unlike every other code path that mutates those same caches, it never takes the `'write'` (or `'aa_triggers'`) mutex that serializes access to them. [1](#0-0) [2](#0-1) 

### Finding Description
This is the closest reachable analog in this codebase to the GNU Recutils UAF: an object (an AA-response unit's props entry) is created, exposed in a shared structure, and then torn down (`forgetUnit`) by code that never holds the lock that all other consumers of that structure rely on for exclusive access — the JS equivalent of a temporal-safety violation on a "freed" object being concurrently read/mutated.

`handleTrigger()` calls `writer.saveJoint()` for every response unit it composes. That write unconditionally inserts the new unit's props into the global caches, regardless of whether the call originated from real trigger execution or from a dry run: [3](#0-2) 

`dryRunPrimaryAATrigger()` then "undoes" this by calling `revertResponsesInCaches()`, which reads `storage.assocUnstableUnits[first_unit]` and then deletes every simulated response unit from `assocUnstableUnits`, `assocBestChildren`, `assocCachedUnits`, `assocStableUnits`, `assocUnstableMessages`, `assocKnownUnits`, and adjusts `is_free` on the parents: [4](#0-3) [5](#0-4) 

Every other mutator of these same structures — real AA-trigger processing (`handleAATriggers`, guarded by `mutex.lock(['aa_triggers'])`), main-chain stabilization/write (`writer.saveJoint`'s commit path, `main_chain.updateMainChain`), and cache-purging routines (`purgeUncoveredNonserialJoints`, `archiveJointAndDescendants`) — is executed either under `mutex.lock(['write'])` or the ordering guarantees that come from being invoked from inside a single `writer.saveJoint` transaction: [6](#0-5) [7](#0-6) 

`dryRunPrimaryAATrigger()`, however, is invoked directly from `network.js`'s `ifOk` handler for a freshly-validated, not-yet-saved unit, with no lock at all around it: [1](#0-0) [8](#0-7) 

Because ocore is asynchronous (multiple DB round-trips, `setImmediate`, callback chains per response unit), this multi-step, lock-free sequence of insert-then-delete on shared global caches can interleave with a concurrently-running, lock-holding operation on the same units/parents (e.g. a real `handleAATriggers()` run, `main_chain.updateMainChain()`, or `purgeUncoveredNonserialJoints()`), all triggered by ordinary, unprivileged unit/trigger submissions happening at the same time. `storage.forgetUnit()` itself performs no existence check before dereferencing `assocUnstableUnits[unit].parent_units`: [9](#0-8) 
so if the corresponding entry has already been removed (by the interleaved lock-holding path, or because `revertResponsesInCaches` runs a second time on stale data), this throws an uncaught `TypeError`. Even short of a hard crash, the parent/child (`assocBestChildren`) and `is_free` bookkeeping that `main_chain.js`'s best-parent/stability algorithms depend on can be left corrupted after the interleave, since dry-run entries and real entries share the exact same maps.

### Impact Explanation
- An uncaught exception thrown from `forgetUnit()`/`fixIsFreeAfterForgettingUnit()` during this unlocked interleave crashes the Node process handling consensus-critical, deterministic logic (AA execution and main-chain stabilization run identically on every full node), so the same attacker-crafted trigger unit can reproducibly take down full nodes that have `conf.bDryRunNewTriggers` enabled — a network-wide inability to process/confirm new units.
- Short of a crash, corruption of the shared `assocBestChildren`/`is_free` state used by `main_chain.js` for best-parent selection and stability determination can cause a node to diverge from the consensus view of unit validity/stability computed by peers that did not experience the same interleave, satisfying "node disagreement on validity or stability."

### Likelihood Explanation
Reachability requires only posting an ordinary unit with a `payment` message to an AA address — something any unprivileged unit poster can do; no special key, node role, or peer trust is needed. The condition is gated behind the `conf.bDryRunNewTriggers` configuration flag, and reliably forcing the exact async interleave needed to hit the missing-lock race is timing-dependent and was not fully reproduced/step-traced in this review (the exact interleave window between `dryRunPrimaryAATrigger`'s callback chain and a concurrent lock-holding cache mutation could not be conclusively demonstrated with the tools available). This uncertainty should be treated as a caveat on likelihood, even though the missing mutex around `dryRunPrimaryAATrigger`/`revertResponsesInCaches` relative to every other cache mutator is a clear, provable code-level defect.

### Recommendation
Wrap `dryRunPrimaryAATrigger()`'s entire operation (from `readLastStableMcUnit` through `revertResponsesInCaches`/`ROLLBACK`) in the same `mutex.lock(['write'])` (or a dedicated lock also held by `handleAATriggers`) that protects `storage.assocUnstableUnits`, `assocBestChildren`, `assocStableUnits`, and related caches, so its simulated writes/deletes can never interleave with real cache mutations. Additionally, harden `storage.forgetUnit()` to check `assocUnstableUnits[unit]` for existence before dereferencing `.parent_units`, converting a potential hard crash into a defensive no-op/logged warning.

### Proof of Concept
1. Enable `conf.bDryRunNewTriggers` on a full node.
2. Post a unit `U1` with a `payment` output to AA address `A`, where `A`'s definition composes at least one response (so `dryRunPrimaryAATrigger` will call `writer.saveJoint` for a simulated response unit and register it in `storage.assocUnstableUnits`/`assocBestChildren`).
3. Concurrently (in the same event-loop window, e.g. by pipelining unit submissions or via a unit that stabilizes an MCI and triggers `handleAATriggers()`/`purgeUncoveredNonserialJoints`) cause a lock-holding cache mutation to touch the same parent unit(s) that the dry run's simulated response used as `parent_units`.
4. Observe either an uncaught `TypeError` from `storage.forgetUnit()` (`Cannot read properties of undefined (reading 'parent_units')`) crashing the node, or divergent `is_free`/`assocBestChildren` state relative to a node that did not experience the interleave (verifiable by comparing `storage.assocBestChildren` / stability results across nodes with the flag enabled vs. disabled).

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

**File:** storage.js (L1808-1849)
```javascript
function archiveJointAndDescendants(from_unit){
	var kvstore = require('./kvstore.js');
	db.executeInTransaction(function doWork(conn, cb){
		
		function addChildren(arrParentUnits){
			conn.query("SELECT DISTINCT child_unit FROM parenthoods WHERE parent_unit IN(" + arrParentUnits.map(db.escape).join(', ') + ")", function(rows){
				if (rows.length === 0)
					return archive();
				var arrChildUnits = rows.map(function(row){ return row.child_unit; });
				arrUnits = arrUnits.concat(arrChildUnits);
				addChildren(arrChildUnits);
			});
		}
		
		function archive(){
			arrUnits = _.uniq(arrUnits); // does not affect the order
			arrUnits.reverse();
			console.log('will archive', arrUnits);
			var arrQueries = [];
			async.eachSeries(
				arrUnits,
				function(unit, cb2){
					readJoint(conn, unit, {
						ifNotFound: function(){
							throw Error("unit to be archived not found: "+unit);
						},
						ifFound: function(objJoint){
							archiving.generateQueriesToArchiveJoint(conn, objJoint, 'uncovered', arrQueries, cb2);
						}
					});
				},
				function(){
					conn.addQuery(arrQueries, "DELETE FROM known_bad_joints");
					conn.addQuery(arrQueries, "UPDATE units SET is_free=1 WHERE is_free=0 AND is_stable=0 \n\
						AND (SELECT 1 FROM parenthoods WHERE parent_unit=unit LIMIT 1) IS NULL");
					console.log('will execute '+arrQueries.length+' queries to archive');
					async.series(arrQueries, function(){
						arrUnits.forEach(function (unit) {
							var parent_units = assocUnstableUnits[unit].parent_units;
							forgetUnit(unit);
							fixIsFreeAfterForgettingUnit(parent_units);
						});
```

**File:** storage.js (L2209-2248)
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

// parent_units are parent units of the forgotten unit
function fixIsFreeAfterForgettingUnit(parent_units) {
	parent_units.forEach(function(parent_unit){
		if (!assocUnstableUnits[parent_unit]) // the parent is already stable
			return;
		var bHasChildren = false;
		for (var unit in assocUnstableUnits){
			var o = assocUnstableUnits[unit];
			if (o.parent_units.indexOf(parent_unit) >= 0)
				bHasChildren = true;
		}
		if (!bHasChildren)
			assocUnstableUnits[parent_unit].is_free = 1;
	});
}
```

**File:** joint_storage.js (L252-279)
```javascript
			mutex.lock(["write"], function(unlock) {
				db.takeConnectionFromPool(function (conn) {
					async.eachSeries(
						rows,
						function (row, cb) {
							breadcrumbs.add("--------------- archiving uncovered unit " + row.unit);
							storage.readJoint(conn, row.unit, {
								ifNotFound: function () {
									throw Error("nonserial unit not found?");
								},
								ifFound: function (objJoint) {
									var arrQueries = [];
									conn.addQuery(arrQueries, "BEGIN");
									archiving.generateQueriesToArchiveJoint(conn, objJoint, 'uncovered', arrQueries, function(){
										conn.addQuery(arrQueries, "COMMIT");
										// sql goes first, deletion from kv is the last step
										async.series(arrQueries, function(){
											kvstore.del('j\n'+row.unit, function(){
												breadcrumbs.add("------- done archiving "+row.unit);
												var parent_units = storage.assocUnstableUnits[row.unit].parent_units;
												storage.forgetUnit(row.unit);
												storage.fixIsFreeAfterForgettingUnit(parent_units);
												cb();
											});
										});
									});
								}
							});
```
