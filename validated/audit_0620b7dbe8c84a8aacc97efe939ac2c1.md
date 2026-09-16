## Finding

### Title
Dry-run AA trigger execution mutates shared unit caches while claiming (but never acquiring) the `"write"` mutex - ([File: aa_composer.js])

### Summary
`aa_composer.dryRunPrimaryAATrigger()` executes a full trigger simulation (including a call into `writer.saveJoint()`) while pretending the `"write"` mutex is already held, but the code path that invokes it from `network.js` never actually acquires that lock. This mirrors the vxlan CVE pattern: code that deletes/mutates a shared lock-protected structure (`vxlan_find_mac`/FDB hash) is invoked from a path that skips acquiring the lock the rest of the code assumes is held.

### Finding Description
`writer.saveJoint()` normally serializes all mutation of the global in-memory unit caches (`storage.assocUnstableUnits`, `storage.assocBestChildren`, `storage.assocStableUnits`, etc.) behind the `"write"` mutex: [1](#0-0) 

It only skips taking that lock when the caller asserts it is already inside a write-locked critical section:
```
const unlock = objValidationState.bUnderWriteLock ? () => { } : await mutex.lock(["write"]);
``` [2](#0-1) 

Once inside, it unconditionally mutates the shared caches: [3](#0-2) 

`aa_composer.js`'s `validateAndSaveUnit()` sets `objAAValidationState.bUnderWriteLock = true` before calling `writer.saveJoint()`, on the assumption that whoever invoked `handleTrigger()` already holds the `"write"` mutex: [4](#0-3) 

However, `dryRunPrimaryAATrigger()` — which calls `handleTrigger()` and therefore reaches `validateAndSaveUnit()`/`writer.saveJoint()` — never takes the `"write"` mutex itself: [5](#0-4) 

After the simulated trigger finishes, `revertResponsesInCaches()` is called to roll back the in-memory effects by calling `storage.forgetUnit()`/`fixIsFreeAfterForgettingUnit()` directly on the shared caches, again with no lock held: [6](#0-5) 

This dry-run path is reachable directly from processing of an untrusted, unprivileged unit: in `network.js`, when a freshly posted unit (not yet stable, no `ball`) contains a primary AA trigger and `conf.bDryRunNewTriggers` is enabled, `dryRunPrimaryAATrigger()` is invoked for each targeted AA address before the real unit is even saved: [7](#0-6) 

Meanwhile, other legitimate mutators of the exact same caches (`assocUnstableUnits`, `assocBestChildren`, `assocStableUnits`, `assocStableUnitsByMci`) do take the real `"write"` mutex, e.g. `storage.shrinkCache()`: [8](#0-7) 

and `writer.saveJoint()`'s own MC-stabilization loop, which is entered while a *different* holder of `"write"` legitimately owns the lock: [9](#0-8) 

Because the dry-run path never registers itself with `mutex.js`'s lock table, `mutex.isAnyOfKeysLocked(["write"])` returns `false` for it, so a legitimately-locked writer (stabilization, `shrinkCache`, catchup processing, or another `handleAATriggers()` batch) can run concurrently with the dry run's insert/mutate/rollback of `assocUnstableUnits`/`assocBestChildren`, exactly as `vxlan_find_mac()` could be entered concurrently with an unlocked FDB deletion in the kernel bug.

### Impact Explanation
The mutated caches are the authoritative in-memory source of truth for unit stability computation (`main_chain.js`), best-parent selection, and `is_free` bookkeeping used throughout validation and writing. An unprivileged unit poster can trigger this path simply by sending a payment unit that targets one or more AA addresses (any address with a stored AA definition). Racing the dry-run's temporary insert/forget of a unit object against a real concurrent writer touching the same maps can:
- corrupt `assocBestChildren`/`assocUnstableUnits` entries (e.g. `_.pull` removing/failing to remove the wrong object reference, or `forgetUnit` deleting a unit that a concurrent stabilization pass is actively reading),
- throw uncaught `Error`s inside these hot paths (e.g. `"no such variable"`/`"trying to forget stable unit"`/mismatched cached-props assertions already present as sanity checks in `storage.js`), crashing the node or causing nodes to diverge on stability/validity decisions.

This falls under "node disagreement on validity or stability" / "a network unable to confirm new units" from the accepted impact categories.

### Likelihood Explanation
Reaching the vulnerable path requires no special privileges — posting a normal payment unit to any known AA address is enough to trigger `dryRunPrimaryAATrigger()` when `conf.bDryRunNewTriggers` is enabled (a documented, non-default-off feature used to preemptively validate that a trigger won't crash). Triggering a genuine race requires the dry run to overlap in time with another `"write"`-mutex-guarded operation (catchup, stabilization, `shrinkCache`, or another AA trigger batch) — plausible on any moderately active full node given `shrinkCache` runs every 5 minutes and AA trigger batches / stabilization happen continuously.

### Recommendation
Have `dryRunPrimaryAATrigger()` (and any other caller that sets `bUnderWriteLock`) actually acquire `mutex.lock(["write"])` before invoking `handleTrigger()`/`writer.saveJoint()`, releasing it only after `revertResponsesInCaches()` completes — mirroring the kernel fix of acquiring the hash lock before the unlocked FDB deletion.

### Proof of Concept
1. Enable `conf.bDryRunNewTriggers` on a full node with at least one deployed AA.
2. Attacker A posts a payment unit whose output targets the AA address; this triggers `network.js`'s `ifOk` handler to call `aa_composer.dryRunPrimaryAATrigger()` (no `"write"` lock held).
3. Concurrently, trigger a legitimate `"write"`-mutex holder to run on the same node — e.g. wait for the periodic `storage.shrinkCache()` (runs every 300s) or have another unit stabilize a main-chain index, both of which mutate `assocUnstableUnits`/`assocBestChildren`/`assocStableUnitsByMci` under `mutex.lock(["write"])`.
4. Because the dry run path never registers under the `"write"` key, both operations run interleaved, mutating/reading the same JS objects; depending on timing this can throw one of the cache-consistency assertions in `storage.js` (`readUnitProps`, `forgetUnit`) or silently corrupt `assocBestChildren`, causing incorrect best-parent/stability computation on that node.

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

**File:** writer.js (L591-601)
```javascript
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
```

**File:** writer.js (L738-769)
```javascript
								if (arrStabilizedMcis.length > 0 && !err) {
									// try to stabilize more MCIs, run triggers and update tps fees after each
									console.log(`stabilized MCI ${arrStabilizedMcis.join(', ')}, trying to stabilize more`);
									while (true) {
										const conn = await db.takeConnectionFromPool();
										await conn.query("BEGIN");
										const batch = kvstore.batch();
										const { arrStabilizedMcis, bStabilizedAATriggers } = await main_chain.advanceMcStability(conn, batch, objUnit.unit);
										console.log(`additional stabilization result`, arrStabilizedMcis, bStabilizedAATriggers);
										if (arrStabilizedMcis.length > 1)
											throw Error(`additional stabilization resulted in more than one MCI: ${arrStabilizedMcis.join(', ')}`);
										await util.promisify(batch.write.bind(batch))({ sync: true });
										await conn.query("COMMIT");
										conn.release();
										if (arrStabilizedMcis.length === 0)
											break;
										if (bStabilizedAATriggers) {
											console.log(`executing AA triggers after additional stabilization`, arrStabilizedMcis);
											// every trigger takes its own db connection
											const aa_composer = require("./aa_composer.js");
											await aa_composer.handleAATriggers();
										}
										if (arrStabilizedMcis[0] >= constants.v4UpgradeMci) {
											console.log(`updating tps fees after additional stabilization`, arrStabilizedMcis);
											// get a new connection to write tps fees
											const conn = await db.takeConnectionFromPool();
											await conn.query("BEGIN");
											await storage.updateTpsFees(conn, arrStabilizedMcis);
											await conn.query("COMMIT");
											conn.release();
										}
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

**File:** storage.js (L2250-2263)
```javascript
async function shrinkCache(){
	if (Object.keys(assocCachedAssetInfos).length > MAX_ITEMS_IN_CACHE)
		assocCachedAssetInfos = {};
	console.log(Object.keys(assocUnstableUnits).length+" unstable units");
	var arrKnownUnits = Object.keys(assocKnownUnits);
	var arrPropsUnits = Object.keys(assocCachedUnits);
	var arrStableUnits = Object.keys(assocStableUnits);
	var arrAuthorsUnits = Object.keys(assocCachedUnitAuthors);
	var arrWitnessesUnits = Object.keys(assocCachedUnitWitnesses);
	if (arrPropsUnits.length < MAX_ITEMS_IN_CACHE && arrAuthorsUnits.length < MAX_ITEMS_IN_CACHE && arrWitnessesUnits.length < MAX_ITEMS_IN_CACHE && arrKnownUnits.length < MAX_ITEMS_IN_CACHE && arrStableUnits.length < MAX_ITEMS_IN_CACHE)
		return console.log('cache is small, will not shrink');
	const unlock = await mutex.lock("write");
	var arrUnits = _.union(arrPropsUnits, arrAuthorsUnits, arrWitnessesUnits, arrKnownUnits, arrStableUnits);
	console.log('will shrink cache, total units: '+arrUnits.length);
```
