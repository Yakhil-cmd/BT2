### Title
Cache corruption from concurrent dry-run AA trigger execution touching shared in-memory unit caches without holding the write lock - (File: aa_composer.js)

### Summary
CVE-2024-2627 is a Chromium Canvas use-after-free: an object is freed/invalidated while a live reference to it is still used elsewhere, corrupting heap state and enabling exploitation. The analogous bug class in `ocore--011` is not memory-unsafety (JS has no raw UAF), but the same "stale reference to a mutated/removed shared object used concurrently" pattern shows up in the in-process AA dry-run path: `dryRunPrimaryAATrigger` mutates the same global unit caches (`storage.assocUnstableUnits`, `assocBestChildren`, `assocUnstableMessages`, etc.) that the real, lock-protected write path (`writer.saveJoint`, `aa_composer.handlePrimaryAATrigger`) also mutates, but the dry run is invoked from `ifOk` in `network.js` before the `"write"` mutex is taken. [1](#0-0) 

### Finding Description
When a posted unit triggers a primary AA and `conf.bDryRunNewTriggers` is set, `network.js`'s `ifOk` handler calls `aa_composer.dryRunPrimaryAATrigger` for every affected AA address, awaiting each dry run sequentially, *before* `writer.saveJoint` is invoked and *before* the `"write"` mutex is acquired: [2](#0-1) 

`dryRunPrimaryAATrigger` runs `handleTrigger` against a real DB connection with `BEGIN`, executes the AA logic (which can insert into `storage.assocUnstableUnits`, `assocBestChildren`, `assocUnstableMessages` as part of composing a fake response unit), then rolls the DB transaction back and calls `revertResponsesInCaches` to undo the in-memory cache mutations: [3](#0-2) [4](#0-3) 

`revertResponsesInCaches` calls `storage.forgetUnit` on the fabricated response units and then `storage.fixIsFreeAfterForgettingUnit` to restore parent `is_free` flags, directly mutating the shared, process-global cache objects: [5](#0-4) [6](#0-5) 

These caches (`assocUnstableUnits`, `assocBestChildren`, `assocStableUnits`, `assocUnstableMessages`, `assocStableUnitsByMci`) are otherwise only supposed to be mutated while holding the `"write"` mutex — this is exactly what `writer.saveJoint` enforces via `mutex.lock(["write"])`: [7](#0-6) 

and it is exactly the invariant the test suite's `fixCache`/`old_cache` snapshot-and-restore machinery exists to verify for dry runs (proving the authors are aware these caches must return to byte-identical state after a dry run, i.e., that dry runs are not supposed to leave any observable trace): [8](#0-7) [9](#0-8) 

Because the pre-trigger dry run in `network.js:1271-1281` is `await`ed without holding the `"write"` mutex, any other unit-processing pipeline that legitimately holds or acquires the `"write"` lock during that same window (real AA execution via `handlePrimaryAATrigger`, or another unit's `writer.saveJoint`) can read/mutate `storage.assocUnstableUnits[unit]`/`assocBestChildren[parent]` objects concurrently with the dry run's in-place mutation and later reversal. Since `forgetUnit` performs `delete` and `_.pull` against arrays/objects that a concurrent writer may already be iterating or holding a direct object reference to (e.g., `assocBestChildren[parent_unit]` arrays that best-parent selection and main-chain construction algorithms walk by reference), a dry run's `forgetUnit`/`fixIsFreeAfterForgettingUnit` call can delete or mutate an entry that a concurrently-running real save/trigger execution still expects to be present and unchanged — the JS analog of using a reference to an object that was concurrently freed/invalidated. This can silently corrupt `is_free`, `main_chain_index`, or `assocBestChildren` bookkeping for units unrelated to the dry run, which downstream is asserted against the DB truth in `readUnitProps` and throws `"different props of ..."`/`"cache is corrupt"` on mismatch — but only when the assertion happens to run again; in between, main-chain/stability logic operating purely off the in-memory caches can compute incorrect `is_on_main_chain`/`is_free`/best-parent state.

### Impact Explanation
If the AA dry-run path races with a genuine main-chain/stability computation or a real AA trigger execution and corrupts `assocBestChildren`/`assocUnstableUnits`/is_free bookkeeping, the node can diverge from the DB-backed truth for best-parent/main-chain selection. This is a node-disagreement-on-validity/stability class issue: since main chain and stability determination directly drive which units are considered stable (and hence which payment outputs/AA effects become final), incorrect in-memory state can cause a node to compute a different main chain or an incorrect free-unit set than other honest nodes, potentially stabilizing/rejecting units differently than peers — a "node disagreement on validity or stability" outcome the report's acceptance criteria explicitly allow. This is reachable purely by an unprivileged party posting an ordinary unit that pays to an existing AA address (triggering `conf.bDryRunNewTriggers`), i.e. from a single posted unit as required by scope rules.

### Likelihood Explanation
The trigger condition requires `conf.bDryRunNewTriggers` to be enabled and requires timing overlap between the awaited dry run (which does real DB work per AA address, is not negligible in duration) and another write-lock-holding operation touching the same units/parents. Because `dryRunPrimaryAATrigger` explicitly does not hold `"write"` while doing meaningful cache mutation and reversal, and the whole node is single-process/event-loop-based (interleaving happens at `await`/callback boundaries, which are frequent here — DB queries, `kvstore` batch writes, etc.), a race window genuinely exists on every unit that pays to an AA address. Exploiting it deterministically (to force a specific desirable divergence) is harder and would likely require timing multiple crafted units, which lowers practical severity somewhat versus a trivially reproducible bug, but the race condition itself is plausible without needing a malicious peer/node — only an ordinary unit poster.

### Recommendation
Take the `"write"` mutex (or an equivalent lock protecting the caches touched by `handleTrigger`/`revertResponsesInCaches`) for the entire duration of `dryRunPrimaryAATrigger`, matching the invariant already enforced for `writer.saveJoint` and `handlePrimaryAATrigger`, so that cache mutation and reversal from a dry run can never interleave with real cache mutations from concurrent writers. Alternatively, redesign the dry run to operate on a deep-cloned/isolated snapshot of the relevant cache slices rather than mutating the live global caches in place and reverting them afterward.

### Proof of Concept
Conceptual timing PoC (cannot be executed without live instrumentation of the event loop, but the code paths are concrete):
1. Attacker A posts unit U1 that pays to AA address X (any address with `aa_addresses` row), with `conf.bDryRunNewTriggers` enabled. This causes `network.js` `ifOk` to call `aa_composer.dryRunPrimaryAATrigger(trigger, X, defX)` at [10](#0-9)  — without the `"write"` lock held.
2. While the dry run's `handleTrigger` is executing (before `revertResponsesInCaches`/`ROLLBACK` completes), a second, independent unit U2 (posted by anyone) completes real validation and enters `writer.saveJoint`, acquiring `mutex.lock(["write"])` at [11](#0-10)  concurrently, mutating `storage.assocUnstableUnits`/`assocBestChildren` for units that share a parent with the dry run's fabricated response unit.
3. When the dry run's `onDone` fires, `revertResponsesInCaches` calls `storage.forgetUnit`/`fixIsFreeAfterForgettingUnit` at [12](#0-11) , deleting/mutating `assocBestChildren[parent_unit]` entries and setting `is_free` flags that may now be stale relative to U2's concurrent write, corrupting the parent's cached `is_free`/best-children state used by main-chain determination.

### Citations

**File:** network.js (L1271-1283)
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
					}
					writer.saveJoint(objJoint, objValidationState, null, function(){
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

**File:** storage.js (L2234-2248)
```javascript
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

**File:** test/aa_composer.test.js (L47-60)
```javascript
var old_cache = {};

// this hack is necessary only for 1-witness network where an AA-response unit can rebuild the MC to itself
function fixCache() {
	if (Object.keys(old_cache.assocUnstableUnits).length !== 1)
		return;
	for (var unit in storage.assocUnstableUnits) {
		var objUnit = storage.assocUnstableUnits[unit];
		if (objUnit.is_free) {
			objUnit.is_on_main_chain = old_cache.assocUnstableUnits[unit].is_on_main_chain;
			objUnit.main_chain_index = old_cache.assocUnstableUnits[unit].main_chain_index;
		}
	}
}
```

**File:** test/aa_composer.test.js (L546-552)
```javascript
		fixCache();
		t.deepEqual(storage.assocUnstableUnits, old_cache.assocUnstableUnits);
		t.deepEqual(storage.assocStableUnits, old_cache.assocStableUnits);
		t.deepEqual(storage.assocUnstableMessages, old_cache.assocUnstableMessages);
		t.deepEqual(storage.assocBestChildren, old_cache.assocBestChildren);
		t.deepEqual(storage.assocStableUnitsByMci, old_cache.assocStableUnitsByMci);
		t.end();
```
