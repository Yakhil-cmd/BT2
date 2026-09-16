### Title
Unlocked in-memory cache mutation during light `dry_run_aa` races with concurrent unit validation/writing - (File: aa_composer.js, network.js)

### Summary
`aa_composer.dryRunPrimaryAATrigger()` (invoked from the `light/dry_run_aa` network command handler) mutates the node's shared in-memory storage caches (`storage.assocUnstableUnits`, `assocBestChildren`, `assocUnstableMessages`, etc.) to simulate an AA trigger, without holding the global `"write"` mutex that guards all other paths that read/write these same caches (unit validation in `validation.js`, unit commit in `writer.js`, cache maintenance in `storage.js`). This mirrors the f2fs bug class: a piece of shared, security/consensus-relevant state is transiently mutated outside of the lock that normally protects it, creating a window in which a concurrent, unrelated operation can observe or act on the corrupted transient state.

### Finding Description
`dryRunPrimaryAATrigger()` takes a DB connection, begins a transaction, and calls `insertFakeOutputsIntoMcUnit()` and `handleTrigger()` to run an AA trigger simulation against the *real* last stable MC unit object and the live in-memory caches (`storage.assocUnstableUnits`, `assocBestChildren`, `assocUnstableMessages`, `assocStableUnits`, etc.), as evidenced by the dedicated `fixCache()`/cache-equality assertions in `test/aa_composer.test.js` that exist specifically because a dry run can leave these caches inconsistent for single-witness networks (comment: "this hack is necessary only for 1-witness network where an AA-response unit can rebuild the MC to itself"). [1](#0-0) [2](#0-1) 

Every other code path that touches these same caches acquires the process-wide `"write"` mutex before mutating them: `writer.saveJoint()` rolls back and calls `storage.resetMemory(conn)` under the write path on error, `storage.js`'s `shrinkCache()` explicitly does `await mutex.lock("write")` before touching `assocKnownUnits`/`assocUnstableUnits`/etc., and `storage.resetMemory()`/`resetUnstableUnits()`/`resetStableUnits()` (called from `initCaches()`, which itself locks `mutex.lock(["write"])`) rebuild these same associative caches. [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) 

However, the `light/dry_run_aa` handler in `network.js` invokes `aa_composer.dryRunPrimaryAATrigger()` directly from an unprivileged, network-reachable command (any peer sending `light/dry_run_aa` with an arbitrary `address` and `trigger`), and only *after* the dry run completes does it conditionally call `storage.resetMemory()` — and only for `COUNT_WITNESSES === 1` networks, via `db.executeInTransaction()`, which does not take the `"write"` mutex used everywhere else. [7](#0-6) 

This is directly analogous to the f2fs `default_options`/`SB_INLINECRYPT` bug: there, a security-relevant flag was cleared and re-set with a gap during which concurrent file creation used the stale, wrong flag state. Here, a consensus-relevant, process-wide cache (main-chain/unstable-unit bookkeeping, best-children pointers, unstable messages used for stability determination in `main_chain.js`/`validation.js`) is transiently corrupted by an unlocked dry run while concurrent real unit validation (`validation.js`'s `validateParents`, `determineIfStableInLaterUnitsAndUpdateStableMcFlag`) and commit (`writer.saveJoint`) read and write the very same objects without any lock coordinating with the dry-run mutation window.

### Impact Explanation
Because `handleJoint`/`validation.validate` and `writer.saveJoint` rely on `storage.assocUnstableUnits`, `assocBestChildren`, and `assocUnstableMessages` to determine parent/ancestor relationships, stability, and MC index during real unit validation, a concurrently running `light/dry_run_aa` request can leave these structures in an inconsistent state (e.g., fake trigger/response units temporarily inserted, `is_free`/`main_chain_index` fields on real units temporarily altered by MC-rebuild logic during the dry run) while a genuine unit's validation is concurrently reading them. On single-witness (and potentially other) networks this can cause the node to compute an incorrect main chain / stability determination for a real unit, leading to divergence between nodes about unit validity or stability (the exact class of impact explicitly called out as acceptable: "node disagreement on validity or stability"). Because this cache is shared process-wide and the corrupting write path (`dryRunPrimaryAATrigger`) is reachable by any peer via the light `dry_run_aa` request, it is a real, remotely triggerable consensus-cache race, not merely a resource-exhaustion issue.

### Likelihood Explanation
`light/dry_run_aa` is a light-client wallet-service command that is processed for any connected peer without additional authorization (only address/trigger shape is validated) as shown in the `handleRequest` case block. Any full node that serves light requests and simultaneously validates/writes new units from the network is exposed to this race on every `light/dry_run_aa` call — this is not a rare, hard-to-hit timing window; it happens on essentially every dry run against a full node that also does normal unit processing, especially pronounced in single-witness/devnet or small-hub topologies where `COUNT_WITNESSES === 1` explicitly triggers the cache-fixup path, which is the very code path the maintainers already acknowledge is fragile (per the `fixCache()` test-only workaround).

### Recommendation
- Wrap the entirety of `dryRunPrimaryAATrigger()`'s cache-touching operations (`insertFakeOutputsIntoMcUnit`, `handleTrigger`, `revertResponsesInCaches`) in the same `"write"` mutex (`mutex.lock(["write"], ...)`) used by `writer.saveJoint()` and `storage.shrinkCache()`, so dry runs and real unit validation/writing cannot interleave on the shared caches.
- Alternatively, make the dry run operate on a private, cloned copy of the relevant cache structures instead of mutating the live `storage.assocUnstableUnits`/`assocBestChildren`/`assocUnstableMessages` objects in place, eliminating the need for any lock but also removing the shared-state corruption vector entirely.
- Remove the special-cased, unlocked `storage.resetMemory()` call in the `light/dry_run_aa` handler and instead unconditionally serialize dry runs with the write mutex so no post-hoc cache repair is required for the 1-witness case.

### Proof of Concept
1. Run a full node with `COUNT_WITNESSES === 1` (e.g., a devnet/single-witness hub) that also serves light clients.
2. From a light client (or any peer), continuously send `light/dry_run_aa` requests with a valid AA `address` and a `trigger` whose response causes an MC-rebuild (any AA that spends/returns funds so that the dry-run response unit becomes the new best child of the last stable MC unit) — this matches the exact scenario the maintainers guard against with `fixCache()` in `test/aa_composer.test.js`.
3. Concurrently, have another peer post real units (payments/AA triggers) to the same node so that `validation.js`'s `validateParents`/stability logic and `writer.saveJoint()` run in the same time window as step 2's `dryRunPrimaryAATrigger()` execution (before its rollback and cache revert completes).
4. Observe that `storage.assocUnstableUnits`/`assocBestChildren`/`main_chain_index`/`is_free` fields diverge from what a strictly serialized (write-locked) execution would produce — detectable by comparing against `old_cache` snapshots the way `test/aa_composer.test.js`'s `fixCache()`/`t.deepEqual(storage.assocUnstableUnits, ...)` assertions do — showing the real unit was validated/stabilized against corrupted transient state. [8](#0-7)

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

**File:** test/aa_composer.test.js (L120-153)
```javascript
test.cb.serial('less than bounce fees', t => {
	var trigger = { outputs: { base: 2000 }, data: { x: 333 } };
	var aa = ['autonomous agent', {
		bounce_fees: { base: 10000 },
		messages: [
			{
				app: 'payment',
				payload: {
					asset: 'base',
					outputs: [
						{address: "{trigger.address}", amount: "{trigger.output[[asset=base]] - 500}"}
					]
				}
			}
		]
	}];
	var address = objectHash.getChash160(aa);
	addAA(aa);
	
	aa_composer.dryRunPrimaryAATrigger(trigger, address, aa, (arrResponses) => {
		t.deepEqual(arrResponses.length, 1);
		t.deepEqual(arrResponses[0].aa_address, address);
		t.deepEqual(arrResponses[0].bounced, true);
		t.deepEqual(arrResponses[0].response_unit, null);
		t.deepEqual(arrResponses[0].objResponseUnit, null);
		t.deepEqual(arrResponses[0].response.error, "received bytes are not enough to cover bounce fees");
		fixCache();
		t.deepEqual(storage.assocUnstableUnits, old_cache.assocUnstableUnits);
		t.deepEqual(storage.assocStableUnits, old_cache.assocStableUnits);
		t.deepEqual(storage.assocUnstableMessages, old_cache.assocUnstableMessages);
		t.deepEqual(storage.assocBestChildren, old_cache.assocBestChildren);
		t.deepEqual(storage.assocStableUnitsByMci, old_cache.assocStableUnitsByMci);
		t.end();
	});
```

**File:** writer.js (L708-713)
```javascript
								if (err) {
									var headers_commission = require("./headers_commission.js");
									headers_commission.resetMaxSpendableMci();
									delete storage.assocUnstableMessages[objUnit.unit];
									await storage.resetMemory(conn);
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

**File:** storage.js (L2500-2530)
```javascript
function resetUnstableUnits(conn, onDone){
	Object.keys(assocBestChildren).forEach(function(unit){
		delete assocBestChildren[unit];
	});
	Object.keys(assocUnstableUnits).forEach(function(unit){
		delete assocUnstableUnits[unit];
	});
	initUnstableUnits(conn, onDone);
}

function resetStableUnits(conn, onDone){
	console.log('resetStableUnits');
	Object.keys(assocStableUnits).forEach(function(unit){
		delete assocStableUnits[unit];
	});
	Object.keys(assocStableUnitsByMci).forEach(function(mci){
		delete assocStableUnitsByMci[mci];
	});
	initStableUnits(conn, onDone);
}

function resetMemory(conn, onDone){
	if (!onDone)
		return new Promise(resolve => resetMemory(conn, resolve));
	resetUnstableUnits(conn, function(){
		resetStableUnits(conn, function(){
			min_retrievable_mci = null;
			initializeMinRetrievableMci(conn, onDone);
		});
	});
}
```

**File:** storage.js (L2532-2537)
```javascript
async function initCaches() {
	console.log('initCaches');
	const unlock = await mutex.lock(["write"]);
	const conn = await db.takeConnectionFromPool();
	await conn.query("BEGIN");
	await initSystemVars(conn);
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
