### Title
Use-after-forget of stabilized AA response units in `revertResponsesInCaches` crashes node consensus processing - (File: aa_composer.js)

### Summary
`aa_composer.js`'s trigger-reversion path removes AA response units from the in-memory unit caches via `storage.forgetUnit()` without checking whether those units have, in the meantime, transitioned from the "unstable" cache (`assocUnstableUnits`) to the "stable" cache (`assocStableUnits`). This mirrors the CVE-2023-53187 btrfs pattern: an object created and tracked in one list (new/unstable) is moved into a different list (stable/reclaimed) by a concurrent code path, and the code that later "frees"/forgets it still assumes it is in the original list, leading to an inconsistency between the object's lifecycle state and the tracking structures that reference it.

### Finding Description
`aa_composer.js`'s `handleTrigger()` posts AA response units synchronously through `sendUnit()` → `validateAndSaveUnit()` → `writer.saveJoint()`: [1](#0-0) 

Inside `writer.saveJoint()`, after inserting the unit into `storage.assocUnstableUnits`, the code immediately calls `main_chain.updateMainChain()` synchronously in the same call, which can advance and stabilize main-chain indexes right away: [2](#0-1) 

When an MCI becomes stable, `main_chain.markMcIndexStable()` moves the affected unit's properties object out of `storage.assocUnstableUnits` and into `storage.assocStableUnits` / `assocStableUnitsByMci`: [3](#0-2) 

The `aa_composer.test.js` suite documents that this can happen mid-trigger for AA response units on networks with `COUNT_WITNESSES === 1`, i.e. "an AA-response unit can rebuild the MC to itself": [4](#0-3) 

If a later step of the *same* trigger fails (e.g. `updateStorageSize()` returns an error) the code calls `revert()`, which in turn calls `revertResponsesInCaches()` to undo previously-posted response units for this trigger: [5](#0-4) 

```js
function revertResponsesInCaches(arrResponses) {
	var arrResponseUnits = [];
	arrResponses.forEach(function (objAAResponse) {
		if (objAAResponse.response_unit)
			arrResponseUnits.push(objAAResponse.response_unit);
	});
	if (arrResponseUnits.length > 0) {
		var first_unit = arrResponseUnits[0];
		var objFirstUnit = storage.assocUnstableUnits[first_unit];
		var parent_units = objFirstUnit.parent_units;
		arrResponseUnits.forEach(storage.forgetUnit);
		storage.fixIsFreeAfterForgettingUnit(parent_units);
	}
}
``` [6](#0-5) 

This code unconditionally dereferences `storage.assocUnstableUnits[first_unit]` and calls `storage.forgetUnit()` on every unit in `arrResponseUnits`, assuming they are still tracked as unstable. `storage.forgetUnit()` however treats "already stable" as a fatal, unrecoverable condition:
```js
function forgetUnit(unit){
	...
	assocUnstableUnits[unit].parent_units.forEach(...)   // throws TypeError if unit already stabilized (removed from assocUnstableUnits)
	...
	delete assocUnstableUnits[unit];
	if (!conf.bLight && assocStableUnits[unit])
		throw Error("trying to forget stable unit "+unit);
	delete assocStableUnits[unit];
	...
}
``` [7](#0-6) 

If any response unit in the chain has already been promoted to `assocStableUnits` (via the mid-trigger MC rebuild described above) by the time `revert()`/`revertResponsesInCaches()` runs, `forgetUnit()` either:
1. Throws a fatal, uncaught `Error("trying to forget stable unit ...")` on full nodes, crashing the node process deterministically for every node that processes the same trigger/response chain, or
2. On `conf.bLight` nodes, silently deletes the object from `assocStableUnits` while it remains referenced from `assocStableUnitsByMci[mci]` (never cleaned up by `forgetUnit()`), leaving a stale/inconsistent object in the stability-indexed cache that other consensus code (`getFinalTps()`, `getMcUnitProps()`, `main_chain.js`) subsequently iterates over.

This is the same bug class as the btrfs CVE: an object is moved between two lifecycle-tracking data structures (unstable → stable) by one code path while another code path (`revertResponsesInCaches`) still holds a stale assumption about which list "owns" the object and unconditionally mutates/removes it, producing either a crash or a corrupted cache with dangling references.

### Impact Explanation
On networks where an AA-response unit can rebuild the main chain to itself mid-trigger (documented explicitly for `COUNT_WITNESSES === 1` deployments, which is a common configuration for permissioned/private DAG deployments using `ocore`), any AA whose response chain can subsequently be forced to bounce/revert (e.g., by failing `updateStorageSize()` or a secondary-AA balance check) can deterministically crash every full node processing that trigger — because the failure and the underlying assertion happen from purely deterministic AA execution, all nodes hit it identically, halting the network's ability to confirm any further units (an accepted High-impact category: "a network unable to confirm new units"). On `bLight`-configured deployments, the same path corrupts `assocStableUnitsByMci`/`assocStableUnits` cache consistency, potentially causing later TPS-fee and stability computations (`getFinalTps`, `getMcUnitProps`) to disagree between nodes.

### Likelihood Explanation
Triggering requires: (1) a low-witness-count (or single-witness) `ocore`-based network, which is a supported and documented deployment mode (see the test hack comment), and (2) an AA whose trigger produces at least one response unit and then hits a later revertible failure in the same trigger evaluation (storage-size overflow or secondary-trigger bounce), which is fully controllable by an unprivileged AA trigger sender crafting the AA definition and trigger payload. No special privileges are needed beyond normal unit/trigger posting.

### Recommendation
In `revertResponsesInCaches()` (aa_composer.js), check whether each response unit is still present in `storage.assocUnstableUnits` before calling `storage.forgetUnit()`, and skip/handle already-stabilized units gracefully instead of assuming they are always unstable. Additionally, harden `storage.forgetUnit()` to be safe/idempotent when invoked on a unit that has already transitioned to `assocStableUnits`, and ensure `assocStableUnitsByMci` is kept consistent whenever a unit is removed from `assocStableUnits` by any code path.

### Proof of Concept
1. Configure/run an `ocore`-based network with `constants.COUNT_WITNESSES === 1` (or another config where an AA response unit becomes the new main-chain tip synchronously within `writer.saveJoint()`).
2. Deploy an AA whose primary trigger emits one or more response messages, generating a response unit that becomes the new main-chain unit and gets stabilized during `main_chain.updateMainChain()` inside the same `sendUnit()`/`saveJoint()` call (as reproduced by the `fixCache()` test helper in `test/aa_composer.test.js`).
3. Craft the trigger such that a subsequent step of the same trigger evaluation fails after the response unit has already been posted — e.g., have the AA's state var writes exceed available byte balance so `updateStorageSize()` returns an error, or have a downstream secondary AA bounce — forcing `revert()` → `revertResponsesInCaches()` to run.
4. Observe that `storage.forgetUnit()` throws `"trying to forget stable unit ..."` (full node) because the unit was already moved into `assocStableUnits`, crashing the process that is handling the trigger, or silently corrupts `assocStableUnits`/`assocStableUnitsByMci` consistency on `bLight` nodes.

### Citations

**File:** aa_composer.js (L1759-1783)
```javascript
	function revert(err) {
		console.log('will revert: ' + err);
		if (bSecondary)
			return bounce(err);
		if (!trigger_opts.bAir)
			revertResponsesInCaches(arrResponses);
		
		// copy all logs
		var logs = [];
		arrResponses.forEach(objAAResponse => {
			if (objAAResponse.logs)
				logs = logs.concat(objAAResponse.logs);
		});
		if (logs.length > 0)
			objValidationState.logs = logs;
		
		arrResponses.splice(0, arrResponses.length); // start over
		if (trigger_opts.bAir)
			return bounce(err);
		Object.keys(stateVars).forEach(function (address) { delete stateVars[address]; });
		batch.clear();
		conn.query("ROLLBACK TO SAVEPOINT initial_balances", function () {
			console.log('done revert: ' + err);
			bounce(err);
		});
```

**File:** aa_composer.js (L1800-1837)
```javascript
	function validateAndSaveUnit(objUnit, cb) {
		var objJoint = { unit: objUnit, aa: true, aa_mci: mci };
		validation.validate(objJoint, {
			ifJointError: function (err) {
				throw Error("AA validation joint error: " + err);
			},
			ifUnitError: function (err) {
				console.log("AA validation unit error: " + err);
				return cb(err);
			},
			ifTransientError: function (err) {
				throw Error("AA validation transient error: " + err);
			},
			ifNeedHashTree: function () {
				throw Error("AA validation unexpected need hash tree");
			},
			ifNeedParentUnits: function (arrMissingUnits) {
				throw Error("AA validation unexpected dependencies: " + arrMissingUnits.join(", "));
			},
			ifOkUnsigned: function () {
				throw Error("AA validation returned ok unsigned");
			},
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

**File:** writer.js (L596-654)
```javascript
			else
				storage.assocUnstableUnits[objUnit.unit] = objNewUnitProps;
			if (!bGenesis && storage.assocUnstableUnits[my_best_parent_unit]) {
				if (!storage.assocBestChildren[my_best_parent_unit])
					storage.assocBestChildren[my_best_parent_unit] = [];
				storage.assocBestChildren[my_best_parent_unit].push(objNewUnitProps);
			}
			if (objUnit.messages) {
				objUnit.messages.forEach(function(message) {
					if (['data_feed', 'definition', 'system_vote', 'system_vote_count'].includes(message.app)) {
						if (!storage.assocUnstableMessages[objUnit.unit])
							storage.assocUnstableMessages[objUnit.unit] = [];
						storage.assocUnstableMessages[objUnit.unit].push(message);
						if (message.app === 'system_vote' && !objValidationState.bDryRun)
							eventBus.emit('system_var_vote', message.payload.subject, message.payload.value, arrAuthorAddresses, objUnit.unit, 0);
					}
				});
			}
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

**File:** main_chain.js (L1293-1307)
```javascript
	var arrStabilizedUnits = [];
	if (mci > 0)
		storage.assocStableUnitsByMci[mci] = [];
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

**File:** test/aa_composer.test.js (L49-59)
```javascript
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
