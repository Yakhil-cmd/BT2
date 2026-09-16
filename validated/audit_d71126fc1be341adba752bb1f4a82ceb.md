### Title
Incomplete cache reversion in `revertResponsesInCaches` leaves stale unstable-unit references and desyncs `is_free` state after a chained AA bounce - (File: aa_composer.js)

### Summary
`bt_conn_tx_processor` frees a tx-buffer object while another code path still holds a pointer to it and later writes through that stale pointer, corrupting memory. The closest reachable analog in ocore is in the AA-trigger composer: when a chain of AA response units must be reverted (`revert()` → `revertResponsesInCaches()`), only the *first* response unit's parent set is used to repair the `is_free`/`assocBestChildren` in-memory caches, while the units and cache objects for the rest of the chain are torn down (`storage.forgetUnit`) without properly detaching all stale references. This leaves dangling entries in `storage.assocBestChildren` and unrepaired `is_free` flags in `storage.assocUnstableUnits`, i.e. an in-memory analog of "freed but still referenced, later mutated" objects that other node subsystems (main-chain/parent selection) continue to read and write.

### Finding Description
`handleTrigger()` in `aa_composer.js` executes a primary AA trigger and any chain of secondary AA triggers it provokes. Each successful step calls `sendUnit()`/`addResponse()`, which registers the newly composed response unit in `storage.assocUnstableUnits` and links it into `storage.assocBestChildren[parent_unit]` (see `writer.js` lines 595-601, the same in-memory bookkeeping pattern used when any unit is written).

If a later secondary AA in the chain bounces with an error, `handleSecondaryTriggers()` calls `revert()` for the *whole* chain (not just the failing branch): [1](#0-0) 

`revert()` calls `revertResponsesInCaches(arrResponses)` to undo the in-memory bookkeeping for every unit produced so far, and then rolls back only to `SAVEPOINT initial_balances` in the DB: [2](#0-1) 

`revertResponsesInCaches()`, however, computes `parent_units` **only from the first unit in the chain** and calls `storage.fixIsFreeAfterForgettingUnit()` once with that single parent set, even though `arrResponseUnits` can contain multiple chained response units (primary + N secondaries), each with its own (possibly different) parents: [3](#0-2) 

`storage.forgetUnit()` is invoked for every unit in the chain. For each unit it reads `assocUnstableUnits[unit].parent_units` to detach the unit from `assocBestChildren[parent_unit]` via `_.pull`, then deletes the unit from every cache map (`assocKnownUnits`, `assocCachedUnits`, `assocUnstableUnits`, `assocStableUnits`, `assocUnstableMessages`, `assocBestChildren`): [4](#0-3) 

Because `forEach(storage.forgetUnit)` invokes `forgetUnit(unit, index, array)`, and each unit's own parent-detachment happens correctly, `assocBestChildren` links pointing *into* each forgotten unit are cleaned. The bug is that `fixIsFreeAfterForgettingUnit()`—which recomputes whether a parent still has any live children and, if not, restores `is_free = 1` on it—is only ever called for the parents of `arrResponseUnits[0]`: [5](#0-4) 

For a 2-unit-or-longer chain (primary → secondary1 → secondary2 …), the parents of `secondary1`, `secondary2`, etc. (typically the *previous* response unit in the chain, since each new response unit's best parent is usually the prior one) never get their `is_free` flag restored in memory after their child was forgotten. Their in-memory `is_free` stays `0` forever, even though the SQL-side `is_free` column was correctly rolled back by `ROLLBACK TO SAVEPOINT initial_balances` (which undoes the earlier `UPDATE units SET is_free=0` performed when those units were inserted).

This creates a permanent, silent divergence between the SQL truth and the in-memory cache that many hot paths trust without re-querying the DB, e.g. `readUnitProps()`'s `conf.bFaster` fast-path returns cached props directly without a DB round trip: [6](#0-5) 
and `readPropsOfUnits()` similarly short-circuits to the in-memory cache under `conf.bFaster`: [7](#0-6) 

`storage.assocBestChildren` is also consulted by `writer.js` when new units are attached and by `main_chain.js` when computing best-parent/witness chains, so once a unit's cache entry is corrupted, subsequent free/parent selection, main-chain construction, and stability determination for later units can operate on the desynchronized state.

### Impact Explanation
The specific write-before-zero/UAF impact described in the report ("attacker-controlled 4 bytes") does not translate literally to a JS heap, but the reachable analog is a **use of stale/incompletely-detached cache objects** that other subsystems (parent-unit selection, `is_free` bookkeeping, main-chain building) continue to read and mutate after the objects were supposed to be fully retired. This falls under "node disagreement on validity or stability" / "network unable to confirm new units" in the acceptance criteria: a node that ran this code path can develop a permanently corrupted view of which units are free/eligible parents, diverging from its own SQL state and from peers that never hit the bug, which can manifest as stuck unit composition, incorrect best-parent computation, or main-chain/witness disagreement versus honest nodes reconstructing state from the DB.

### Likelihood Explanation
This is triggered purely by posting AA triggers that cause a **chain of at least two AA calls where a later link bounces** (a normal, attacker-reachable interaction — no special privileges, hub, or peer position needed; only a valid unit + AA trigger is required). Any user can define/call chained AAs and intentionally craft the final AA in the chain to bounce (e.g., insufficient balance, `bounce()` call, formula error) to reliably hit `revert()` with `arrResponses.length > 1`.

### Recommendation
In `revertResponsesInCaches()`, collect the parent units of **every** unit in `arrResponseUnits` (not just the first) before calling `forgetUnit`, and pass the union of all these parent sets to `fixIsFreeAfterForgettingUnit()` after all units have been forgotten, e.g.:
```js
var allParentUnits = [];
arrResponseUnits.forEach(function(unit) {
    allParentUnits = allParentUnits.concat(storage.assocUnstableUnits[unit].parent_units);
});
arrResponseUnits.forEach(storage.forgetUnit);
storage.fixIsFreeAfterForgettingUnit(_.uniq(allParentUnits));
```
Additionally, add a runtime assertion (similar to the existing `_.isEqual` cache/DB consistency checks in `storage.js`) that periodically validates `assocUnstableUnits[...].is_free` against the DB `is_free` column so any future desync of this kind fails loudly instead of silently persisting.

### Proof of Concept
1. Define AA `A` (primary) whose trigger response posts a payment to AA `B`.
2. Define AA `B` (secondary) whose trigger response posts a payment to AA `C`.
3. Define AA `C` (secondary) that always bounces (e.g., insufficient bounce fee or explicit `bounce()`).
4. Post a trigger unit to `A` with enough funds to reach `B` but engineered so `C` bounces.
5. Observe `handleTrigger` → `handleSecondaryTriggers` → `revert()` fire because the AA chain has more than one response unit (`A`'s and `B`'s responses already exist in `arrResponses` when `C` fails).
6. `revertResponsesInCaches(arrResponses)` is called with `arrResponseUnits = [unitA_response, unitB_response]`; only `unitA_response`'s parents get `fixIsFreeAfterForgettingUnit`, while the parent of `unitB_response` (typically `unitA_response` itself or another unit) never has its in-memory `is_free` flag restored.
7. Query `storage.assocUnstableUnits[<that parent>].is_free` versus the SQL `units.is_free` column for the same unit after the rollback completes — they diverge, and remain diverged for the lifetime of the process (or until `resetUnstableUnits`/restart), demonstrating the corrupted cache state that downstream `conf.bFaster` code paths trust without verification.

### Citations

**File:** aa_composer.js (L1743-1750)
```javascript
				function (err) {
					if (err) {
						// revert
						if (bSecondary)
							return bounce(err);

						return revert({message: "one of secondary AAs bounced with error: ", callChain: {address, next: err}});
					}
```

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

**File:** storage.js (L1557-1561)
```javascript
function readPropsOfUnits(conn, earlier_unit, arrLaterUnits, handleProps){
	var objEarlierUnitProps2 = assocUnstableUnits[earlier_unit] || assocStableUnits[earlier_unit];
	var arrLaterUnitProps2 = arrLaterUnits.map(function(later_unit){ return assocUnstableUnits[later_unit] || assocStableUnits[later_unit]; });
	if (conf.bFaster && objEarlierUnitProps2 && arrLaterUnitProps2.every(function(p){ return !!p; }))
		return handleProps(objEarlierUnitProps2, arrLaterUnitProps2);
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
