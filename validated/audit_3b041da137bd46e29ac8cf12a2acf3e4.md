Found it: the `revert()` path in `handleTrigger` at line 1764 calls `revertResponsesInCaches(arrResponses)` when a **primary** (non-secondary) trigger's chain of secondary AA triggers bounces. This is reachable directly by an unprivileged AA trigger sender who crafts a trigger causing a chain of secondary AA calls where a later one fails, forcing the top-level `revert()`. [1](#0-0) 

The bug is in `revertResponsesInCaches`: [2](#0-1) 

It only reads `parent_units` from the **first** response unit in `arrResponses` (`arrResponseUnits[0]`), then calls `storage.forgetUnit` on every response unit and finally `storage.fixIsFreeAfterForgettingUnit(parent_units)` using only that single set of parent units. If the AA trigger produced a chain of secondary AA responses (multiple response units, each with different, non-overlapping `parent_units`, since each response unit's parent is normally the previous response unit or a distinct AA-stemming branch), `fixIsFreeAfterForgettingUnit` is never called for the parents of the later units in the chain.

`forgetUnit` itself, however, unconditionally deletes each unit from `assocUnstableUnits`, `assocBestChildren`, `assocStableUnits`, etc: [3](#0-2) 

and it also actively removes the forgotten unit's own props object from its immediate parent's `assocBestChildren[parent_unit]` array using `_.pull`: [4](#0-3) 

So each unit is properly pulled from its own parent's children list, but `fixIsFreeAfterForgettingUnit` — whose job is to flip `is_free = 1` back on for a parent whose only child(ren) were just forgotten — is only invoked for the first response unit's parents. If the second (or later) response unit in the reverted chain had a different, still-cached parent (e.g. a still-unstable earlier unit on the main branch, or its own previous response unit that isn't shared with the first), that parent is left with a stale `is_free = 0` and a dangling entry in `assocUnstableUnits`/`assocBestChildren`, since its only child was just deleted from the in-memory unstable-unit graph but the parent was never told to reconsider its `is_free` status. This is the same class of bug as CVE-2020-0466: a logic error in bookkeeping (missing the analogous "remove and fix up all linked structures" step for every affected node, not just the first one) that leaves the in-memory unit-graph inconsistent with reality — stale references / pointers into freed unstable-unit state.

The reachable, unprivileged trigger for this is `dryRunPrimaryAATrigger` (called for every submitted unit with `bDryRunNewTriggers` when `count_primary_aa_triggers` is set) which calls `handleTrigger` and, on failure, hits `revert()`: [5](#0-4) [6](#0-5) 

as well as the real (non-dry-run) execution path in `handleTrigger`'s own `revert()` at line 1764, triggered whenever any of a chain of secondary AA calls bounces.

### Title
Incomplete cache invalidation after reverting a multi-unit AA response chain leaves stale `is_free`/unstable-unit state - (File: aa_composer.js)

### Summary
When an AA trigger produces more than one response unit across a chain of secondary AA calls and that chain is later reverted (`revert()` in `handleTrigger`), `revertResponsesInCaches()` forgets all response units from the in-memory caches but only recomputes the `is_free` flag for the parents of the *first* response unit. Parents of subsequent response units in the chain are left with a stale `is_free=0` even though their only unstable child was just removed from `storage.assocUnstableUnits`/`assocBestChildren`.

### Finding Description
`revert()` is reached from within `handleTrigger` whenever a chain of secondary AA triggers produces an error and the outer (primary, non-air) trigger must roll back: [7](#0-6) 

It calls `revertResponsesInCaches(arrResponses)`, which is defined as: [2](#0-1) 

The function collects `arrResponseUnits` from every response, then reads `parent_units` from only `storage.assocUnstableUnits[first_unit]` (the first response unit), calls `storage.forgetUnit` on every unit in the chain, and finally calls `storage.fixIsFreeAfterForgettingUnit(parent_units)` using only the first unit's parents.

`forgetUnit` deletes the unit from all in-memory maps and pulls it out of its immediate parent's `assocBestChildren` array: [3](#0-2) 

`fixIsFreeAfterForgettingUnit` is the routine responsible for restoring `is_free=1` on a parent when it no longer has any unstable children left: [8](#0-7) 

Since each secondary AA response unit in the chain is generated with its own `best_parent_unit`/parent set (a new unit is composed for each AA call in the chain, potentially with a different parent lineage from the very first response unit, e.g. when secondary calls fan out or the chain root itself is not the first response unit's parent), calling `fixIsFreeAfterForgettingUnit` with only the first unit's `parent_units` skips fixing up the `is_free` flag for every other forgotten unit's parent that isn't shared with the first one.

### Impact Explanation
An incorrect `is_free=0` on a unit that should be free corrupts the main-chain building queries in `main_chain.js`, which select free units by `is_free=1` to walk the DAG and determine the best parent/main chain tip (`findNextUpMainChainUnit`, `readLastUnitProps`): [9](#0-8) 
A node whose in-memory cache disagrees with the actual free-unit set can compute a different main chain / best parent than a node whose cache is correct, or than what the database itself would compute on a cold read. This is a node-disagreement-on-validity/stability class bug: different nodes (or the same node before/after a cache-rebuilding restart) can diverge on which unit is free and thus on main-chain selection, which feeds directly into stability determination for every subsequent unit.

### Likelihood Explanation
This is reachable by any unprivileged AA trigger sender: simply crafting a trigger that invokes an AA whose secondary AA call(s) fail after at least two response units have already been generated in the call chain (one before the failure) causes `revert()` to run with `arrResponses.length > 1` and parent sets that differ from the first response unit's parents. AA definitions with chained secondary calls are a normal, permitted feature, so no special privilege or race condition is needed—only careful crafting of a bouncing multi-hop AA chain.

### Recommendation
In `revertResponsesInCaches`, collect the `parent_units` for **every** response unit before calling `forgetUnit` (not just the first), and call `storage.fixIsFreeAfterForgettingUnit` with the union of all collected parent sets (or call it once per response unit with that unit's own captured parents), e.g.:
```js
var arrAllParentUnits = [];
arrResponseUnits.forEach(function(unit){
    var props = storage.assocUnstableUnits[unit];
    if (props) arrAllParentUnits = arrAllParentUnits.concat(props.parent_units);
});
arrResponseUnits.forEach(storage.forgetUnit);
storage.fixIsFreeAfterForgettingUnit(_.uniq(arrAllParentUnits));
```

### Proof of Concept
1. Deploy an AA `A` whose formula, on receiving a trigger, sends a payment to AA `B`.
2. Deploy AA `B` whose formula, on receiving a payment from `A`, sends a payment to AA `C`.
3. Deploy AA `C` whose formula deliberately bounces (e.g. references a nonexistent state var or fails a balance check) under attacker-controlled trigger data.
4. Post a unit triggering `A` with data chosen so that `C`'s secondary invocation bounces after `A`'s and `B`'s response units have already been added to `arrResponses` (`bSecondary=true` chain).
5. `handleTrigger`'s `handleSecondaryTriggers` failure path calls `revert(err)` on the primary (non-secondary, non-air) invocation for `A`, which calls `revertResponsesInCaches(arrResponses)` with `arrResponses.length === 2` (units from `A` and `B`).
6. Observe that only the parent(s) of `A`'s response unit are passed to `fixIsFreeAfterForgettingUnit`; the parent of `B`'s response unit (which may differ, e.g. if `B`'s response was generated with parent `[A's response unit]` while `A`'s own parent set is the MC unit) is never re-checked and remains `is_free=0` in memory even though `B`'s response unit — its only child — was already forgotten, leaving `storage.assocUnstableUnits` and the DB `is_free` column out of sync for that unit.

### Citations

**File:** aa_composer.js (L290-300)
```javascript
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

**File:** network.js (L1271-1282)
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
```

**File:** main_chain.js (L46-57)
```javascript
		function readLastUnitProps(handleLastUnitProps){
			conn.query("SELECT unit AS best_parent_unit, witnessed_level \n\
				FROM units WHERE is_free=1 \n\
				ORDER BY witnessed_level DESC, \n\
					level-witnessed_level ASC, \n\
					unit ASC \n\
				",
				async function(rows){
					if (rows.length === 0)
						throw Error("no free units?");
					if (rows.length === 1)
						return handleLastUnitProps(rows[0]);
```
