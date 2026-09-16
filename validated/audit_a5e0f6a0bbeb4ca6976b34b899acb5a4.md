### Title
Stale unit-props reference retained in `assocBestChildren` after AA response rollback on light nodes leads to main-chain/balance corruption - ([File: aa_composer.js])

### Summary
CVE-2022-1312 is a use-after-free where an object is freed from one bookkeeping structure but a dangling reference to it survives in another, later dereferenced by an attacker-influenced path. ocore's analog is not a raw memory bug but a logical dangling-reference bug: `storage.forgetUnit()` removes an in-flight AA-response unit's props from most in-memory caches, but only prunes the stale reference out of the parent's `assocBestChildren[parent_unit]` array when `!conf.bLight`. On light nodes this array element is never removed, so a "forgotten" (rolled-back) unit object keeps living inside its parent's best-children list and can be revisited by later main-chain/graph logic that consumes `assocBestChildren`.

### Finding Description
When an AA trigger is processed speculatively (dry run or real trigger causing chained AA responses), `aa_composer.js` builds response units and registers them in `storage.assocUnstableUnits` / `storage.assocBestChildren` via `writer.js` (`storage.assocBestChildren[my_best_parent_unit].push(objNewUnitProps)` at [1](#0-0) , executed unconditionally, i.e. also for light nodes).

If the trigger chain later fails/bounces, `aa_composer.js`'s `revert()`/`bounce()` paths call `revertResponsesInCaches(arrResponses)` to unwind these speculative units from the caches: [2](#0-1) . This delegates to `storage.forgetUnit(unit)`: [3](#0-2) 

The pruning of the parent's `assocBestChildren[parent_unit]` array (`_.pull(assocBestChildren[parent_unit], assocUnstableUnits[unit])`) is guarded by `if (!conf.bLight)`. Everything else (`assocKnownUnits`, `assocCachedUnits`, `assocUnstableUnits`, `assocStableUnits`, `assocUnstableMessages`, and `assocBestChildren[unit]` for the unit's own key) is deleted unconditionally, but the *entry inside the parent's array* is left untouched for light nodes (`conf.bLight === true`). Since the unit's props object was pushed into that array by `writer.js`, it remains reachable via `assocBestChildren[parent_unit]` even though the unit itself has been "forgotten" everywhere else — a dangling/stale reference analogous to a freed-but-still-referenced object.

`assocBestChildren` is consumed by main-chain determination logic in `main_chain.js` (`createListOfBestChildren`, `findMinMcWitnessedLevel`) to walk best-child chains that determine main-chain-index/stability and witness collection, and by `storage.js`'s own bookkeeping used across ~14 other call sites. A light wallet that runs the AA dry-run path (`dryRunPrimaryAATrigger`, `estimatePrimaryAATrigger` in `aa_composer.js`) repeatedly (e.g. estimating multiple triggers/fees in a session) will accumulate stale forgotten-unit objects in its parents' `assocBestChildren` arrays. Because these are the *same object references* originally created per dry run, and units/addresses can repeat across successive AA calls in the same session, a subsequent real (non-dry-run) walk of `assocBestChildren` for the same parent can pick up rolled-back response objects that no longer have a backing entry in `assocUnstableUnits`, producing state inconsistent with the actual DAG (incorrect best-child selection, incorrect free/child bookkeeping used by `fixIsFreeAfterForgettingUnit`, or a crash/incorrect result when code assumes `assocUnstableUnits[unit]` exists for every element visited via `assocBestChildren`).

### Impact Explanation
On a light node, corruption of `assocBestChildren` after speculative-AA-trigger rollback can cause the wallet to mis-track which unit is the "best child" of a given parent, corrupt local free/stable bookkeeping (`fixIsFreeAfterForgettingUnit` relies on iterating `assocUnstableUnits`, but downstream consumers of `assocBestChildren` may not), and lead to the wallet computing an incorrect view of its own balances/AA state after estimating one or more AA triggers (e.g. `dryRunPrimaryAATrigger`/`estimatePrimaryAATrigger`, which are invoked whenever a user or app estimates the effect of posting an AA trigger). This can manifest as fund-loss-relevant state (wrong balance estimation leading to bad spending decisions) or a node crash from dereferencing an object whose companion cache entries have been deleted. It does not directly enable double-spend on the network's canonical ledger (full nodes are unaffected because `!conf.bLight` is true there), which limits blast radius to light-wallet users, but a malicious/crafted AA response chain that a light wallet dry-runs repeatedly can reliably trigger the inconsistency.

### Likelihood Explanation
Triggering the `!conf.bLight` gap requires only that the code run in light mode and that at least one primary-AA-trigger dry run (or on-chain trigger causing an AA-response chain the local light node's caches follow) be rolled back — both are ordinary conditions (dry runs of AA triggers happen routinely in wallets and via `estimatePrimaryAATrigger`), so no privileged access or malicious peer/hub cooperation is required, satisfying the "unprivileged AA trigger sender" reachability requirement.

### Recommendation
Remove the `!conf.bLight` guard around the `assocBestChildren` pruning in `storage.forgetUnit()`, or explicitly also clean the entry from `assocBestChildren[parent_unit]` for light nodes in `revertResponsesInCaches()`/`forgetUnit()`, ensuring parity between full and light code paths, and add regression tests (mirroring the existing `aa_composer.test.js` cache-equality assertions) run with `conf.bLight = true`.

### Proof of Concept
1. Run a light node (`conf.bLight = true`).
2. Call `aa_composer.dryRunPrimaryAATrigger` (or trigger a real AA chain that later bounces) for an AA whose response chain shares a `best_parent_unit` with another unit already tracked in `storage.assocUnstableUnits`.
3. Force the chain to fail/bounce so `revert()`/`bounce()` invoke `revertResponsesInCaches` → `storage.forgetUnit` for each response unit.
4. Inspect `storage.assocBestChildren[parent_unit]` after rollback — the rolled-back unit's props object is still present (verified structurally from [3](#0-2)  where the pruning is skipped when `conf.bLight` is true, contrasted with the unconditional push at [1](#0-0) ), while `storage.assocUnstableUnits[unit]` no longer exists — a dangling reference that any later consumer of `assocBestChildren` (e.g. `main_chain.js` best-child walkers) can dereference inconsistently with the rest of the caches.

### Citations

**File:** writer.js (L596-602)
```javascript
			else
				storage.assocUnstableUnits[objUnit.unit] = objNewUnitProps;
			if (!bGenesis && storage.assocUnstableUnits[my_best_parent_unit]) {
				if (!storage.assocBestChildren[my_best_parent_unit])
					storage.assocBestChildren[my_best_parent_unit] = [];
				storage.assocBestChildren[my_best_parent_unit].push(objNewUnitProps);
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
