Based on my investigation, I found a directly analogous bug-class instance to the CVE's pattern (a lookup function that can return an empty/failed result, dereferenced by the caller without a null check).

### Title
Unchecked cache lookup causes TypeError crash when handling a primary AA trigger from a pruned/unknown unit - (File: aa_composer.js)

### Summary
`aa_composer.js`'s `handleTrigger()` dereferences `storage.assocStableUnits[trigger.unit]` without verifying the lookup succeeded, mirroring the `pass_establish()` bug class where `get_ep_from_tid()`'s result is used without a null check.

### Finding Description
When a primary AA trigger is processed, `handleTrigger()` runs a check to prevent a second primary trigger from firing for the same unit: [1](#0-0) 
```
if (trigger.unit !== constants.GENESIS_UNIT && !trigger_opts.bAir && storage.assocStableUnits[trigger.unit].count_aa_responses && mci >= constants.pemCurvesFixMci)
    return bounce('a second primary trigger from the same unit is not allowed');
```
`storage.assocStableUnits` is an in-memory cache of stable unit properties, populated lazily via `readUnitProps()` and pruned/evicted via `forgetUnit()`. [2](#0-1) 
There is no guarantee that `trigger.unit` is present in `assocStableUnits` at the moment `handleTrigger()` runs this check — if the entry was evicted (`forgetUnit`), not yet cached, or if `readUnitProps` chose not to cache it (`sequence !== 'good'`, see `storage.js:1536`), the lookup `storage.assocStableUnits[trigger.unit]` returns `undefined`, and `.count_aa_responses` throws `TypeError: Cannot read properties of undefined`. This is the exact bug class of the CVE: a lookup that can legitimately fail is dereferenced without a guard.

### Impact Explanation
`handleTrigger()` is invoked by `handleAATriggers()` while iterating `aa_triggers` for units that just became stable and target an AA address — this is triggered whenever any unprivileged user posts a payment to an AA address, i.e., fully attacker-reachable by an ordinary unit poster / AA trigger sender. [3](#0-2) 
An uncaught `TypeError` here is thrown synchronously inside the main-chain stabilization / trigger-processing path (`markMcIndexStable` → `handleAATriggers` → `handleTrigger`), which is invoked as part of writing/stabilizing units. An uncaught exception in Node.js will crash the process unless caught by a wrapping handler, which would stop the node from processing further units — satisfying "a network unable to confirm new units" if enough nodes hit the same code path deterministically (since all full nodes process the same AA triggers when the referenced MCI stabilizes).

### Likelihood Explanation
This requires a legitimate condition where `assocStableUnits[trigger.unit]` is absent at the time `handleTrigger` runs — this can occur for full nodes with `conf.bFaster` disabled, for units whose sequence was not 'good' when cached, or after long-running processes evict/prune old cache state. I could not fully verify from the available context whether normal code paths always guarantee this unit is already cached by the time `handleTrigger` executes (e.g., via a prior `readUnitProps` call earlier in the trigger-processing pipeline) — this needs confirmation with a running Devin session that can trace the full call chain from `markMcIndexStable` through `handleAATriggers` and set up a reproduction, and to check whether `bSecondary` calls into `handleTrigger` before `trigger.unit`'s stable props are guaranteed populated.

### Recommendation
Replace the unchecked property access with a guarded lookup, e.g. use `storage.assocStableUnits[trigger.unit] && storage.assocStableUnits[trigger.unit].count_aa_responses`, or explicitly call `storage.readUnitProps(conn, trigger.unit, ...)` to ensure the props are loaded (falling back to DB read) before checking `count_aa_responses`, and treat a missing entry defensively rather than assuming it's always cached.

### Proof of Concept
Not independently reproducible from static analysis alone — a live/instrumented ocore node would be needed to trigger the exact state of `assocStableUnits` (e.g., a fresh full node under `conf.bFaster=false`, or after triggering `forgetUnit()` for the relevant unit) at the moment a second AA-trigger check runs, and this is best explored in a Devin session with source and execution access to the repository.

### Citations

**File:** aa_composer.js (L59-88)
```javascript
function handleAATriggers(onDone) {
	if (!onDone)
		return new Promise(resolve => handleAATriggers(resolve));
	mutex.lock(['aa_triggers'], function (unlock) {
		db.query(
			"SELECT aa_triggers.mci, aa_triggers.unit, address, definition \n\
			FROM aa_triggers \n\
			CROSS JOIN units USING(unit) \n\
			CROSS JOIN aa_addresses USING(address) \n\
			ORDER BY aa_triggers.mci, level, aa_triggers.unit, address",
			function (rows) {
				var arrPostedUnits = [];
				async.eachSeries(
					rows,
					function (row, cb) {
						console.log('handleAATriggers', row.unit, row.mci, row.address);
						var arrDefinition = JSON.parse(row.definition);
						handlePrimaryAATrigger(row.mci, row.unit, row.address, arrDefinition, arrPostedUnits, cb);
					},
					function () {
						arrPostedUnits.forEach(function (objUnit) {
							eventBus.emit('new_aa_unit', objUnit);
						});
						unlock();
						onDone();
					}
				);
			}
		);
	});
```

**File:** aa_composer.js (L1860-1862)
```javascript
			// skip this check for dry-run which uses genesis unit as trigger unit
			if (trigger.unit !== constants.GENESIS_UNIT && !trigger_opts.bAir && storage.assocStableUnits[trigger.unit].count_aa_responses && mci >= constants.pemCurvesFixMci)
				return bounce('a second primary trigger from the same unit is not allowed');
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
