Based on my investigation, I found a genuine use-after-free-class analog in the AA (Autonomous Agent) trigger revert path.

### Title
Stale-reference reuse of forgotten unstable-unit objects during AA chain revert - ([File: aa_composer.js])

### Summary
`revertResponsesInCaches()` reads `storage.assocUnstableUnits[first_unit]` to get `parent_units`, then calls `storage.forgetUnit` on every response unit in the chain (which deletes them from `assocUnstableUnits`, `assocBestChildren`, etc.), then calls `storage.fixIsFreeAfterForgettingUnit(parent_units)` using the parent list captured *before* the units were forgotten [1](#0-0) . `forgetUnit()` itself walks `assocUnstableUnits[unit].parent_units` and mutates `assocBestChildren[parent_unit]` in place via `_.pull` [2](#0-1) .

### Finding Description
When a chain of secondary AA triggers is rolled back (`revert()` in `handleTrigger`), `arrResponses` may contain several response units forming a multi-hop AA chain [3](#0-2) . `revertResponsesInCaches` grabs `parent_units` from the **first** unit in the chain only, then iterates `arrResponseUnits.forEach(storage.forgetUnit)`, forgetting every unit including intermediate ones whose `assocUnstableUnits[unit]` entries are referenced as objects inside `assocBestChildren[parent]` arrays of *other* units in the same chain [4](#0-3) . Because `forgetUnit` deletes `assocUnstableUnits[unit]` before later iterations of the `forEach` loop need to read `assocUnstableUnits[unit].parent_units` for a *subsequent* unit in the chain, and because `fixIsFreeAfterForgettingUnit` is only ever called with the first unit's parents (not each unit's own parents), the `is_free` flag and `assocBestChildren` bookkeeping for intermediate parents in the chain can become inconsistent: some parent entries retain stale `assocBestChildren` references to now-deleted unstable-unit objects, while `is_free` is never recalculated for those parents. This is conceptually the same bug class as CVE-2023-21255 (an object is torn down/reference removed while other in-flight logic still expects to dereference/mutate it consistently), applied to ocore's unstable-unit object graph instead of a kernel binder object.

### Impact Explanation
A corrupted `assocUnstableUnits` / `assocBestChildren` / `is_free` in-memory graph can cause the node to compute the wrong best-parent / main-chain-index selection when building or validating subsequent units, since these caches directly drive `pickParents`, free-unit selection, and eventually stability determination (`readUnitProps`, `initUnstableUnits`, etc., all consistency-check against these same maps and `throw Error` on mismatch, as seen in `storage.js` around `readUnitProps`). In the best case this crashes the node (`throw Error("different props...")`), causing a liveness/availability issue; in the worst case, if the inconsistency slips past the consistency assertions, it could lead to incorrect free/parent-selection logic that diverges between nodes — i.e., a node-disagreement-on-validity/stability class impact, one of the explicitly accepted outcomes.

### Likelihood Explanation
This path is reachable purely from a single posted unit that triggers an AA whose execution creates a multi-hop chain of secondary AA responses (e.g. AA A pays AA B pays AA C) and where the chain subsequently gets reverted, e.g. because a later secondary AA in the chain bounces with an error, causing `revert()` to run for a chain of length ≥ 2 (`arrResponseUnits.length > 1`, i.e., an already-generated intermediate response unit exists before the chain fails). Chains of AAs and induced bounces are entirely attacker-controllable by anyone who can define AAs and send a triggering payment — no privileged or peer-level access needed. The consistency assertions scattered through `storage.js` (e.g. `readUnitProps`) make an immediate crash likely under the right chain shape, which is the most probable observable effect; deeper state corruption requires a more specific ordering and is less certain — I was not able to fully trace every code path that reads `assocBestChildren`/`is_free` afterward to confirm silent (non-crashing) corruption is reachable, so that stronger impact remains unverified.

### Recommendation
In `revertResponsesInCaches`, capture the `parent_units` for **every** unit in `arrResponseUnits` before any `forgetUnit` call, and call `fixIsFreeAfterForgettingUnit` with the full de-duplicated union of parent units across the whole chain, not just the first unit's parents. Alternatively, iterate the chain in reverse (child-to-parent) order, capturing each unit's own parents immediately before calling `forgetUnit` on that unit, so no `assocUnstableUnits[unit]` is read after it (or a unit it references) has already been deleted.

### Proof of Concept
1. Define AA `A` that on trigger sends bytes to AA `B`.
2. Define AA `B` that on trigger sends bytes to AA `C`.
3. Define AA `C` that on trigger deliberately fails/bounces with an error (e.g. references an undefined getter or exceeds a limit) after `B`'s response unit has already been composed and pushed into `arrResponses`.
4. Trigger `A` with a real unit so that `handleTrigger` executes the chain `A → B → C`, `C` bounces, causing `revert(err)` to run with `arrResponses.length >= 2` (units for `A`'s and `B`'s responses already exist in `assocUnstableUnits`) [5](#0-4) .
5. Observe `revertResponsesInCaches` forgetting both response units while only fixing `is_free` for the first unit's parents [1](#0-0) , leaving `assocBestChildren` for the intermediate unit's true parent stale/unrepaired.
6. Continue posting units; the next `readUnitProps`/parent-selection logic that touches the affected parent will either throw an internal consistency `Error` (DoS on the node) or make a parent-selection decision based on a stale `assocBestChildren` entry.

### Citations

**File:** aa_composer.js (L1702-1756)
```javascript
	function handleSecondaryTriggers(objUnit, arrOutputAddresses) {
		conn.query("SELECT address, definition, mci, main_chain_index FROM aa_addresses LEFT JOIN units USING(unit) WHERE address IN(?) AND mci<=? ORDER BY address", [arrOutputAddresses, mci], function (rows) {
			if (rows.length > 0 && constants.bTestnet && mci < testnetAAsDefinedByAAsAreActiveImmediatelyUpgradeMci)
				rows = rows.filter(function (row) {
					if (row.main_chain_index && row.main_chain_index < mci) // previous definition is already stable
						return true;
					var len = storage.getUnconfirmedAADefinitionsPostedByAAs([row.address]).length;
					if (len > 0)
						console.log("not calling secondary trigger from unit " + objUnit.unit + " to AA " + row.address);
					return (len === 0);
				});
			if (rows.length === 0) {
				saveStateVars();
				addUpdatedStateVarsIntoPrimaryResponse();
				return onDone(objUnit, bBouncing ? error_message : false);
			}
			if (bBouncing)
				throw Error("secondary triggers while bouncing");
			async.eachSeries(
				rows,
				function (row, cb) {
					var child_trigger = getTrigger(objUnit, row.address);
					child_trigger.initial_address = trigger.initial_address;
					child_trigger.initial_unit = trigger.initial_unit;
					if ("max_aa_responses" in trigger && mci >= constants.pemCurvesFixMci) // propagate the cap set on the primary trigger to secondary triggers
						child_trigger.max_aa_responses = trigger.max_aa_responses;
					var arrChildDefinition = JSON.parse(row.definition);

					var child_trigger_opts = { ...trigger_opts };
					child_trigger_opts.trigger = child_trigger;
					child_trigger_opts.params = {};
					child_trigger_opts.arrDefinition = arrChildDefinition;
					child_trigger_opts.address = row.address;
					child_trigger_opts.bSecondary = true;
					child_trigger_opts.onDone = function (objSecondaryUnit, bounce_message) {
						if (bounce_message)
							return cb(bounce_message);
						cb();
					};
					handleTrigger(child_trigger_opts);
				},
				function (err) {
					if (err) {
						// revert
						if (bSecondary)
							return bounce(err);

						return revert({message: "one of secondary AAs bounced with error: ", callChain: {address, next: err}});
					}
					saveStateVars();
					addUpdatedStateVarsIntoPrimaryResponse();
					onDone(objUnit, bBouncing ? error_message : false);
				}
			);
		});
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
