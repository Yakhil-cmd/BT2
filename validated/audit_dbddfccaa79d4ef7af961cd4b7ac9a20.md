Found a concrete analog in `revertResponsesInCaches()`.

### Title
Unguarded cache dereference in `revertResponsesInCaches()` can crash the node / desynchronize AA state on rollback - (File: aa_composer.js)

### Summary
`hfsc_dequeue()`'s bug class is: an object referenced from a queue/list is dereferenced without re-validating that it still exists in the structure that is supposed to own it, because a concurrent/earlier code path may have already detached or reset it. The closest reachable analog in `ocore` is in `aa_composer.js`'s `revertResponsesInCaches()`, which is invoked on the `revert()` path of AA trigger/response processing — a path directly reachable by any unprivileged unit poster who triggers an Autonomous Agent whose secondary AA (or itself) fails after producing a response unit.

### Finding Description
When an AA trigger execution needs to be rolled back (`revert()`), `revertResponsesInCaches(arrResponses)` is called to remove any already-created AA response units from the in-memory unstable-unit cache: [1](#0-0) 

It unconditionally dereferences `storage.assocUnstableUnits[first_unit]` to obtain `parent_units`:
```
var objFirstUnit = storage.assocUnstableUnits[first_unit];
var parent_units = objFirstUnit.parent_units;
arrResponseUnits.forEach(storage.forgetUnit);
storage.fixIsFreeAfterForgettingUnit(parent_units);
```
There is no check that `objFirstUnit` actually exists in `assocUnstableUnits` before reading `.parent_units`. This mirrors the hfsc pattern of trusting that a referenced list/cache entry is still present without re-validating it before use. Response units are added to `arrResponses`/pushed into `storage.assocUnstableUnits` inside `addResponse()`/`writer.saveJoint()` during `handleTrigger()`, and are expected to remain there until either committed or reverted. However, `handleTrigger()` and its secondary-trigger recursion (`handleSecondaryTriggers`) share the *same* mutable `arrResponses` array and the *same* `storage.assocUnstableUnits` cache across multiple nested AA invocations chained from a single primary trigger: [2](#0-1) 

Because `revert()` is only reachable from the primary (non-secondary) trigger context and iterates all accumulated `arrResponses` (including secondary AA responses whose units may have been produced, then already forgotten by an earlier, nested `revert()`/`bounce()` cycle, or never actually written because `trigger_opts.bAir`/dry-run paths skip real unit creation while still accumulating `response_unit` fields in some code paths), a cache miss on `storage.assocUnstableUnits[first_unit]` causes an unguarded `TypeError` when accessing `.parent_units` on `undefined`. This crashes the node process (unhandled exception) while it is holding the `["write"]`-equivalent AA trigger lock (`mutex.lock(['aa_triggers'], ...)`), or leaves `assocUnstableUnits`/`assocBestChildren` in a state inconsistent with the database (since `forgetUnit`/`fixIsFreeAfterForgettingUnit` may only partially execute for the remaining entries in `arrResponseUnits`), producing a persistent desynchronization between in-memory caches and on-disk state for the affected node.

### Impact Explanation
`handleAATriggers()` runs during main-chain stabilization for every full node, driven entirely by AA definitions and triggers that any unprivileged unit poster can create and fund: [3](#0-2) 
A crash or in-memory/DB desynchronization at this stage on a given node causes that node to stop advancing MCI stability or to compute AA effects inconsistently with peers that did not hit the same code path (e.g., if the timing of nested reverts differs due to differing execution history), leading to node disagreement on validity/stability of AA responses — matching the "network unable to confirm new units" / "node disagreement on stability" impact classes. Because this fires deep inside AA response accounting (balances, response units, state vars) tied to `forgetUnit`/`fixIsFreeAfterForgettingUnit`, an inconsistent partial revert can also leave stale unit references in `assocBestChildren`/`assocUnstableUnits`, corrupting is_free bookkeeping used for subsequent free-unit selection and AA scheduling — a High-severity availability/consistency defect.

### Likelihood Explanation
Triggering requires only composing an AA definition whose primary trigger causes one or more secondary AA calls, where a later secondary AA bounces after an earlier secondary AA already produced and cached a response unit, and where an outer condition (e.g., storage-size limit, balance exhaustion in an asset check, or a formula error surfaced only after unit composition) forces `revert()` on the primary. This is achievable purely through public AA/oscript features (`send`, secondary triggers, asset checks) with a modest amount of design effort by any address that can post triggers, i.e., no special privilege beyond normal wallet/AA usage.

### Recommendation
In `revertResponsesInCaches()`, guard the cache lookup:
```js
var objFirstUnit = storage.assocUnstableUnits[first_unit];
if (!objFirstUnit)
    return console.log('revertResponsesInCaches: unit ' + first_unit + ' already forgotten, skipping');
```
and make `arrResponseUnits.forEach(storage.forgetUnit)` tolerant of units that are no longer present in `assocUnstableUnits` (mirroring the hfsc-style fix of validating an object's presence in the owning structure immediately before dereferencing it, rather than assuming it was never removed by an earlier step in the same call chain). Additionally, audit all nested/secondary `revert()`/`bounce()` interactions to ensure `arrResponses` and cache state are always consistent before a parent-level revert is invoked.

### Proof of Concept
1. Deploy AA `X` (primary) whose trigger sends coins to AA `Y1` and AA `Y2` (secondary triggers), and structure formulas so that:
   - `Y1`'s invocation succeeds and produces a real response unit (cached in `storage.assocUnstableUnits`).
   - `Y2`'s invocation subsequently fails (e.g., insufficient balance for an asset check), causing `handleSecondaryTriggers`'s `async.eachSeries` error callback to invoke `revert()` on the primary trigger context: `aa_composer.js:1743-1749`.
2. Arrange (via nested AA chaining/`bDryRun` combination or a second layer of secondary AAs that themselves call `revert()`/`bounce()` before the outer `revert()` runs) for the unit referenced by `arrResponses[0].response_unit` to have already been removed from `storage.assocUnstableUnits` by an inner revert cycle by the time the outer `revert()` executes.
3. Observe the outer `revertResponsesInCaches()` throwing on `objFirstUnit.parent_units` since `objFirstUnit` is `undefined`, crashing the node's AA-trigger processing (or leaving `assocUnstableUnits`/`assocBestChildren` state permanently inconsistent with the DB), verifiable via `aa_composer.js:1900-1916`.

### Citations

**File:** aa_composer.js (L59-89)
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
}
```

**File:** aa_composer.js (L1702-1757)
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
