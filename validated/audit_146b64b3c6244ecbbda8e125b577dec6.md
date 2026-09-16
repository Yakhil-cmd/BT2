### Title
Unchecked property access on `storage.assocStableUnits[trigger.unit]` causes AA-composer crash for secondary/child AA triggers - ([File: aa_composer.js])

### Summary
`handleTrigger()` in `aa_composer.js` dereferences `storage.assocStableUnits[trigger.unit].count_aa_responses` without first checking that `storage.assocStableUnits[trigger.unit]` is defined, mirroring the free5GC bug class where an `interface{}` value pulled from a map/cache is used without a nil/undefined check before further access, causing a crash (CWE-476).

### Finding Description
In `handleTrigger()`: [1](#0-0) 

```
// skip this check for dry-run which uses genesis unit as trigger unit
if (trigger.unit !== constants.GENESIS_UNIT && !trigger_opts.bAir && storage.assocStableUnits[trigger.unit].count_aa_responses && mci >= constants.pemCurvesFixMci)
    return bounce('a second primary trigger from the same unit is not allowed');
```

This line accesses `.count_aa_responses` directly on `storage.assocStableUnits[trigger.unit]` without checking whether that lookup returned an object. Elsewhere in the same file, the codebase explicitly guards against this same map returning `undefined` and treats it as a fatal condition: [2](#0-1) 

```
let objUnitProps = storage.assocStableUnits[unit];
if (!objUnitProps)
    throw Error(`handlePrimaryAATrigger: unit ${unit} not found in cache`);
```

Critically, `handleTrigger()` is re-entered recursively for **secondary triggers** — AA-to-AA calls triggered when one AA's response unit pays out to another AA address, via `handleSecondaryTriggers()`: [3](#0-2) 

Here `child_trigger = getTrigger(objUnit, row.address)` builds a new trigger whose `.unit` is the just-composed (not-yet-stable, not-yet-in-`assocStableUnits`) response unit of the parent AA: [4](#0-3) 

Since secondary/chained AA triggers use a freshly composed response unit as `trigger.unit`, and that unit has not been inserted into `storage.assocStableUnits` at the time `handleTrigger()` re-enters the guard at line 1861, `storage.assocStableUnits[trigger.unit]` can legitimately be `undefined`, and `.count_aa_responses` on `undefined` throws a `TypeError`, crashing the AA-composition pipeline the same way the nil-interface conversion crashes AUSF's `GetSupiFromSuciSupiMap`.

### Impact Explanation
A `TypeError: Cannot read properties of undefined (reading 'count_aa_responses')` thrown inside `handleTrigger()` is not caught anywhere in the surrounding `async`/callback chain in `handleAATriggers()` / `handlePrimaryAATrigger()`, so it propagates as an unhandled exception in the node process handling AA trigger processing — the same "unprivileged unit poster ⇒ crash the service" pattern as the AUSF advisory. Because AA trigger execution is central to the network's ability to process and stabilize units containing AA payments/chained AA calls, a crash here can prevent the node from continuing to process pending AA triggers, i.e., a "network unable to confirm new units" condition for chains involving AAs. Any address that is a target of an AA-to-AA payment (any AA author defining a chained-call setup) can, by composing a chain of AA calls, drive `handleTrigger` into this unguarded path.

### Likelihood Explanation
Reaching this code requires `mci >= constants.pemCurvesFixMci` and `trigger.unit !== constants.GENESIS_UNIT` and `!trigger_opts.bAir`, and specifically a **secondary** trigger whose triggering unit is the AA composer's own not-yet-committed response unit. The exact conditions under which `storage.assocStableUnits[trigger.unit]` is populated for the just-composed response unit (e.g., whether it's pre-inserted earlier in the same `handleTrigger` flow before this check executes) could not be fully confirmed from the available code excerpts — the population/timing of `assocStableUnits` entries relative to `sendUnit`/response-unit composition would need to be traced further (e.g., in `writer.js`/`main_chain.js`) to determine definitively whether this path is reachable in practice or whether an earlier assignment always guarantees the entry exists before this check runs.

### Recommendation
Add an explicit existence check before dereferencing, mirroring the pattern already used at line 104-106:
```js
const objTriggerUnitProps = storage.assocStableUnits[trigger.unit];
if (trigger.unit !== constants.GENESIS_UNIT && !trigger_opts.bAir && objTriggerUnitProps && objTriggerUnitProps.count_aa_responses && mci >= constants.pemCurvesFixMci)
    return bounce('a second primary trigger from the same unit is not allowed');
```
This preserves the intended duplicate-trigger check while avoiding the crash if the cache entry is absent.

### Proof of Concept
Not fully constructible from the indexed code alone: reproducing the crash requires confirming the exact ordering between when `storage.assocStableUnits` is populated for a freshly-composed AA response unit and when `handleSecondaryTriggers` re-invokes `handleTrigger` for that unit as `trigger.unit` — this ordering could not be verified with the available tool access and would need direct execution/tracing (e.g., a Devin session with runtime access) to confirm whether the guard at `aa_composer.js:1861` is actually hit with an undefined cache entry in a live chained-AA-call scenario.

### Citations

**File:** aa_composer.js (L104-106)
```javascript
							let objUnitProps = storage.assocStableUnits[unit];
							if (!objUnitProps)
								throw Error(`handlePrimaryAATrigger: unit ${unit} not found in cache`);
```

**File:** aa_composer.js (L375-397)
```javascript
function getTrigger(objUnit, receiving_address) {
	var trigger = { address: objUnit.authors[0].address, unit: objUnit.unit, outputs: {} };
	if ("max_aa_responses" in objUnit)
		trigger.max_aa_responses = objUnit.max_aa_responses;
	objUnit.messages.forEach(function (message) {
		if (message.app === 'data' && !trigger.data) // use the first data message, ignore the subsequent ones
			trigger.data = message.payload;
		else if (message.app === 'payment' && message.payload) {
			var payload = message.payload;
			var asset = payload.asset || 'base';
			payload.outputs.forEach(function (output) {
				if (output.address === receiving_address) {
					if (!trigger.outputs[asset])
						trigger.outputs[asset] = 0;
					trigger.outputs[asset] += output.amount; // in case there are several outputs
				}
			});
		}
	});
	if (Object.keys(trigger.outputs).length === 0)
		throw Error("no outputs to " + receiving_address);
	return trigger;
}
```

**File:** aa_composer.js (L1720-1741)
```javascript
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
```

**File:** aa_composer.js (L1860-1862)
```javascript
			// skip this check for dry-run which uses genesis unit as trigger unit
			if (trigger.unit !== constants.GENESIS_UNIT && !trigger_opts.bAir && storage.assocStableUnits[trigger.unit].count_aa_responses && mci >= constants.pemCurvesFixMci)
				return bounce('a second primary trigger from the same unit is not allowed');
```
