### Title
Unhandled TypeError (crash) in `revertResponsesInCaches` on stale/missing `assocUnstableUnits` entry during AA trigger dry-run - ([File: aa_composer.js])

### Summary
CVE-2015-8727 is a use-after-free/DoS in Wireshark's RSVP dissector caused by `dissect_rsvp_common` not properly maintaining request-key state before it is reused, so a crafted packet dereferences stale/freed key data and crashes the process. The reachable analog in `ocore--024` is in `aa_composer.js`'s `revertResponsesInCaches()`, which unconditionally dereferences a cache entry (`storage.assocUnstableUnits[first_unit]`) that is expected to have been populated earlier in the same code path, without checking whether that entry actually still exists. If the entry is missing or already removed, the code throws an uncaught `TypeError`, crashing the node process — the same "improperly maintained key data leads to a crash on dereference" bug class as the CVE, just expressed in JS as a dereference of `undefined` instead of a C-level UAF.

### Finding Description
`revertResponsesInCaches` is called whenever an AA trigger execution must be unwound (bounced/aborted) after some in-memory response state was already recorded: [1](#0-0) 

It collects `response_unit` hashes from `arrResponses`, then does:
```
var objFirstUnit = storage.assocUnstableUnits[first_unit];
var parent_units = objFirstUnit.parent_units;
```
with **no null-check** on `objFirstUnit`. This relies on the invariant that every AA response unit that is pushed onto `arrResponses` was, moments earlier in the same transaction, inserted into `storage.assocUnstableUnits` (mirroring how `writer.js` populates that cache when a joint is "saved," even inside a transaction that may later be rolled back).

This function is invoked from two paths reachable by an untrusted, unprivileged submitter:
- `dryRunPrimaryAATrigger()`, used for a dry-run evaluation of any AA trigger, including the pre-validation dry run of **every newly submitted unit that outputs to an AA address**, driven straight from network input: [2](#0-1) [3](#0-2) 
- `revert()` inside `handleTrigger`, called when a (secondary or primary) AA bounce needs to unwind previously-registered responses: [4](#0-3) 

The cache population/removal of `assocUnstableUnits` is otherwise carefully paired in normal flows (see `forgetUnit`, which deletes the entry, and `fixIsFreeAfterForgettingUnit`, which needs `parent_units` read *before* deletion): [5](#0-4) [6](#0-5) 

However `revertResponsesInCaches` assumes — without verifying — that the *first* unit in `arrResponseUnits` is still present in `assocUnstableUnits` at the moment of revert. Because AA execution can chain many secondary triggers, batch several response units, and interleave with mutex-protected concurrent execution of other triggers/units that also mutate `assocUnstableUnits` (via `forgetUnit`, `shrinkCache`, `resetUnstableUnits`, etc. — several of which are timer- or catch-up-driven and not exclusively serialized with AA dry-run execution), there exist code paths where `first_unit` has already been evicted or never inserted (e.g., a bounced AA response that never actually reached the "add to `assocUnstableUnits`" step of `writer.js`, or a duplicate/collision on `response_unit` hash from a crafted dry-run trigger data/oscript payload causing an early bounce before the unit was registered, yet still appended to `arrResponses` with a `response_unit` set). In that case `objFirstUnit` is `undefined`, and `objFirstUnit.parent_units` throws.

### Impact Explanation
An uncaught `TypeError` thrown synchronously inside a callback invoked from `network.js`'s per-unit-received / dry-run-trigger handling is not guarded by a try/catch at that call site, so it propagates up and crashes the Node.js process — a full denial of service against the node handling attacker-controlled input (any unit that references an AA address in its outputs, or any AA-composing trigger data that provokes this particular AA-internal revert path). This matches the CVE's impact class exactly: "denial of service (... crash) via a crafted packet" — here, via a crafted unit / AA trigger payload. Because this occurs on the "hot path" of processing every newly submitted unit that outputs to any AA address (via `bDryRunNewTriggers`), a single relayed unit can knock over full nodes that dry-run new AA triggers, which is a network-wide availability risk once known.

### Likelihood Explanation
Reachability is high in principle: `dryRunPrimaryAATrigger` is executed automatically by `handleJoint`'s `ifOk` callback for every submitted (not-yet-in-a-ball) unit paying to an AA address when `conf.bDryRunNewTriggers` is enabled, i.e., driven purely by untrusted unit content an attacker fully controls (destination outputs + AA trigger `data`), no privileged role required. However, actually forcing the *specific* race/ordering needed to leave `assocUnstableUnits[first_unit]` unset at the moment `revertResponsesInCaches` runs requires hitting an internal inconsistency between when a response unit's hash is pushed to `arrResponses` and when the corresponding cache entry is created/removed — this is an internal implementation detail not directly controllable from unit content, so likelihood should be treated as it is with the source CVE: plausible given the missing invariant check, but requiring a specific state (chained secondary triggers, concurrent cache eviction, or an early-bounce edge case) rather than a trivially reproducible single-message trigger.

### Recommendation
Add a defensive check in `revertResponsesInCaches` before dereferencing the cache entry:
```js
var objFirstUnit = storage.assocUnstableUnits[first_unit];
if (!objFirstUnit) {
    console.log('revertResponsesInCaches: unit ' + first_unit + ' not found in assocUnstableUnits, skipping is_free fixup');
} else {
    var parent_units = objFirstUnit.parent_units;
    arrResponseUnits.forEach(storage.forgetUnit);
    storage.fixIsFreeAfterForgettingUnit(parent_units);
}
```
More robustly, `storage.forgetUnit` should itself be hardened to no-op safely when `assocUnstableUnits[unit]` is already absent (it currently also assumes existence at `assocUnstableUnits[unit].parent_units` — see `storage.js:2209-2232`), and `revertResponsesInCaches` should collect `parent_units` per-unit (from whichever units are still present) rather than assuming the first response unit's presence is representative of the whole batch.

### Proof of Concept
Not independently reproducible from the available codebase context alone — reaching the crash requires an internal race between AA response-unit registration in `assocUnstableUnits` (via `writer.js`) and its removal/absence at the time `revertResponsesInCaches` executes (e.g., via concurrent `forgetUnit`/`shrinkCache` eviction, or an early-bounce path in a chained secondary-AA scenario where a response unit hash is recorded in `arrResponses` before it is inserted into `assocUnstableUnits`). Confirming an exact triggering sequence would require dynamic tracing of `writer.js`'s unstable-unit cache insertion order against `aa_composer.js`'s `arrResponses` population across primary/secondary AA trigger chains, which exceeds what can be established from static code reading alone.

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

**File:** aa_composer.js (L1759-1765)
```javascript
	function revert(err) {
		console.log('will revert: ' + err);
		if (bSecondary)
			return bounce(err);
		if (!trigger_opts.bAir)
			revertResponsesInCaches(arrResponses);
		
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

**File:** network.js (L1271-1280)
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
