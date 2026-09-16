### Title
Stale/dangling in-memory unit-cache references during AA response rollback can desynchronize node consensus state - (File: aa_composer.js)

### Summary
The FFmpeg CVE describes a heap-use-after-free where `av_freep()` releases memory that is still referenced and later dereferenced elsewhere. The closest reachable analog in `ocore` is in the AA (Autonomous Agent) trigger/response rollback path, where `revertResponsesInCaches()` frees ("forgets") in-memory unit objects from `storage.assocUnstableUnits` while other in-memory structures (`assocBestChildren`, `is_free` flags of parents) may still hold or expect references to those freed objects, and the parent `is_free` fix-up is computed only from the *first* response unit rather than from every unit actually removed.

### Finding Description
`revertResponsesInCaches()` in `aa_composer.js` is invoked whenever a chain of AA triggers must be rolled back (e.g. from `revert()` at [1](#0-0) , and from `dryRunPrimaryAATrigger()` used by the network-reachable `light/dry_run_aa` command at [2](#0-1) ): [3](#0-2) 

It reads `parent_units` only from `storage.assocUnstableUnits[first_unit]` (the first response unit in the chain), then calls `storage.forgetUnit()` on *every* response unit, and finally calls `storage.fixIsFreeAfterForgettingUnit(parent_units)` using only that first unit's parents. `forgetUnit()` itself deletes the unit's entry from `assocUnstableUnits`, `assocCachedUnits`, `assocBestChildren`, etc., and tries to pull the unit's object reference out of its parent's `assocBestChildren` array by object identity: [4](#0-3) .

Because a chain of AA responses forms a linear parent→child relationship (each secondary AA's response unit is built on top of the previous response unit, see `handleSecondaryTriggers`/`pickParents` at [5](#0-4)  and [6](#0-5) ), `forgetUnit` is invoked oldest-unit-first. When an inner/child unit is forgotten, its `parent_units` array still contains the *already-forgotten* parent unit, but that parent's `assocBestChildren` entry (and the object it would need to be pulled from) has already been deleted. The cleanup silently no-ops for that stale reference, and — critically — `fixIsFreeAfterForgettingUnit` is only ever called with the outer-most parent's `parent_units`, never re-run for any intermediate unit that might have external children/parents outside the reverted response chain (e.g., if a concurrent unit briefly attached to one of the intermediate response units before rollback). This leaves `is_free` flags and `assocBestChildren` bookkeeping in a state that does not fully correspond to any of the objects still resident in memory — a logic-level analog of using a data structure after part of its referenced state has been freed, rather than a memory-safety crash.

### Impact Explanation
If `is_free`/`assocBestChildren` bookkeeping becomes inconsistent after a rolled-back AA chain (particularly under `dryRunPrimaryAATrigger`, reachable by any unprivileged peer via `light/dry_run_aa`, and under real AA-trigger rollbacks reachable by any unit poster whose payment triggers a chain of AAs that ultimately bounces), a node's view of which units are "free" (candidates for pruning/best-parent selection) can diverge from other nodes' views. This class of bug maps to "node disagreement on validity or stability" — the acceptable impact category for this analog — because best-parent/witness-level selection and unit pruning both depend on `is_free` and `assocBestChildren` being accurate.

### Likelihood Explanation
Triggering the rollback path itself is trivial and unprivileged: any user can post a payment that invokes a chain of two or more AAs where a later AA in the chain bounces, forcing `revert()`/`revertResponsesInCaches()` to run, or can send a `light/dry_run_aa` request with a trigger that produces a multi-hop AA response chain and then bounces or completes (both call `revertResponsesInCaches`/similar cache mutation). However, actually causing a *visible* stability/consensus divergence requires a specific interleaving (e.g., a real unit briefly attaching to one of the intermediate, soon-to-be-forgotten response units before the rollback completes) that I could not fully confirm is reachable given available code — `handleTrigger`/`dryRunPrimaryAATrigger` run under the `write` mutex and inside DB transactions that get rolled back, which likely (but not certainly, from what I could inspect) prevents other code from observing the intermediate state. I was not able to fully trace all callers/timing of `mutex.lock(["write"])` acquisition relative to `revertResponsesInCaches` to rule this out with certainty.

### Recommendation
- In `revertResponsesInCaches()`, compute and pass parent_units for *every* forgotten unit (not just the first), or call `storage.fixIsFreeAfterForgettingUnit` once per unit inside the loop using that unit's own `parent_units` captured before deletion.
- Ensure `forgetUnit()` is only ever invoked while holding the `write` mutex for the full duration of the multi-unit forget sequence, and audit all callers (`revertResponsesInCaches`, `purgeUncoveredNonserialJoints`, `shrinkCache`) to guarantee no other code path can read `assocUnstableUnits`/`assocBestChildren` mid-sequence.
- Add invariant assertions (as already partially done via `fixIsFreeAfterForgettingUnit`) that verify no dangling references to forgotten unit objects remain in `assocBestChildren` after a rollback completes.

### Proof of Concept
Not fully constructible from static analysis alone: reproducing observable impact requires triggering `dryRunPrimaryAATrigger` or a real bounced multi-hop AA chain (as in `test/aa_composer.test.js` "chain of AAs" test at [7](#0-6) , which already exercises `revertResponsesInCaches`/cache-equality checks) while concurrently attempting to attach a new unit to one of the intermediate response units before rollback finishes, then asserting on `storage.assocBestChildren`/`is_free` consistency across two nodes. I could not verify with full certainty (given tool/index limitations) that such concurrent attachment is actually reachable before the `write` mutex is released, so this should be validated with a live/dynamic test in a Devin session rather than treated as fully confirmed exploitability.

### Citations

**File:** aa_composer.js (L290-299)
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
```

**File:** aa_composer.js (L875-907)
```javascript
	function pickParents(handleParents) {
		if (trigger_opts.bAir)
			throw Error("pickParents shouldn't be called with bAir");
		// first look for a chain of AAs stemming from the MC unit
		conn.query(
			"SELECT units.unit \n\
			FROM units CROSS JOIN unit_authors USING(unit) CROSS JOIN aa_addresses USING(address) \n\
			WHERE latest_included_mc_index=? AND aa_addresses.mci<=? \n\
			ORDER BY level DESC LIMIT 1",
			[mci, mci],
			function (rows) {
				if (rows.length > 0)
					return handleParents([rows[0].unit]);
				// next, check if there is an AA stemming from a recent MCI
				conn.query(
					"SELECT units.unit, latest_included_mc_index \n\
					FROM units CROSS JOIN unit_authors USING(unit) CROSS JOIN aa_addresses USING(address) \n\
					WHERE (main_chain_index>? OR main_chain_index IS NULL) AND aa_addresses.mci<=? \n\
					ORDER BY latest_included_mc_index DESC, level DESC LIMIT 1",
					[mci, mci],
					function (rows) {
						if (rows.length > 0) {
							var row = rows[0];
							if (row.latest_included_mc_index >= mci)
								throw Error("limci of last AA > mci");
							return handleParents([row.unit, objMcUnit.unit].sort());
						}
						handleParents([objMcUnit.unit]);
					}
				);
			}
		);
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

**File:** test/aa_composer.test.js (L156-252)
```javascript
test.cb.serial('chain of AAs', t => {
	var trigger_address = "I2ADHGP4HL6J37NQAD73J7E5SKFIXJOT";
	var trigger = { outputs: { base: 40000 }, data: { x: 333 }, address: trigger_address };

	var secondary_aa = ['autonomous agent', {
		bounce_fees: { base: 10000 },
		messages: [
			{
				app: 'payment',
				payload: {
					asset: 'base',
					outputs: [
						{address: "{trigger.initial_address}", amount: "{trigger.output[[asset=base]] - 2000}"}
					]
				}
			},
			{
				app: 'state',
				state: `{
					var['who'] = trigger.address || timestamp;
					var['initial'] = trigger.initial_address || timestamp;
					var['initial_unit'] = trigger.initial_unit;
					var['large_num2'] = var[trigger.address]['large_num'] + 1;
					var['long_num2'] = var[trigger.address]['long_num'] + 1;
					var['number_of_responses'] = number_of_responses;
					var['previous_aa_responses_trigger_address'] = previous_aa_responses[0].trigger_address;
					var['previous_aa_responses_unit'] = previous_aa_responses[0].unit_obj.unit;
				}`
			}
		]
	}];
	var secondary_address = objectHash.getChash160(secondary_aa);
	addAA(secondary_aa);

	var primary_aa = ['autonomous agent', {
		bounce_fees: { base: 10000 },
		messages: [
			{
				app: 'payment',
				payload: {
					asset: 'base',
					outputs: [
						{address: secondary_address, amount: "{trigger.output[[asset=base]] - 1000}"}
					]
				}
			},
			{
				app: 'state',
				state: `{
					var['who'] = trigger.address || timestamp;
					var['initial'] = trigger.initial_address || timestamp;
					var['large_num'] = 1e15;
					var['long_num'] = 0.000678901234567;
				}`
			}
		]
	}];
	var primary_address = objectHash.getChash160(primary_aa);
	addAA(primary_aa);
	
	aa_composer.dryRunPrimaryAATrigger(trigger, primary_address, primary_aa, (arrResponses) => {
		t.deepEqual(arrResponses.length, 2);
		t.deepEqual(arrResponses[0].aa_address, primary_address);
		t.deepEqual(arrResponses[0].bounced, false);
		t.deepEqual(arrResponses[0].response.error, undefined);
		t.deepEqual(arrResponses[0].objResponseUnit.messages.find(function (message) { return (message.app === 'payment'); }).payload.outputs.find(function (output) { return (output.address === secondary_address); }).amount, 39000);
		t.deepEqual(arrResponses[0].updatedStateVars[primary_address], {
			who: { value: trigger_address + arrResponses[0].objResponseUnit.timestamp },
			initial: { value: trigger_address + arrResponses[0].objResponseUnit.timestamp },
			large_num: { value: 1e15 },
			long_num: { value: 0.000678901234567 },
		});
		t.deepEqual(arrResponses[0].updatedStateVars[secondary_address], {
			who: { value: primary_address + arrResponses[1].objResponseUnit.timestamp },
			initial: { value: trigger_address + arrResponses[1].objResponseUnit.timestamp },
			initial_unit: { value: arrResponses[0].trigger_unit },
			number_of_responses: { value: 1 },
			previous_aa_responses_trigger_address: { value: trigger_address },
			previous_aa_responses_unit: { value: arrResponses[0].response_unit },
			large_num2: { value: 1e15 }, // the same due to loss of precision
			long_num2: { value: 1.00067890123457 }, // rounded to 15 significant digits (but uses cached vars)
		});
		
		t.deepEqual(arrResponses[1].aa_address, secondary_address);
		t.deepEqual(arrResponses[1].bounced, false);
		t.deepEqual(arrResponses[1].response.error, undefined);
		t.deepEqual(arrResponses[1].objResponseUnit.messages.find(function (message) { return (message.app === 'payment'); }).payload.outputs.find(function (output) { return (output.address === trigger_address); }).amount, 37000);
		t.deepEqual(arrResponses[1].updatedStateVars, undefined);
		
		t.deepEqual(storage.assocUnstableUnits, old_cache.assocUnstableUnits);
		t.deepEqual(storage.assocStableUnits, old_cache.assocStableUnits);
		t.deepEqual(storage.assocUnstableMessages, old_cache.assocUnstableMessages);
		t.deepEqual(storage.assocBestChildren, old_cache.assocBestChildren);
		t.deepEqual(storage.assocStableUnitsByMci, old_cache.assocStableUnitsByMci);
		t.end();
	});
});
```
