### Title
Incomplete in-memory cache reconciliation on AA trigger revert corrupts DAG tip (`is_free`) tracking - ([File: aa_composer.js])

### Summary
`ALPINE-CVE-2025-5244` is a memory-corruption bug in binutils' `elf_gc_sweep`, where a garbage-collection *sweep* pass frees/reclaims objects without correctly accounting for all live references, corrupting the linker's bookkeeping. The analogous logic in `ocore` is `revertResponsesInCaches()` in `aa_composer.js`, an in-memory "sweep" that undoes (forgets) DAG unit objects created during an aborted AA-trigger execution chain. It reconciles only a subset of the affected bookkeeping (the parents of the *first* forgotten unit), leaving the rest of the chain's parent/tip (`is_free`) state stale — a bookkeeping-corruption bug reachable by any AA trigger sender.

### Finding Description
When a primary AA trigger causes a chain of secondary AA invocations, each successfully-executing AA in the chain immediately creates and registers a real unit via `validateAndSaveUnit()` → `writer.saveJoint()`. `writer.saveJoint()` mutates global in-memory state for every such unit:
- adds the unit to `storage.assocUnstableUnits[unit]`
- pushes it into `storage.assocBestChildren[best_parent_unit]`
- flips `is_free = 0` on all of its `parent_units` (in DB and in `storage.assocUnstableUnits[parent_unit].is_free`) [1](#0-0) [2](#0-1) 

Each response unit in the chain is composed independently via `pickParents()`, which can select **different** parent units for each AA response unit in the chain (it looks for the most recent AA-chain unit or falls back to distinct MC/AA units) [3](#0-2) .

If any AA later in the chain bounces with an error, `handleSecondaryTriggers()`'s error branch calls `revert()`, which rolls back the whole DB transaction to a savepoint and calls `revertResponsesInCaches(arrResponses)` to manually undo the in-memory side effects that the SQL `ROLLBACK TO SAVEPOINT` cannot undo [4](#0-3) .

`revertResponsesInCaches()` is the sweep routine:
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
``` [5](#0-4) 

It calls `storage.forgetUnit` for **every** response unit (correctly removing each from `assocUnstableUnits`/`assocBestChildren`) [6](#0-5) , but it only recomputes `is_free` for the parents of the **first** response unit, via `fixIsFreeAfterForgettingUnit(parent_units)` [7](#0-6) . Because each response unit in the chain can have distinct `parent_units`, the parent units of the second, third, etc. forgotten response units are never re-scanned. Any parent that was consumed (`is_free` flipped to 0) exclusively by one of those later, now-forgotten units keeps `is_free = 0` forever in the live in-memory cache (`storage.assocUnstableUnits`), even though its only child no longer exists anywhere (DB row rolled back, in-memory unit forgotten).

This is exactly the `elf_gc_sweep` bug class: a sweep/cleanup pass that frees objects (units) but fails to correctly walk all of the resulting dangling/reference-count updates (parent `is_free` states), corrupting the DAG "free-tip" bookkeeping used by main-chain and parent-selection logic (`main_chain.js`'s `SELECT unit FROM units WHERE is_free=1`, `storage.js`'s `determineBestParent`/tip queries) — this cached state diverges from the persisted DB truth after every AA revert of a multi-hop chain, and the divergence is permanent (no code path fixes it later, and periodic `shrinkCache()` doesn't recompute `is_free`, only evicts old entries).

### Impact Explanation
`is_free` governs which units are eligible DAG tips for main-chain traversal (`findNextUpMainChainUnit`) and for choosing parents of new units. A permanently wrong `is_free=0` on a unit that is actually free (no children) can make that unit's parent become unreachable/never re-selected as a tip in the *in-memory* view used by this node, diverging this node's local DAG bookkeeping from what other nodes compute from the DB truth. Depending on how far this corrupted state propagates into stability/main-chain computations that consult the in-memory caches, this can cause this node to disagree with the rest of the network on validity/stability determinations, or to stall composing/advancing its own view of the free-ball set — falling under "node disagreement on validity or stability" / "a network unable to confirm new units" if enough nodes running the same AA chains hit this condition. Because the trigger is any externally-postable AA chain that bounces partway through, this is remotely reachable by an unprivileged trigger sender, not a privileged operator.

### Likelihood Explanation
Reasonably likely: any user can post a payment/trigger to an AA address whose oscript composes a chain calling a second AA, and can craft conditions (e.g. insufficient balance/asset restriction/state check) so that the second (or later) AA in the chain bounces, which is a fully attacker-controlled and common occurrence in AA design (bounces are an expected AA mechanism). No special privileges, timing races, or malicious peer/node behavior are required — a single well-formed unit that triggers a multi-hop AA chain ending in a bounce reliably exercises this code path.

### Recommendation
Fix `revertResponsesInCaches()` to collect and reconcile the `parent_units` of **every** forgotten response unit, not just the first, e.g.:
```js
function revertResponsesInCaches(arrResponses) {
	var arrResponseUnits = arrResponses.filter(r => r.response_unit).map(r => r.response_unit);
	if (arrResponseUnits.length === 0)
		return;
	var arrAllParentUnits = [];
	arrResponseUnits.forEach(function(unit){
		var props = storage.assocUnstableUnits[unit];
		if (props && props.parent_units)
			arrAllParentUnits = arrAllParentUnits.concat(props.parent_units);
	});
	arrResponseUnits.forEach(storage.forgetUnit);
	storage.fixIsFreeAfterForgettingUnit(_.uniq(arrAllParentUnits));
}
```
Capture each unit's `parent_units` *before* calling `forgetUnit` (since `forgetUnit` deletes `assocUnstableUnits[unit]`), then call `fixIsFreeAfterForgettingUnit` once with the union of all parent units across the whole reverted chain.

### Proof of Concept
1. Deploy AA `A` whose oscript sends part of its received bytes to AA `B` (a "chain of AAs" pattern, as used in `test/aa_composer.test.js`'s "chain of AAs" test) [8](#0-7) .
2. Deploy AA `B` such that under certain trigger data it bounces (e.g., insufficient balance for a requested asset, or an explicit `bounce()`), which is standard AA behavior.
3. Post a real (non-dry-run) trigger unit to `A` that causes `A`'s response unit to be created and saved (`writer.saveJoint`, consuming its `parent_units`' `is_free`), then the secondary trigger to `B` to be composed (also saved, consuming a different `parent_units` set), and then `B` bounces, hitting `handleSecondaryTriggers`'s error branch → `revert()` → `revertResponsesInCaches([A_response, B_response])`.
4. After the revert, inspect `storage.assocUnstableUnits[parent]` for `B_response`'s parents — they remain `is_free: 0` even though `B_response` was rolled back and no longer exists in `assocUnstableUnits` or the DB, while `A_response`'s parents were correctly reset to `is_free: 1`.

I was not able to execute this against a running node to directly observe a resulting main-chain/stability failure (that would require running the full network/DB pipeline), so the concrete network-level consequence (stalled tip selection vs. cross-node disagreement) is inferred from how `is_free` is consumed elsewhere (`main_chain.js`, `storage.determineBestParent`) rather than empirically confirmed in this session.

### Citations

**File:** writer.js (L118-127)
```javascript
		else {
			conn.addQuery(arrQueries, "UPDATE units SET is_free=0 WHERE unit IN(?)", [objUnit.parent_units], function(result){
				// in sqlite3, result.affectedRows actually returns the number of _matched_ rows
				var count_consumed_free_units = result.affectedRows;
				console.log(count_consumed_free_units+" free units consumed");
				objUnit.parent_units.forEach(function(parent_unit){
					if (storage.assocUnstableUnits[parent_unit])
						storage.assocUnstableUnits[parent_unit].is_free = 0;
				})
			});
```

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
