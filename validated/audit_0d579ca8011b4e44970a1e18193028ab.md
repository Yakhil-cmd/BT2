### Title
Stale balance reads across chained AA triggers permit balance/state race analogous to reentrancy - (File: aa_composer.js)

### Summary
The external report describes a classic "read state after external call" reentrancy in a Solidity `create()` function. The closest reachable analog in ocore is the AA (Autonomous Agent) trigger cascade in `aa_composer.js`, where a primary trigger sent by any unprivileged unit poster can cause a chain of secondary AA triggers (AA calling AA), and balance/state variables are read from shared, mutable structures (`trigger_opts.assocBalances`, `stateVars`) that persist across the whole call chain, with database/state updates interleaved between asynchronous "external calls" (sending units, evaluating formulas, reading state).

### Finding Description
`handleTrigger()` in `aa_composer.js` processes an AA trigger and, for every payment message the AA sends, deducts from a shared `trigger_opts.assocBalances[address][asset]` object [1](#0-0) . This `assocBalances` map is threaded through the whole trigger chain and reused for chained/secondary AA calls via `handleSecondaryTriggers()`, which spreads the same `trigger_opts` (including `assocBalances`) into `child_trigger_opts` and re-enters `handleTrigger()` recursively for each output address that happens to be another AA [2](#0-1) .

Because `handleTrigger` is asynchronous (state formulas are evaluated, units are validated/saved, and balances are updated across several async callbacks such as `executeStateUpdateFormula`, `validateAndSaveUnit`, and `updateFinalAABalances` before `finish`/`addResponse` is reached), and because a single primary trigger can cause the *same* AA address to be invoked more than once within one cascade (an AA sending to itself or to another AA that sends back, as demonstrated by the "chain of AAs" and "issue recently defined asset" test cases where an AA is triggered, forwards funds, and is later re-invoked with `var[trigger.address]` state read back) [3](#0-2) [4](#0-3) , subsequent invocations read `stateVars`/`assocBalances` that were mutated by not-yet-fully-finalized previous invocations in the same cascade.

The "second primary trigger from the same unit" guard illustrates the same read-after-external-effect pattern: it checks `storage.assocStableUnits[trigger.unit].count_aa_responses` to prevent double invocation, but this in-memory cache is only updated after the entire multi-step trigger cascade (batch write + `COMMIT`) completes in `handlePrimaryAATrigger` [5](#0-4) , and the check itself is only performed inside `handleTrigger` per invocation [6](#0-5) , i.e., state is consulted mid-cascade while earlier "external calls" (sub-AA invocations, unit saves) in the same cascade are still in flight.

### Impact Explanation
If balance/state bookkeping for a given AA address is read while an earlier link in the same trigger chain has already mutated `assocBalances`/`stateVars` but has not yet fully committed its response (state update formula, unit validation, and `updateFinalAABalances` all happen asynchronously before `addResponse`/`finish`), a maliciously crafted AA (which any unprivileged unit poster can trigger by simply funding it) could attempt to have a secondary AA invocation observe an intermediate, not-yet-finalized balance state of the same address, leading to overspending of AA balances in a single cascade (loss/inflation of AA funds) or double execution of a payment intended to run once.

### Likelihood Explanation
Reachability is straightforward: any address can post a payment unit to an AA address to originate a primary trigger, and any AA author can define an AA whose `messages` payment outputs point back to itself or to other AAs, creating a chain that re-enters `handleTrigger` for the same address multiple times within one MCI-stabilization cascade — this exact pattern (AA-to-AA, and AA calling back to the trigger's own address) is already exercised by the test suite ("chain of AAs", "issue recently defined asset", "AA with generated definition of new AA and immediately sending to this new AA") [7](#0-6) . However, I could not fully trace `updateInitialAABalances`/`updateFinalAABalances` (only their call sites were found, not their full bodies) to confirm whether they already contain sufficient guards (e.g., re-reading committed DB balances rather than relying purely on the in-memory `assocBalances` snapshot) that would neutralize this race. Given ocore's cascades run fully synchronously per-MCI under a `mutex.lock(['aa_triggers'], ...)` and each trigger's sub-chain resolves in strict `async.eachSeries` order before the next AA in the queue starts [8](#0-7) , it is plausible the existing serialization already prevents true concurrent reentrancy — meaning the impact would depend on a subtle ordering bug within a single cascade rather than genuine concurrent execution.

### Recommendation
- Audit `updateInitialAABalances` and `updateFinalAABalances` (bodies not available in the indexed context) to confirm balances used for spending decisions in `handleTrigger`/`sendDummyUnit`/`sendUnit` are always sourced from finalized, committed state at the time each AA in a cascade is invoked, not from an in-memory snapshot mutated by not-yet-committed sibling invocations in the same cascade.
- Ensure the "second primary trigger from the same unit" check and any per-address balance checks are evaluated against state that reflects all completed mutations of the current cascade, not a stale copy of `assocBalances`/`stateVars` captured before secondary triggers ran.
- Add explicit regression tests where an AA's payment output targets an address that (directly or indirectly) re-invokes the same AA within one primary-trigger cascade, verifying no double-count or negative-balance/overspend condition is possible.

### Proof of Concept
A precise PoC unit/AA sequence cannot be constructed without access to the full bodies of `updateInitialAABalances`/`updateFinalAABalances`, which were not retrievable via the indexed search (only call sites were found). Due to index size limits, some file contents may not be available; a Devin session with full repository access would be needed to inspect these functions line-by-line and construct or rule out a concrete exploit sequence.

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

**File:** aa_composer.js (L101-117)
```javascript
					handleTrigger(conn, batch, trigger, {}, {}, arrDefinition, address, mci, objMcUnit, false, arrResponses, function(){
						conn.query("DELETE FROM aa_triggers WHERE mci=? AND unit=? AND address=?", [mci, unit, address], async function(){
							await conn.query("UPDATE units SET count_aa_responses=IFNULL(count_aa_responses, 0)+? WHERE unit=?", [arrResponses.length, unit]);
							let objUnitProps = storage.assocStableUnits[unit];
							if (!objUnitProps)
								throw Error(`handlePrimaryAATrigger: unit ${unit} not found in cache`);
							if (!objUnitProps.count_aa_responses)
								objUnitProps.count_aa_responses = 0;
							objUnitProps.count_aa_responses += arrResponses.length;
							var batch_start_time = Date.now();
							batch.write({ sync: true }, function(err){
								console.log("AA batch write took "+(Date.now()-batch_start_time)+'ms');
								if (err)
									throw Error("AA composer: batch write failed: "+err);
								conn.query("COMMIT", function () {
									conn.release();
									if (arrResponses.length > 1) {
```

**File:** aa_composer.js (L960-973)
```javascript
			messages.forEach(message => {
				if (message.app !== 'payment')
					return;
				var asset = message.payload.asset || 'base';
				message.payload.outputs.forEach(output => {
					if (output.amount !== 0 && arrOutputAddresses.indexOf(output.address) === -1)
						arrOutputAddresses.push(output.address);
					if (!trigger_opts.assocBalances[address][asset])
						trigger_opts.assocBalances[address][asset] = 0;
					if (output.amount === undefined) // send all
						output.amount = trigger_opts.assocBalances[address][asset];
					// deduct from this AA's balance. It can get negative if we are issuing coins but in this case balance[] is probably meaningless
					trigger_opts.assocBalances[address][asset] -= output.amount;
				});
```

**File:** aa_composer.js (L1702-1741)
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
```

**File:** aa_composer.js (L1860-1863)
```javascript
			// skip this check for dry-run which uses genesis unit as trigger unit
			if (trigger.unit !== constants.GENESIS_UNIT && !trigger_opts.bAir && storage.assocStableUnits[trigger.unit].count_aa_responses && mci >= constants.pemCurvesFixMci)
				return bounce('a second primary trigger from the same unit is not allowed');
		}
```

**File:** test/aa_composer.test.js (L156-253)
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

**File:** test/aa_composer.test.js (L450-526)
```javascript
test.cb.serial('issue recently defined asset', t => {
	var trigger_address = "I2ADHGP4HL6J37NQAD73J7E5SKFIXJOT";
	var trigger = { outputs: { base: 10000 }, data: { define: true }, address: trigger_address };

	// a chain of 3 AA responses
	// 1. define asset, save var['asset'] state var, and send bytes to bouncer AA
	// 2. bouncer reflects the bytes back
	// 3. the 1st AA acts again, it reads the state var and issues the asset

	var bouncer_aa = ['autonomous agent', {
		messages: [
			{
				app: 'payment',
				payload: {
					asset: 'base',
					outputs: [
						{address: "{trigger.address}", amount: "{trigger.output[[asset=base]] - 1000}"}
					]
				}
			},
		]
	}];
	var bouncer_address = objectHash.getChash160(bouncer_aa);
	addAA(bouncer_aa);

	var asset_aa = ['autonomous agent', {
		messages: {
			cases: [
				{
					if: "{trigger.data.define}",
					messages: [
						{
							app: 'asset',
							payload: {
								cap: 1e6,
								is_private: false,
								is_transferrable: true,
								auto_destroy: false,
								fixed_denominations: false,
								issued_by_definer_only: true,
								cosigned_by_definer: false,
								spender_attested: false,
							}
						},
						{
							app: 'payment',
							payload: {
								asset: 'base',
								outputs: [
									{address: bouncer_address, amount: "{trigger.output[[asset=base]] - 1000}"}
								]
							}
						},
						{
							app: 'state',
							state: `{
								var['asset'] = response_unit;
							}`
						}
					]
				},
				{
					if: `{trigger.address == '${bouncer_address}' AND var['asset']}`,
					messages: [{
						app: 'payment',
						payload: {
							asset: "{var['asset']}",
							outputs: [
								{address: "{trigger.initial_address}", amount: "{asset[var['asset']].cap}"}
							]
						}
					}]
				},
			]
		}
	}];
	var asset_address = objectHash.getChash160(asset_aa);
```

**File:** test/aa_composer.test.js (L922-1010)
```javascript
test.cb.serial('AA with generated definition of new AA and immediately sending to this new AA', t => {
	var trigger_address = "I2ADHGP4HL6J37NQAD73J7E5SKFIXJOT";
	var trigger = { outputs: { base: 10000 }, data: { x: 5 }, address: trigger_address };

	var child_aa = ['autonomous agent', {
		bounce_fees: { base: 10000 },
		doc_url: 'https://myapp.com/description.json',
		messages: [
			{
				app: 'payment',
				payload: {
					asset: 'base',
					init: "{response['received_amount'] = trigger.output[[asset=base]];}",
					outputs: [
						{address: "{trigger.initial_address}", amount: "{min(trigger.output[[asset=base]] - 2000, 5000)}"}
					]
				}
			}
		]
	}];
	var child_aa_address = objectHash.getChash160(child_aa);
	
	var factory_aa = ['autonomous agent', {
		init: `{
			$child_aa = ['autonomous agent', {
				bounce_fees: { base: 10000 },
				doc_url: 'https://myapp.com/description.json',
				messages: [
					{
						app: 'payment',
						payload: {
							asset: 'base',
							init: "{response['received_amount'] = trigger.output[[asset=base]];}",
							outputs: [
								{address: "{trigger.initial_address}", amount: "{min(trigger.output[[asset=base]] - 2000, 5000)}"}
							]
						}
					}
				]
			}];
			$child_aa_address = chash160($child_aa);
		}`,
		messages: [
			{
				app: 'definition',
				payload: {
					definition: `{$child_aa}`
				}
			},
			{
				app: 'payment',
				payload: {
					asset: 'base',
					outputs: [{address: `{$child_aa_address}`, amount: 8000}]
				}
			},
			{
				app: 'state',
				state: `{
					var['child_aa1'] = $child_aa_address;
					var['child_aa2'] = unit[response_unit].messages[[.app='definition']].payload.address;
				}`
			}
		]
	}];

	validateAA(factory_aa, err => {
		t.deepEqual(err, null);

		var factory_address = objectHash.getChash160(factory_aa);
		addAA(factory_aa);
		
		aa_composer.dryRunPrimaryAATrigger(trigger, factory_address, factory_aa, (arrResponses) => {
			t.deepEqual(arrResponses.length, 2);
			t.deepEqual(arrResponses[0].bounced, false);
			t.deepEqual(arrResponses[0].updatedStateVars[factory_address].child_aa1.value, child_aa_address);
			t.deepEqual(arrResponses[0].updatedStateVars[factory_address].child_aa2.value, child_aa_address);
			t.deepEqual(arrResponses[0].objResponseUnit.messages.find(function (message) { return (message.app === 'definition'); }).payload.definition, child_aa);
			t.deepEqual(arrResponses[1].objResponseUnit.messages.find(function (message) { return (message.app === 'payment'); }).payload.outputs.find(function (output) { return (output.address === trigger_address); }).amount, 5000);
			fixCache();
			t.deepEqual(storage.assocUnstableUnits, old_cache.assocUnstableUnits);
			t.deepEqual(storage.assocStableUnits, old_cache.assocStableUnits);
			t.deepEqual(storage.assocUnstableMessages, old_cache.assocUnstableMessages);
			t.deepEqual(storage.assocBestChildren, old_cache.assocBestChildren);
			t.deepEqual(storage.assocStableUnitsByMci, old_cache.assocStableUnitsByMci);
			t.end();
		});
	});
});
```
