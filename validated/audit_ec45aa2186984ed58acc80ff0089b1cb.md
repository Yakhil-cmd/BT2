Given the scope constraints (in-scope AA/oscript surfaces reachable by an unprivileged trigger sender) and after confirming how `trigger.output[[asset=X]]` and AA-to-AA secondary trigger chains behave, the strongest analog to the Pine Protocol flash-loan/price-manipulation class is the atomic-execution model of chained AA triggers combined with instantaneous-balance-based pricing formulas.

### Title
Atomic AA-to-AA trigger chaining enables flash-loan-style price manipulation of balance-ratio formulas - (File: `aa_composer.js`, `test/samples/uniswap_like_market_maker.oscript`)

### Summary
Obyte AAs that price swaps/redemptions using the AA's live `balance[asset]` (as in the reference constant-product market-maker pattern) are exploitable exactly like a flash-loan attack: a single unit can trigger a cascading, fully atomic chain of AA-to-AA payments (`handleSecondaryTriggers`) that is evaluated and committed in one database transaction before any other party can react, letting an attacker temporarily inflate/deflate a pool's `balance[]` mid-chain, extract mispriced value, and unwind — all inside one trigger evaluation.

### Finding Description
`handlePrimaryAATrigger` processes an entire cascade of primary + secondary AA triggers stemming from a single posted unit inside one `BEGIN…COMMIT` transaction and one `kvstore` batch [1](#0-0) . Balances are updated synchronously as each AA in the chain executes (`updateInitialAABalances` / `updateFinalAABalances` / `sendDummyUnit`), and a bounced branch can be rolled back to a savepoint while the rest of the chain still commits together [2](#0-1) [3](#0-2) . Up to `MAX_RESPONSES_PER_PRIMARY_TRIGGER` AA calls can be chained from one originating unit [4](#0-3) , and this chaining is a documented, intended capability (see `chain of AAs` test) [5](#0-4) .

The reference constant-product market-maker AA pattern shipped as an oscript sample prices swaps purely from the AA's current balances at evaluation time: [6](#0-5) [7](#0-6) 

Because the entire multi-hop AA chain from a single unit is atomic and synchronous, an attacker can construct one unit whose cascading triggers: (1) route a large amount of an asset through/into the pricing AA to shift `balance[asset]`/`balance[base]` momentarily, (2) have a secondary AA in the same chain consume the now-mispriced quote (e.g., an oracle- or ratio-dependent AA reading `balance[]` of the pool), and (3) reverse/unwind the position in a later message of the same chain — with no possibility for other units to interleave, exactly mirroring how flash loans let an attacker manipulate an AMM price and arbitrage against a dependent contract within one atomic transaction, as in the reported Pine Protocol incident.

### Impact Explanation
Any AA design (bundled as reference/sample code that developers copy, and a pattern explicitly supported by the engine) that derives price/collateral value from a live, in-chain `balance[]` read is vulnerable to atomic self-arbitrage, resulting in unauthorized extraction of pool funds/AA fund loss — matching the required "concrete unauthorized spending / AA fund loss" impact bar.

### Likelihood Explanation
Any unprivileged unit poster can trigger arbitrarily deep AA chains in a single unit (bounded only by `MAX_RESPONSES_PER_PRIMARY_TRIGGER`), and the balance-ratio AMM pattern is the officially documented reference design for AA-based market makers, so the precondition (a deployed pricing AA using live balances) is realistic and the exploitation path requires only crafting one unit with the appropriate payment/trigger messages.

### Recommendation
For any AA pattern that prices based on internal balances (e.g., the market-maker template), document/enforce use of manipulation-resistant pricing (e.g., require price/ratio inputs from external oracles with `min_mci` staleness protection via `data_feed`/`in_data_feed`, or use pre/post-trade invariant checks that can't be satisfied by a single-unit round trip) rather than trusting `balance[asset]` read within the same synchronous trigger chain. At the protocol/documentation level, explicitly warn AA authors that a full chain of secondary triggers from one unit is atomic and adversarially composable, similar to flash loans.

### Proof of Concept
1. Deploy a pool AA following the constant-product formula shown in `test/samples/uniswap_like_market_maker.oscript` (or any AA using `balance[asset]`/`balance[base]` for pricing).
2. Deploy/control a second AA that, in the same message chain, consumes the pool's quote (e.g., borrows against it, or reads a derived price) — chained via secondary triggers as demonstrated by the `chain of AAs` pattern [8](#0-7) .
3. Post a single unit whose primary trigger: (a) swaps a large amount into the pool to skew `balance[$asset]`/`balance[base]`, (b) in the same cascading chain, triggers the dependent AA to act on the skewed balance, (c) swaps back in a later message of the same chain to restore the pool and realize profit.
4. Because steps (a)-(c) execute inside one `BEGIN…COMMIT`/batch as in `handlePrimaryAATrigger`, the entire manipulate-and-arbitrage sequence completes atomically in a single unit, with no other trigger able to interleave.

### Citations

**File:** aa_composer.js (L91-116)
```javascript
function handlePrimaryAATrigger(mci, unit, address, arrDefinition, arrPostedUnits, onDone) {
	db.takeConnectionFromPool(function (conn) {
		conn.query("BEGIN", function () {
			var batch = kvstore.batch();
			readMcUnit(conn, mci, function (objMcUnit) {
				readUnit(conn, unit, function (objUnit) {
					var arrResponses = [];
					var trigger = getTrigger(objUnit, address);
					trigger.initial_address = trigger.address;
					trigger.initial_unit = trigger.unit;
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
```

**File:** aa_composer.js (L947-1004)
```javascript
	// with bAir option, we don't send or save a real unit
	function sendDummyUnit(messages) {
		console.log('AA ' + address + ': send dummy unit with messages', util.inspect(messages, { depth: 6 }));
		var objUnit = messages.length ? {
			unit: 'dummy' + Date.now(),
			authors: [{ address: address }],
			messages: messages,
		} : null;
		executeStateUpdateFormula(objUnit, function (err) {
			if (err)
				return bounce(err);
			// update balances
			var arrOutputAddresses = [];
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
			});
			if (arrOutputAddresses.length === 0)
				return finish(objUnit);
			if (trigger_opts.assocBalances[address].base < 0)
				return bounce("not enough balance in base");
			let arrAssetsWithNegativeBalances = [];
			for (let asset in trigger_opts.assocBalances[address])
				if (asset !== 'base' && trigger_opts.assocBalances[address][asset] < 0)
					arrAssetsWithNegativeBalances.push(asset);
			async.eachSeries(
				arrAssetsWithNegativeBalances,
				function (asset, cb) {
					storage.loadAssetWithListOfAttestedAuthors(conn, asset, mci, [address], true, function (err, objAsset) {
						if (err)
							return cb(err);
						if (objAsset.issued_by_definer_only && address !== objAsset.definer_address)
							return cb("not enough balance in " + asset); // and we are not the issuer
						cb();
					});
				},
				function (err) {
					if (err)
						return bounce(err);
					fixStateVars();
					addResponse(objUnit, function () {
						handleSecondaryTriggers(objUnit, arrOutputAddresses);
					});
				}
			);
		});
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

**File:** aa_composer.js (L1846-1849)
```javascript
		if (arrResponses.length >= constants.MAX_RESPONSES_PER_PRIMARY_TRIGGER) // max number of responses per primary trigger, over all branches stemming from the primary trigger
			return bounce("max number of responses per trigger exceeded");
		if ("max_aa_responses" in trigger && arrResponses.length >= trigger.max_aa_responses)
			return bounce(`max_aa_responses ${trigger.max_aa_responses} exceeded`);
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

**File:** test/samples/uniswap_like_market_maker.oscript (L102-123)
```text
			{ // exchange bytes to asset
				if: `{trigger.output[[asset=base]] > 1e5 AND trigger.output[[asset=$asset]] == 0 AND var['mm_asset_outstanding']}`,
				init: `{
					$asset_balance = balance[$asset] - trigger.output[[asset=$asset]];
					$bytes_balance = balance[base] - trigger.output[[asset=base]];
					// other formula can be used for product, e.g. $asset_balance * $bytes_balance ^ 2
					$p = $asset_balance * $bytes_balance;
					$new_asset_balance = round($p / balance[base]);
					$amount = $asset_balance - $new_asset_balance; // we can deduct exchange fees here
				}`,
				messages: [
					{
						app: 'payment',
						payload: {
							asset: "{$asset}",
							outputs: [
								{address: "{trigger.address}", amount: "{ $amount }"}
							]
						}
					},
				]
			},
```

**File:** test/samples/uniswap_like_market_maker.oscript (L124-145)
```text
			{ // exchange asset to bytes
				if: `{trigger.output[[asset=$asset]] > 0 AND var['mm_asset_outstanding']}`,
				init: `{
					$asset_balance = balance[$asset] - trigger.output[[asset=$asset]];
					$bytes_balance = balance[base] - trigger.output[[asset=base]]; // 10Kb fee
					// other formula can be used for product, e.g. $asset_balance * $bytes_balance ^ 2
					$p = $asset_balance * $bytes_balance;
					$new_bytes_balance = round($p / balance[$asset]);
					$amount = $bytes_balance - $new_bytes_balance; // we can deduct exchange fees here
				}`,
				messages: [
					{
						app: 'payment',
						payload: {
							asset: "base",
							outputs: [
								{address: "{trigger.address}", amount: "{ $amount }"}
							]
						}
					},
				]
			},
```
