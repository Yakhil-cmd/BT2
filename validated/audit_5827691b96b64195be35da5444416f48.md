I have enough evidence to confirm the analog. The core mechanism (`revert()` at `aa_composer.js:1759-1783` using `ROLLBACK TO SAVEPOINT initial_balances`, and `handleSecondaryTriggers` at `aa_composer.js:1702-1757`) confirms that an entire chain of AA triggers stemming from one posted unit is atomic — it either all completes or is entirely rolled back, exactly mirroring EVM flash-loan atomicity.

### Title
Reserve-ratio AMM-style AAs are vulnerable to same-unit atomic price manipulation ("flash-loan"-style) attacks - (File: `aa_composer.js`, `formula/evaluation.js`)

### Summary
The reported Sandclock bug exploited an on-chain AMM spot price (DAI/UST Curve pool reserve ratio) that could be pushed away from the true market price atomically within a single flash-loaned transaction, then used to get favorable vault deposit/withdraw terms, before reverting the price and repaying the loan — all in one atomic, revertible transaction. Obyte's AA (Autonomous Agent) framework provides the same primitive: the `balance[asset]` operator in `oscript` reads the AA's current on-chain balance/reserves at evaluation time [1](#0-0) , and a chain of AAs triggered from a single posted unit is executed atomically — if any AA in the chain bounces, the entire chain (including all balance/state changes) is rolled back via `ROLLBACK TO SAVEPOINT initial_balances` [2](#0-1) , and secondary triggers stemming from a single primary unit are dispatched in the same atomic execution scope [3](#0-2) .

### Finding Description
Obyte's canonical, project-authored constant-product market-maker pattern (shipped as a reference/test sample, `uniswap_like_market_maker.oscript`) computes swap/investment prices purely from the AA's current reserve balances within the trigger:
```
$asset_balance = balance[$asset] - trigger.output[[asset=$asset]];
$bytes_balance = balance[base] - trigger.output[[asset=base]];
$current_ratio = $asset_balance / $bytes_balance;
``` [4](#0-3)  and similarly for swaps: [5](#0-4) 

Because `balance[]` is evaluated against `objValidationState.assocBalances`, which reflects the AA's real-time balance including all payments received so far in the current atomic trigger/response chain [6](#0-5) , and because AA-to-AA chains triggered from one posted unit execute as a single atomic unit of work that can either fully commit or be fully reverted via savepoint rollback on any failure [2](#0-1) , an attacker can, within one atomic sequence stemming from a single posted unit:
1. Send a large payment to swap into the pool AA, skewing `$asset_balance`/`$bytes_balance` (and thus `$current_ratio`/`$p`) far from the market-consistent ratio.
2. In the same atomic chain, trigger a second operation (e.g. "invest" to mint MM shares, or a downstream AA that depends on this distorted ratio) that reads the now-manipulated `balance[]`-derived price to obtain shares/tokens at favorable terms.
3. Swap back to restore the original ratio, and if any step fails or the economics aren't favorable, the AA `bounce()`/`revert()` unwinds the whole chain atomically with no lasting cost to the attacker beyond fees [7](#0-6) .

This is functionally identical to the Curve/DAI flash-loan attack in the H-03 report: a manipulable on-chain reserve ratio, read and acted upon within one atomic, revertible operation, with no oracle or time-weighted average price protection.

### Impact Explanation
Any AA built on this reserve-ratio pricing pattern (which ocore itself ships as the reference "Uniswap-like market maker" design) is exposed to atomic price-manipulation extraction of pooled funds — an attacker can mint/redeem shares or swap assets at a manipulated rate and drain value from other liquidity providers/depositors, i.e., unauthorized transfer of pooled AA funds. This maps to concrete fund loss for AA depositors/LPs, a Medium/High-severity impact.

### Likelihood Explanation
Likelihood is Medium: exploitation requires an AA author to deploy a reserve-ratio-based pricing AA without a time-weighted/oracle safeguard (as in the shipped sample) and sufficient liquidity imbalance to be economically worthwhile, but no special privilege is needed — any unprivileged unit poster can trigger the swap/invest/divest sequence in one atomic unit chain.

### Recommendation
- Do not use spot reserve ratios (`balance[]`) directly for pricing in AA-based AMMs/pools; use a `data_feed` oracle-provided or time-weighted average price instead, as ocore's own `data_feed[[...]]`-based examples (e.g. `futures_contract.oscript`) already demonstrate [8](#0-7) .
- For pool-style AAs that must use reserves, add manipulation resistance: minimum liquidity thresholds, fees large enough to make round-trip manipulation unprofitable, and/or restrict per-unit reserve-ratio changes.
- Document this risk explicitly for AA developers building AMM/market-maker style contracts on ocore, since the atomic secondary-trigger chaining and full-chain revert (`ROLLBACK TO SAVEPOINT initial_balances`) reproduce the same atomicity guarantees that make flash-loan attacks possible on EVM chains.

### Proof of Concept
1. Deploy the reference `uniswap_like_market_maker.oscript`-style AA with `$asset` reserves and `base` (bytes) reserves in some ratio.
2. Post a unit that sends a very large `base` payment to the AA triggering the "exchange bytes to asset" case, sharply moving `$asset_balance`/`$bytes_balance` and thus the effective price [5](#0-4) .
3. Within the same atomic chain (secondary trigger from the same posted unit, or a subsequent message in a follow-up AA call before the manipulated balance reverts), trigger the "invest" case so `$issue_amount` is computed from the now-skewed `var['mm_asset_outstanding']` and reserve ratio [9](#0-8) , minting shares worth more than fair value.
4. Swap back to restore reserves; if the sequence is not profitable, cause a bounce so `revert()` rolls the whole chain back to `SAVEPOINT initial_balances` at zero net cost except fees [2](#0-1) .

### Citations

**File:** formula/evaluation.js (L1510-1528)
```javascript
				function readBalance(param_address, bal_asset, cb2) {
					if (bal_asset !== 'base' && !ValidationUtils.isValidBase64(bal_asset, constants.HASH_LENGTH))
						return setFatalError('bad asset ' + bal_asset, { arr }, false, cb);

					if (!objValidationState.assocBalances[param_address])
						objValidationState.assocBalances[param_address] = {};
					var balance = objValidationState.assocBalances[param_address][bal_asset];
					if (balance !== undefined)
						return cb2(new Decimal(balance));
					conn.query(
						"SELECT balance FROM aa_balances WHERE address=? AND asset=? ",
						[param_address, bal_asset],
						function (rows) {
							balance = rows.length ? rows[0].balance : 0;
							objValidationState.assocBalances[param_address][bal_asset] = balance;
							cb2(new Decimal(balance));
						}
					);
				}
```

**File:** aa_composer.js (L474-490)
```javascript
	// add the coins received in the trigger
	function updateInitialAABalances(cb) {
		let bOverflow = false;
		if (trigger_opts.assocBalances) {
			if (!trigger_opts.assocBalances[address])
				trigger_opts.assocBalances[address] = {};
			originalBalances = _.cloneDeep(trigger_opts.assocBalances);
			for (var asset in trigger.outputs) {
				trigger_opts.assocBalances[address][asset] = (trigger_opts.assocBalances[address][asset] || 0) + trigger.outputs[asset];
				if (trigger_opts.assocBalances[address][asset] > MAX_BALANCE)
					bOverflow = true;
			}
			objValidationState.assocBalances = trigger_opts.assocBalances;
			byte_balance = trigger_opts.assocBalances[address].base || 0;
			storage_size = 0;
			return cb(bOverflow && mci >= constants.pemCurvesFixMci ? "balance overflow" : null);
		}
```

**File:** aa_composer.js (L909-944)
```javascript
	var bBouncing = false;
	function bounce(error) {
		console.log('bouncing with error', error, new Error().stack);
		objStateUpdate = null;
		error_message = error_message ? (error_message + ', then ' + error) : error;
		if (trigger_opts.bAir) {
			assignObject(stateVars, originalStateVars); // restore state vars
			assignObject(trigger_opts.assocBalances, originalBalances); // restore balances
			if (!bSecondary) {
				for (let a in trigger.outputs)
					if (bounce_fees[a])
						trigger_opts.assocBalances[address][a] = (trigger_opts.assocBalances[address][a] || 0) + bounce_fees[a];
			}
		}
		if (bBouncing)
			return finish(null);
		bBouncing = true;
		if (bSecondary)
			return finish(null);
		if ((trigger.outputs.base || 0) < bounce_fees.base)
			return finish(null);
		var messages = [];
		// iteration order is standardized since ECMAScript 2020
		for (var asset in trigger.outputs) {
			var amount = trigger.outputs[asset];
			var fee = bounce_fees[asset] || 0;
			if (fee > amount)
				return finish(null);
			if (fee === amount)
				continue;
			var bounced_amount = amount - fee;
			messages.push({app: 'payment', payload: {asset: asset, outputs: [{address: trigger.address, amount: bounced_amount}]}});
		}
		if (messages.length === 0)
			return finish(null);
		sendUnit(messages);
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

**File:** test/samples/uniswap_like_market_maker.oscript (L33-48)
```text
			{ // invest in MM
				if: `{$mm_asset AND trigger.output[[asset=base]] > 1e5 AND trigger.output[[asset=$asset]] > 0}`,
				init: `{
					$asset_balance = balance[$asset] - trigger.output[[asset=$asset]];
					$bytes_balance = balance[base] - trigger.output[[asset=base]];
					if ($asset_balance == 0 OR $bytes_balance == 0){ // initial deposit
						$issue_amount = balance[base];
						return;
					}
					$current_ratio = $asset_balance / $bytes_balance;
					$expected_asset_amount = round($current_ratio * trigger.output[[asset=base]]);
					if ($expected_asset_amount != trigger.output[[asset=$asset]])
						bounce('wrong ratio of amounts, expected ' || $expected_asset_amount || ' of asset');
					$investor_share_of_prev_balance = trigger.output[[asset=base]] / $bytes_balance;
					$issue_amount = round($investor_share_of_prev_balance * var['mm_asset_outstanding']);
				}`,
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

**File:** test/samples/futures_contract.oscript (L59-93)
```text
			{ // record blackswan event
				if: `{ trigger.data.blackswan AND !var['blackswan'] AND data_feed[[oracles='X55IWSNMHNDUIYKICDW3EOYAWHRUKANP', feed_name='GBYTE_USD_MA']] < 25 AND timestamp < 1556668800 }`,
				messages: [{
					app: 'state',
					state: `{
						var['blackswan'] = 1;
						response['blackswan'] = 1;
					}`
				}]
			},
			// 1 GB is now 50 USD, 1 byte is 50e-9 = 5e-8 USD
			// 1 usd asset is always 2.5e-8 USD, 1 gb asset is 1 byte minus 2.5e-8 USD
			{ // pay bytes in exchange for the assets
				if: `{
					if (trigger.output[[asset!=base]].asset == 'none')
						return false;
					$gb_asset_amount = trigger.output[[asset=var['gb_asset']]];
					$usd_asset_amount = trigger.output[[asset=var['usd_asset']]];
					if ($gb_asset_amount < 1e4 AND $usd_asset_amount < 1e4)
						return false;
					if ($gb_asset_amount == $usd_asset_amount){ // helps in case the exchange rate is never posted
						$bytes = $gb_asset_amount;
						return true;
					}
					if (var['blackswan'])
						$bytes = $usd_asset_amount;
					else{
						if (timestamp < 1556668800)
							bounce('wait for maturity date');
						// data_feed will abort if the exchange rate not posted yet
						$exchange_rate = data_feed[[oracles='X55IWSNMHNDUIYKICDW3EOYAWHRUKANP', feed_name='GBYTE_USD_MA_2019_04_30']];
						$bytes_per_usd_asset = min(50/$exchange_rate/2, 1);
						$bytes_per_gb_asset = 1 - $bytes_per_usd_asset;
						$bytes = round($bytes_per_usd_asset * $usd_asset_amount + $bytes_per_gb_asset * $gb_asset_amount);
					}
```
