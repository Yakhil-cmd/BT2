## Finding: Flash-loan-style price manipulation of AAs that use another AA's live balance/spot-price as an oracle

### Title
Atomic cross-AA balance manipulation enables flash-loan-style price attacks on AAs relying on `balance[address][asset]` spot ratios — ([File: aa_composer.js], [File: formula/evaluation.js])

### Summary
Oscript exposes a `balance[address][asset]` (and `var[address][name]`) primitive that lets any Autonomous Agent read the *live* balance/state of **any other address**, including another AA's asset-pair reserves. Combined with ocore's native ability to chain multiple AA invocations atomically within a single top-level trigger (via bounce-back "secondary triggers"), an attacker can manipulate a target AA's own liquidity-pool ratio and have a second, price-consuming AA read that manipulated ratio — all inside one atomically committed/rolled-back unit sequence, exactly mirroring the "manipulate reserves → drain a dependent protocol → succeed atomically or revert for free" pattern used in the WGPT flash-loan incident.

### Finding Description
`balance[address][asset]` in the formula evaluator is not restricted to the querying AA's own address — the second optional parameter lets it read the balance of an arbitrary address: [1](#0-0) 
This is the documented mechanism by which one AA "queries the state or balance of another AA."

Separately, `aa_composer.js` implements chained/secondary AA triggers: a message from AA A to AA B automatically re-invokes AA B (`handleSecondaryTriggers`), which can itself pay back to AA A or to a third AA, all as part of the *same* top-level primary trigger: [2](#0-1) 
Crucially, if any step in this chain bounces/fails, the **entire chain is rolled back** to a savepoint taken before the primary trigger began, i.e. the whole multi-hop sequence is atomic: [3](#0-2) 

The shipped reference AMM template (`test/samples/uniswap_like_market_maker.oscript`), which developers are expected to use as a basis for real pools, prices every trade purely off the pool's *own current* reserve ratio with no time-weighting or external oracle: [4](#0-3) 
```
$asset_balance = balance[$asset] - trigger.output[[asset=$asset]];
$bytes_balance = balance[base] - trigger.output[[asset=base]];
$p = $asset_balance * $bytes_balance;
$new_asset_balance = round($p / balance[base]);
$amount = $asset_balance - $new_asset_balance;
```
Any other AA that trusts this pool's `balance[pool_address][asset]` ratio as a spot-price oracle (a documented, encouraged pattern in oscript, since cross-AA `balance[]`/`var[]` reads are the *intended* way to compose AAs) inherits the classic AMM spot-price manipulation weakness. Because a single top-level trigger can chain: (1) a large one-sided swap against the pool (skewing its `balance[]` ratio), then (2) a call to the price-consuming AA that reads the now-skewed `balance[pool][asset]`, then (3) a reversing swap back — with the whole thing succeeding or fully reverting atomically (`ROLLBACK TO SAVEPOINT initial_balances`), the attacker pays only bounce fees on failure and only unit fees on success, with no persistent capital at risk. This is functionally identical to a DeFi flash-loan attack: reserves of a spot-priced pool are distorted and read by a dependent contract inside one atomic transaction.

### Impact Explanation
Any deployed AA that composes with another AA's asset pool by reading `balance[pool_address][asset]` (a pattern the protocol itself documents and ships as a reference template) can have its pricing/collateral logic manipulated within a single atomic unit, leading to AA fund loss/drain analogous to the $82.5k WGPT flash-loan loss — the victim is the price-consuming AA (e.g., a lending/synthetic AA using the pool as an oracle), and losses scale with the pool's TVL and the price-consuming AA's exposure.

### Likelihood Explanation
No special privilege is required: any unprivileged unit poster/AA-trigger sender can post a trigger, cause secondary triggers to fire (this is core, always-on AA composition behavior, not an edge case), and revert the whole multi-hop sequence for free if unprofitable. The only prerequisite is that some deployed AA in the ecosystem reads another AA's `balance[]` as a price reference instead of a time-weighted or externally-attested `data_feed` — a pattern the codebase's own reference AMM sample encourages by using unguarded spot balances.

### Recommendation
- Document and strongly discourage using another AA's raw `balance[address][asset]` ratio as a price oracle in oscript guidance/templates; recommend `data_feed[]` from independent, TWAP-style oracles instead.
- Consider adding a built-in "average/TWAP balance" or "balance at last stable MCI" primitive so cross-AA price reads cannot be manipulated within the same atomic multi-hop trigger chain.
- Update `test/samples/uniswap_like_market_maker.oscript` to note (or better, mitigate) this composability risk, since it is shipped as a canonical example that third-party developers copy.

### Proof of Concept
1. Attacker deploys/uses an oracle-consuming AA `L` that reads `balance[Pool][X]` / `balance[Pool][base]` from an existing pool AA `Pool` (following the pattern in `uniswap_like_market_maker.oscript`) to price a loan or synthetic mint.
2. Attacker crafts one unit whose primary trigger pays into `Pool` with a large one-sided swap of `X`→bytes (or vice versa), which `Pool` processes via `sendUnit`, updating `aa_balances` for `Pool` immediately (`updateFinalAABalances`), skewing `balance[Pool][X]/balance[Pool][base]`.
3. The response chain (secondary trigger) is directed so that, in the same primary trigger's execution, `L` is invoked next and reads the now-skewed `balance[Pool][...]`, computing an inflated payout/loan to the attacker's address.
4. Attacker optionally chains a third hop back through `Pool` to restore the ratio and collect the arbitrage profit extracted from `L`.
5. If any hop bounces, `aa_composer.js`'s `revert()` rolls the entire unit back to `SAVEPOINT initial_balances`, so the attack costs only bounce fees when unsuccessful, and yields drained funds from `L` when successful — the atomic, no-capital-risk signature of a flash-loan attack. [5](#0-4)

### Citations

**File:** formula/evaluation.js (L1480-1508)
```javascript
			case 'var':
			case 'balance':
				var param1 = arr[1];
				var param2 = arr[2];
				evaluate(param1, function (evaluated_param1) {
					if (fatal_error)
						return cb(false);
					if (typeof evaluated_param1 !== 'string')
						return setFatalError("1st var name is not a string: " + evaluated_param1, { arr }, false, cb);
					if (op === 'var' && !evaluated_param1.isWellFormed())
						return setFatalError("state var name not well formed: " + evaluated_param1, { arr }, false, cb);
					if (param2 === null)
						return ((op === 'var') ? readVar(address, evaluated_param1, cb) : readBalance(address, evaluated_param1, cb));
					// then, the 1st param is the address of an AA whose state or balance we are going to query
					var param_address = evaluated_param1;
					if (!ValidationUtils.isValidAddress(param_address))
						return setFatalError("var address is invalid: " + param_address, { arr }, false, cb);
					evaluate(param2, function (evaluated_param2) {
						if (fatal_error)
							return cb(false);
						if (typeof evaluated_param2 !== 'string')
							return setFatalError("2nd var name is not a string: " + evaluated_param2, { arr }, false, cb);
						if (op === 'var' && !evaluated_param2.isWellFormed())
							return setFatalError("state var name not well formed: " + evaluated_param2, { arr }, false, cb);
						(op === 'var')
							? readVar(param_address, evaluated_param2, cb)
							: readBalance(param_address, evaluated_param2, cb);
					});
				});
```

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

**File:** aa_composer.js (L1841-1863)
```javascript
	updateInitialAABalances(function (err) {

		// these errors must be thrown after updating the balances
		if (err)
			return bounce(err);
		if (arrResponses.length >= constants.MAX_RESPONSES_PER_PRIMARY_TRIGGER) // max number of responses per primary trigger, over all branches stemming from the primary trigger
			return bounce("max number of responses per trigger exceeded");
		if ("max_aa_responses" in trigger && arrResponses.length >= trigger.max_aa_responses)
			return bounce(`max_aa_responses ${trigger.max_aa_responses} exceeded`);
		// being able to pay for bounce fees is not required for secondary triggers as they never actually send any bounce response or change state when bounced
		if (!bSecondary) {
			if ((trigger.outputs.base || 0) < bounce_fees.base) {
				return bounce('received bytes are not enough to cover bounce fees');
			}
			for (var asset in trigger.outputs) { // if not enough asset received to pay for bounce fees, ignore silently
				if (bounce_fees[asset] && trigger.outputs[asset] < bounce_fees[asset]) {
					return bounce('received ' + asset + ' is not enough to cover bounce fees');
				}
			}
			// skip this check for dry-run which uses genesis unit as trigger unit
			if (trigger.unit !== constants.GENESIS_UNIT && !trigger_opts.bAir && storage.assocStableUnits[trigger.unit].count_aa_responses && mci >= constants.pemCurvesFixMci)
				return bounce('a second primary trigger from the same unit is not allowed');
		}
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
