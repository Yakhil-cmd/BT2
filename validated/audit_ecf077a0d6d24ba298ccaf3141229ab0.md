This confirms the analog. The `balance[address][asset]` formula in `formula/evaluation.js` (`readBalance`, lines 1510-1528) lets any AA read the **live, current** on-chain balance/reserve of any other address, including a third-party AMM-style AA — exactly the "spot price" primitive from the Panoptic report. The bundled `test/samples/uniswap_like_market_maker.oscript` example demonstrates the intended usage pattern: swap/investment amounts are computed directly from `balance[$asset]` and `balance[base]` (the pool's current reserves) with a constant-product formula, with **no TWAP, no oracle, and no slippage/price protection** — the same root cause flagged in the Panoptic finding. Because `aa_composer.js`'s secondary-trigger mechanism (`handleSecondaryTriggers`, `aa_composer.js:1702-1757`) lets a single top-level trigger unit atomically cascade through a chain of AA calls (as shown in `test/aa_composer.test.js:156-252` "chain of AAs" and `test/aa_composer.test.js:450-554` "issue recently defined asset"), an attacker can post one unit that (1) swaps against the pool AA to skew its `balance[]` reserves, then (2) in the same atomic cascade, triggers a second AA that reads the now-manipulated `balance[pool_address][asset]` to price an action (e.g., a lending/vault AA using the pool as a price reference, or the pool AA's own subsequent swap case in the same response chain) — all executed atomically and, if anything fails, rolled back together (`revert`/`ROLLBACK TO SAVEPOINT initial_balances`, `aa_composer.js:1759-1798`), giving the attacker the same free, reversible manipulation window a flashloan provides on Ethereum.

### Title
Autonomous Agents relying on `balance[address][asset]` as a spot price/reserve oracle are exploitable via atomic secondary-trigger chains — (File: `formula/evaluation.js`, `aa_composer.js`)

### Summary
`ojson`/oscript formulas expose the current, live balance of *any* address — including other AAs — via `balance[address][asset]`. This is the AA-layer equivalent of reading a Uniswap pool's instantaneous spot reserves. The bundled reference implementation `test/samples/uniswap_like_market_maker.oscript` explicitly builds a constant-product AMM whose swap/invest/divest amounts are derived purely from this live balance, with no TWAP, external oracle, or slippage protection. Because ocore's secondary-trigger mechanism executes a whole chain of dependent AA calls atomically from a single posted unit (and rolls all of them back together on failure), an attacker can manipulate a pool AA's reserves and have a dependent AA consume that manipulated value in the same atomic operation, with no possibility for other parties to intervene in between — mirroring the flashloan-manipulation pattern from the Panoptic report.

### Finding Description
`readBalance` in `formula/evaluation.js:1510-1528` returns the AA's current `aa_balances` row (or the in-flight `objValidationState.assocBalances` value if already touched in this same trigger chain) for whatever `address`/`asset` pair is requested, with no averaging, no historical window, and no cost to query. Any AA author can therefore write formulas like the sample AMM's:
```
$asset_balance = balance[$asset] - trigger.output[[asset=$asset]];
$bytes_balance = balance[base] - trigger.output[[asset=base]];
$p = $asset_balance * $bytes_balance;
$new_asset_balance = round($p / balance[base]);
$amount = $asset_balance - $new_asset_balance;
```
(`test/samples/uniswap_like_market_maker.oscript:104-122`) using the pool's *current* reserves as the price, exactly as Panoptic's `deployNewPool` used `v3Pool.slot0()`'s current sqrt price. `aa_composer.js`'s `handleSecondaryTriggers` (lines 1702-1757) lets one primary trigger unit cascade through multiple AA invocations — up to `constants.MAX_RESPONSES_PER_PRIMARY_TRIGGER` — atomically: if any step bounces, `revert()` (lines 1759-1798) rolls back the whole chain via `ROLLBACK TO SAVEPOINT initial_balances`. This gives a single attacker-crafted unit the same atomic, all-or-nothing execution window that a flashloan provides on Ethereum: swap against the pool to skew reserves, then immediately consume the skewed `balance[]` reading in a dependent AA, with the option to bounce/undo if unprofitable.

### Impact Explanation
Any third-party AA (a lending AA using the pool as a price feed, a second pool-derived vault, or even the pool's own subsequent swap case triggered within the same cascade) that consumes `balance[address][asset]` of a pool-like AA as a pricing input can be made to misprice a swap/issue/redeem operation, transferring value from honest liquidity providers or users to the attacker. This directly maps to "concrete unauthorized spending" / "AA fund loss" — funds held by AAs can be drained or mispriced through a single, free, reversible atomic transaction.

### Likelihood Explanation
Any unprivileged user can post the trigger unit that starts the cascade; no special key, oracle address, or privileged role is required. The building blocks (secondary triggers, atomic rollback via savepoint, and unrestricted `balance[]` reads of any address) are core, always-available oscript/AA features, not opt-in extensions. The only precondition is that some deployed AA design uses raw `balance[]` of a swap-affectable address for pricing without additional safeguards — exactly the pattern ocore's own bundled example (`uniswap_like_market_maker.oscript`) teaches AA developers to write, making this a realistic and likely-to-be-copied pattern.

### Recommendation
- Document prominently (and ideally enforce via linting/formula-validation warnings) that `balance[address][asset]` must never be used as a sole pricing input for cross-AA value transfers without a time-weighted or oracle-backed safeguard.
- Update `test/samples/uniswap_like_market_maker.oscript` to include a slippage/minimum-output parameter supplied by the trigger, or to require the price to be corroborated by a `data_feed` oracle before executing a swap, so the reference implementation does not model an exploitable pattern.
- Consider adding an oscript primitive for a time-weighted average of `balance[]`/reserves (analogous to a TWAP), so AA authors have an audited safe primitive instead of ad hoc spot reads.

### Proof of Concept
1. Attacker deploys (or targets an existing) AMM AA identical to `test/samples/uniswap_like_market_maker.oscript`, and a second "consumer" AA that, on trigger, reads `balance[pool_address][asset]` / `balance[pool_address][base]` to price its own payout (e.g., a lending AA that lets users borrow against collateral valued at the pool's implied price).
2. Attacker composes a single unit with a payment message to the pool AA (large one-sided swap that temporarily skews `$asset_balance`/`$bytes_balance`) and, via the pool's own `state`/`response` cascading to the consumer AA address (secondary trigger, `aa_composer.js:1702-1757`), a second payment/action to the consumer AA that is processed in the same atomic chain and reads the now-skewed `balance[]`.
3. Because both AA invocations are part of one atomic primary-trigger execution (rolled back together via `ROLLBACK TO SAVEPOINT initial_balances` if any step fails), the attacker can safely retry with different swap sizes until the consumer AA's mispriced payout is maximized, then let the whole chain commit — extracting value from the consumer AA/pool with no counter-party able to react in between, analogous to the flashloan-based liquidity manipulation in the original Panoptic finding. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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

**File:** aa_composer.js (L1759-1798)
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
		/*
		conn.query("ROLLBACK", function () {
			conn.query("BEGIN", function () {
				// initial AA balances were rolled back, we have to add them again
				if (!fPrepare)
					fPrepare = function (cb) { cb(); };
				fPrepare(function () {
					updateInitialAABalances(function () {
						console.log('done revert: ' + err);
						bounce(err);
					});
				});
			});
		});*/
	}
```
