### Title
AA balance-ratio "oracles" are manipulable atomically via chained secondary AA triggers, enabling flash-loan-style price attacks - (File: `formula/evaluation.js`, `aa_composer.js`)

### Summary
Any AA can read another AA's live balance synchronously with `balance[address][asset]`, and this is the documented pattern for building AMM-style price references in oscript (see `test/samples/uniswap_like_market_maker.oscript`). Because a single primary trigger unit can cause a chain of secondary AA triggers to execute atomically (all-or-nothing, with the whole call chain bouncing together on failure), an attacker can, within one trigger unit, (1) swap against an AMM-style AA to skew its balance ratio, (2) have a dependent AA consume that skewed balance as a "price" to extract value, and (3) swap back — exactly the flash-loan attack pattern described in the external report, but implemented via ocore's native chained AA calls instead of a DEX flash loan.

### Finding Description
`balance[address][asset]` lets any AA read the current balance of any other AA address directly from `objValidationState.assocBalances` / `aa_balances`, no permission needed: [1](#0-0) 

This is the exact mechanism used to build "price oracle" style AMM AAs shipped as a first-class sample in the repo, where the ratio of two live balances is used as the instantaneous exchange price: [2](#0-1) 

Other sample AAs (`fundraising_proxy.oscript`) also cross-read another AA's balance as input to a financial decision: [3](#0-2) 

Crucially, when an AA's response sends a payment to another AA address, that triggers a *secondary* AA call in the same processing chain, and the entire chain is atomic: if any AA in the chain bounces, the whole chain (including all prior state/balance changes in that chain) is reverted: [4](#0-3) 

This atomicity/rollback semantics (`revert(...)`/`bounce(...)` propagating up the chain) is functionally equivalent to the "borrow → manipulate → exploit → repay → all-or-nothing" structure that makes flash loan attacks profitable on EVM chains: an attacker designs (or uses an existing) orchestrator AA whose single response triggers, in sequence, (a) a large swap against an AMM-style AA to move its balance ratio, (b) a call to a victim AA that reads that AMM's `balance[...]` ratio as a price/valuation input and pays out based on it, and (c) a reverse swap to restore the AMM balance — with the entire multi-hop chain either fully succeeding (profit extracted) or fully bouncing (only bounce fees lost, no other risk). No TWAP, min/max slippage check, or staleness protection exists at the `balance[]`/`var[]` cross-AA read primitive itself — protection is entirely up to each AA author, and the sample AMM AA shipped in the codebase itself has no anti-manipulation defenses.

### Impact Explanation
Any AA (a "lending", "rebalancer", or "stablecoin" style AA analogous to USSD) that uses another AA's live balance ratio as a price input can have its collateral/asset balances drained by an attacker who atomically skews the referenced AA's balance and then exploits the resulting mispriced valuation within the same trigger chain — a High severity unauthorized-fund-loss scenario for the affected AA(s), fully analogous to the reported Uniswap `slot0` flash-loan issue.

### Likelihood Explanation
Exploitation only requires posting a single ordinary unit (a primary AA trigger) from an unprivileged address; no special permissions, oracle control, or witness/timing tricks are needed — only that some deployed AA relies on another AA's instantaneous `balance[]` ratio as a valuation/price source (a pattern explicitly demonstrated and encouraged by the shipped `uniswap_like_market_maker.oscript` sample). Given this is a documented, reusable oscript building block, the likelihood of it being used unsafely by AA authors is significant.

### Recommendation
- Do not treat instantaneous `balance[other_aa][asset]` ratios as manipulation-resistant prices; document this risk prominently next to the `balance[]` operator in `formula/evaluation.js` and in the AMM sample.
- For any AA intended to act as a price reference, maintain a time-weighted or state-var-based accumulator (TWAP) rather than exposing the raw instantaneous balance ratio, and have consuming AAs read that accumulator instead of raw balances.
- Consuming AAs should apply sanity bounds/circuit breakers (max deviation vs. a slower-moving reference) before acting on a cross-AA balance-derived price within the same trigger-chain, to blunt single-transaction (single-chain) manipulation.

### Proof of Concept
1. Deploy `uniswap_like_market_maker.oscript`-style AA `AMM` holding asset `X` and `base`, price = `balance[AMM][X] / balance[AMM][base]` as in [2](#0-1) .
2. Deploy victim AA `V` that, upon receiving a trigger, reads `balance[AMM][X]` / `balance[AMM][base]` (or an equivalent `data_feed`/`var` cross-read) to value collateral and pays out accordingly.
3. Deploy attacker orchestrator AA `O` whose single response chain (secondary triggers per `aa_composer.js` `handleSecondaryTriggers`, [5](#0-4) ) does: swap large `base`→`X` into `AMM` (skew ratio) → call `V` with a payment sized to exploit the skewed price → swap `X`→`base` back into `AMM` (restore ratio).
4. Post one trigger unit to `O`. If any step fails, the whole chain bounces per [6](#0-5) , so the attack is essentially risk-free; if it succeeds, `V`'s funds are drained based on the transiently skewed AMM price.

### Citations

**File:** formula/evaluation.js (L1480-1528)
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

**File:** test/samples/fundraising_proxy.oscript (L44-52)
```text
			{ // contribute
				if: `{trigger.output[[asset=base]] >= 1e5 AND $asset}`,
				init: `{
					if (var[$destination_aa]['finished'])
						bounce('game over');
					$amount = trigger.output[[asset=base]] - 2000; // to account for fees we need to respond now and to refund bytes or pay shares later
					$total_raised = var['total_raised'] + $amount;
					$missing_amount = ceil((balance[$destination_aa][base] + $total_raised)*0.51) - var[$destination_aa]['team_' || $team || '_amount'];
					$bDone = ($total_raised > $missing_amount);
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
