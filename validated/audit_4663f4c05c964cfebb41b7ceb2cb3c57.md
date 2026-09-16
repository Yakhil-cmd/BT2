## Title
Instant-balance AMM pricing combined with atomic, revert-on-failure AA call chains enables flash-loan-style price manipulation - (File: test/samples/uniswap_like_market_maker.oscript, aa_composer.js)

### Summary
The PancakeBunny incident was a single-transaction flash-loan attack that skewed an AMM's instantaneous reserve ratio and drained value from a strategy relying on that unmanipulated price. Ocore's own bundled reference AMM (`uniswap_like_market_maker.oscript`) prices trades purely from the *current* `balance[asset]`/`balance[base]` ratio inside one AA invocation, and ocore's AA engine (`aa_composer.js`) executes a full chain of triggered AAs **atomically and synchronously** in a single database transaction with an all-or-nothing rollback (`ROLLBACK TO SAVEPOINT initial_balances`). This combination reproduces the core precondition of the PancakeBunny bug class inside ocore: a single posted unit can, within one atomic execution, deposit into a pool-style AA to skew its instantaneous price, have a second, chained AA consume that skewed price, and unwind — with the entire sequence guaranteed to commit only if profitable, and guaranteed to fully revert (no partial state) otherwise.

### Finding Description
The reference market-maker AA computes trade output directly from the AA's live balance, without any time-weighting or manipulation resistance: [1](#0-0) 

Both the "invest" and "exchange" branches derive `$current_ratio` / `$p` from `balance[$asset]` and `balance[base]` net of the trigger's own outputs, i.e., the price is entirely a function of whatever the current triggering chain has already deposited: [2](#0-1) 

Separately, `aa_composer.js` processes a "chain of AAs" — a primary trigger unit that pays out to a second AA, whose response can pay back into a third — entirely within one `handleTrigger` call graph, sharing the same `conn`/`batch`/DB transaction, without waiting for any of the intermediate response units to reach main-chain stability: [3](#0-2) 

If any AA in the chain bounces, the whole chain (including any state/balance changes already applied) is rolled back to a savepoint taken before the primary trigger began, guaranteeing atomicity for the entire multi-hop sequence: [4](#0-3) 

This atomic, all-or-nothing, multi-hop execution model is functionally equivalent to a flash loan's atomicity guarantee (borrow → manipulate → profit-check → repay-or-revert), and the bundled AMM template supplies the "manipulable, unprotected, instant price" ingredient that PancakeBunny's attacker exploited.

### Impact Explanation
Any unprivileged unit poster can define one or more attacker-controlled AAs and route a single triggering unit through them and into a deployed instance of this (or structurally similar) pool AA, atomically: (1) deposit into the pool to skew `$current_ratio`/`$p`, (2) trigger a second leg — either another interaction with the same pool, or a different AA that reads the pool's balance/rate as a price reference — to capture value at the skewed price, and (3) unwind, all inside one non-reverting call chain. Because the whole sequence commits together, the attacker never bears the risk of the price reverting between steps, exactly as with a flash loan. Deployed clones of this reference AMM (a documented Obyte pattern) would suffer real fund loss / AA fund drain from liquidity providers.

### Likelihood Explanation
The vulnerable pricing formula is the *bundled reference implementation* shipped in ocore's own samples, which developers are expected to copy/adapt for real AMM-style AAs, so the probability of live deployments using the same instant-balance formula is high. The atomic multi-hop trigger chain is a core, well-exercised feature of the AA engine (explicitly tested in `test/aa_composer.test.js` "chain of AAs" and related tests), so the exploitation primitive is always available to any unit poster without special privilege.

### Recommendation
- Update the bundled market-maker reference (and document the requirement for any deployed AMM/bonding-curve AA) to use a manipulation-resistant price, e.g., a time-weighted or oracle-anchored reference price rather than the raw same-transaction `balance[]` ratio.
- Add explicit guidance/constants limiting how much price impact a single atomic trigger-chain can have on such AAs (e.g., per-call size caps, or requiring price to be sourced from a `data_feed` rather than instantaneous internal balance).
- Consider documenting for AA authors that ocore's synchronous secondary-trigger chaining is transactionally atomic (like a flash loan) so any AA that treats its own or another AA's live balance as a trusted price must defend against single-chain manipulation.

### Proof of Concept
1. Deploy the sample `uniswap_like_market_maker.oscript` AA (`$asset`/bytes pool) as-is.
2. Craft attacker AA `M` that, upon receiving a trigger, (a) sends a large payment of `base` into the pool AA to skew `$current_ratio` in the "exchange asset to bytes"/"exchange bytes to asset" branch, and, in the same response unit, (b) forwards output to a second attacker AA `N` which immediately trades against the now-skewed pool balance to capture the mispriced asset, then (c) `N` forwards remaining funds back to `M`/the original trigger address.
3. Post a single unit from the attacker's own address with output to `M`; per `aa_composer.js`'s `handleSecondaryTriggers`/`handleTrigger`, `M`'s and `N`'s responses are computed synchronously in the same DB transaction as the primary trigger — if the net result is profitable it commits atomically; if not, `revert()` rolls everything back to the savepoint, so the attacker risks nothing but bounce fees while probing for profitable skew, mirroring flash-loan trial economics.

### Citations

**File:** test/samples/uniswap_like_market_maker.oscript (L33-47)
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
