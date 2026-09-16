The evidence gathered confirms the relevant analog: the `uniswap_like_market_maker.oscript` sample in `test/samples/` demonstrates a documented pattern where a market-maker AA relies on the raw `balance[asset]` formula function to compute ratios and issuance amounts, exactly analogous to the reported `getSupplyProportion()` pattern relying on unaccounted pool balances.

### Title
Balance-based ratio/issuance formulas in AA scripts are corruptible by direct unsolicited transfers, mirroring the UniV3 balance-manipulation bug class - (File: `test/samples/uniswap_like_market_maker.oscript`, engine support: `formula/evaluation.js`)

### Summary
The reported bug is a class of vulnerability where a contract computes exchange ratios/mint amounts from the *raw on-chain token balance* of a pool rather than an internally tracked, authenticated supply figure, allowing an attacker to corrupt the ratio by transferring tokens directly to the pool address. Obyte's oscript/AA formula language exposes an exact structural analog through the `balance[asset]` primitive, which any unprivileged party can manipulate by simply sending a payment to the AA's address, since **any** payment received by an AA address is unconditionally added to that AA's queryable balance regardless of whether it matches an intended "case" in the AA's `if` conditions.

### Finding Description
`balance[asset]` in the oscript formula evaluator reads the AA's live balance directly from `objValidationState.assocBalances` / the `aa_balances` table [1](#0-0) . This balance is updated for *any* trigger unit sent to the AA's address that adds outputs, before the AA's own `if`/`init` logic runs, exactly as seen in `updateInitialAABalances` [2](#0-1) . Consequently, an attacker can send an "unsolicited" payment of the pool's asset (or bytes) to the AA address — one that does not match any of the AA's defined "invest"/"divest" cases, or is captured by a generic catch-all case — thereby inflating `balance[asset]` without any corresponding update to the AA's own accounting state variables (e.g. `var['mm_asset_outstanding']`).

This is demonstrated by the shipped reference AA `uniswap_like_market_maker.oscript`, which computes swap/issuance ratios purely from `balance[$asset]` and `balance[base]` rather than from internally tracked reserve variables: [3](#0-2)  for investment issuance, and [4](#0-3)  for the constant-product swap formulas. In every one of these cases the "reserve" values `$asset_balance` and `$bytes_balance` are derived by subtracting only the *current trigger's* output from the *raw* balance, not from a separately maintained, tamper-resistant state variable. Any prior donation directly to the AA's address (not tied to a matching case) permanently pollutes these balances, which is structurally identical to the report's "DAI/USSD transferred to UniV3 pool directly" attack, where the raw balance/`getSupplyProportion()` no longer corresponds to the price/ratio the contract's logic assumes.

### Impact Explanation
For any AA (deployed by a third party) that follows this documented pattern — computing mint/swap amounts from `balance[asset]` instead of from independently maintained state variables — an attacker can:
1. Send a "silent"/unsolicited payment of the pool's minority asset to skew `$current_ratio` / `$p` (the constant product), causing the "wrong ratio of amounts" bounce condition to trip permanently (denial of service on `invest`), analogous to the reported rebalance-can-never-execute scenario, or
2. Because `$new_asset_balance`/`$new_bytes_balance` and `$amount` are derived from the polluted `balance[...]`, cause under/over-payment on swaps relative to the AA's true tracked liabilities (`var['mm_asset_outstanding']`), leading to fund loss/freezing for legitimate investors when they later try to divest their share of `balance[$asset]`/`balance[base]` (`round($investor_share * balance[$asset])` in the divest case) [5](#0-4) .

This matches the "AA fund loss or freezing" acceptance criterion, reachable by an unprivileged trigger sender directly interacting with a deployed AA that follows this documented reference pattern.

### Likelihood Explanation
High likelihood of exploitation for any AA deployed from or inspired by this reference implementation: the attack requires only sending a single ordinary payment (any amount, to any asset the AA holds) to the AA's address — no special privileges, no race condition, and no interaction with the AA's defined cases is required, since balances are updated unconditionally on receipt regardless of whether the payment matches an `if` condition.

### Recommendation
The reference AA pattern (and by extension the guidance given to AA authors via this sample) should track and rely on internally maintained state variables (e.g., `var['reserve_' || asset]`) that are updated only through the AA's own authorized code paths, instead of trusting `balance[asset]`, mirroring the audit's recommendation to compute liquidity from tracked state rather than raw balances. Documentation/samples shipped with ocore should be updated to warn AA authors against using `balance[...]` for financial ratio calculations without reconciling against tracked reserves.

### Proof of Concept
1. Deploy an AA based on `uniswap_like_market_maker.oscript` and perform the initial `define` + first deposit as normal, establishing `var['mm_asset_outstanding']` and real reserves.
2. As an unprivileged attacker, send a plain payment of `$asset` tokens directly to the AA's address with `trigger.data` empty or not matching the `invest`/`divest`/`exchange` conditions (e.g., an amount below the `1e5` byte threshold used in the "exchange bytes to asset" case, or in a shape that doesn't trigger any case but is still added to `aa_balances`).
3. On the next legitimate "invest" trigger, `$asset_balance = balance[$asset] - trigger.output[[asset=$asset]]` at line 36 of `test/samples/uniswap_like_market_maker.oscript` now includes the attacker's donation, skewing `$current_ratio` at line 42 and causing either a bounce (`'wrong ratio of amounts...'`, line 45) for legitimate investors, or, in the "exchange" cases (lines 102-133), an incorrect `$amount` calculation that misallocates funds relative to `var['mm_asset_outstanding']`, allowing later divestors to overdraw `balance[$asset]`/`balance[base]` at the expense of other investors.

### Citations

**File:** formula/evaluation.js (L1510-1527)
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
```

**File:** aa_composer.js (L474-485)
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
```

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

**File:** test/samples/uniswap_like_market_maker.oscript (L67-93)
```text
			{ // divest MM shares 
				// (user is already paying 10000 bytes bounce fee which is a divest fee)
				// the price slightly moves due to fees received and paid in bytes
				if: `{$mm_asset AND trigger.output[[asset=$mm_asset]]}`,
				init: `{
					$mm_asset_amount = trigger.output[[asset=$mm_asset]];
					$investor_share = $mm_asset_amount / var['mm_asset_outstanding'];
				}`,
				messages: [
					{
						app: 'payment',
						payload: {
							asset: "{$asset}",
							outputs: [
								{address: "{trigger.address}", amount: "{ round($investor_share * balance[$asset]) }"}
							]
						}
					},
					{
						app: 'payment',
						payload: {
							asset: "base",
							outputs: [
								{address: "{trigger.address}", amount: "{ round($investor_share * balance[base]) }"}
							]
						}
					},
```

**File:** test/samples/uniswap_like_market_maker.oscript (L102-133)
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
```
