## Analysis

The Surge Pool bug class — using the contract's **raw token balance** (attacker-inflatable via a direct transfer) as the denominator/numerator of a share-price ratio — has a direct analog in ocore's own shipped Autonomous Agent (AA) reference design.

In Obyte, an AA's `balance[asset]` formula operator does not read a self-tracked "deposits ledger"; it reads the AA's literal on-chain balance, which is updated for **every** unit of value sent to the AA address, regardless of whether any `if` case in the AA's oscript matches: [1](#0-0) 

and read back via: [2](#0-1) 

This means anyone can inflate an AA's `balance[base]`/`balance[asset]` simply by sending it a plain payment that doesn't match any oscript case (it is silently absorbed, exactly like Bob's direct `transfer()` to the Surge `Pool`).

The shipped `uniswap_like_market_maker.oscript` sample (tested in `test/ojson.test.js`) computes AMM share-issuance/redemption ratios directly from `balance[base]` / `balance[$asset]`: [3](#0-2) [4](#0-3) 

This is structurally identical to Surge's `_supplied = _totalDebt + _loanTokenBalance` / `_accruedFeeShares = fee * _totalSupply / _supplied` pattern: the share-minting ratio is derived from a balance that an outside party can inflate for free before a victim's deposit is processed, and the same inflated balance is then used to price a later divesting/withdrawing party's payout.

### Title
Donation-inflatable `balance[asset]` used as share-price denominator enables fund-loss attack in AA reference AMM design - (File: `test/samples/uniswap_like_market_maker.oscript`)

### Summary
The market-maker AA example computes investor share issuance (`invest in MM` case) and divestment payouts (`divest MM shares` case) directly from `balance[base]`/`balance[$asset]`, which reflect the AA's raw on-chain balance. Because any unmatched or plain payment sent to an AA address is silently absorbed into that balance (per `aa_composer.js`'s `updateInitialAABalances`), an attacker can donate funds directly to the AA to inflate the balance without minting shares, then reap a disproportionate share of the pool on divestment — precisely mirroring Surge's `getCurrentState()`/`_loanTokenBalance` miscalculation.

### Finding Description
`updateInitialAABalances` in `aa_composer.js` adds **all** amounts from `trigger.outputs` (i.e., every payment output addressed to the AA in the triggering unit) into `aa_balances`/`assocBalances` before any oscript `if` condition is evaluated: [5](#0-4) 
This happens even if no `case` in the AA's `messages.cases` matches the trigger (the "no messages after filtering" path just performs the balance update and emits no response), so a bare/plain transfer to the AA address permanently and irreversibly raises `balance[base]`/`balance[asset]` for that AA.

The `uniswap_like_market_maker.oscript` reference design uses this manipulable balance as the pricing basis:
- Investment: `$bytes_balance = balance[base] - trigger.output[[asset=base]]` and `$issue_amount = round($investor_share_of_prev_balance * var['mm_asset_outstanding'])`.
- Divestment: `$investor_share = $mm_asset_amount / var['mm_asset_outstanding']`, payout `round($investor_share * balance[$asset])` / `round($investor_share * balance[base])`.

Because `var['mm_asset_outstanding']` (the tracked share supply) is only incremented on actual `invest` calls, while `balance[base]`/`balance[$asset]` can be inflated by a plain donation that never touches `mm_asset_outstanding`, an attacker can:
1. Make the first ("initial deposit") investment to obtain shares while `mm_asset_outstanding` is still small.
2. Send a large direct/plain payment of `base` to the AA (silently absorbed, no shares minted, `mm_asset_outstanding` unchanged).
3. Wait for a victim to invest; the victim's `$issue_amount = round($investor_share_of_prev_balance * var['mm_asset_outstanding'])` rounds down toward zero because `$bytes_balance` (denominator) is now huge relative to the victim's contribution, while their bytes/asset payment is still fully absorbed into the AA's balance.
4. Divest all attacker shares: `$investor_share = mm_asset_amount(attacker) / mm_asset_outstanding` is now close to 100% (since the victim got ~0 shares), so the attacker's payout is `round($investor_share * balance[asset])`/`round($investor_share * balance[base])` — i.e., essentially the entire pool, including the victim's deposit and the attacker's own earlier donation.

### Impact Explanation
A victim who calls the "invest" case can receive zero (or far fewer than expected) `mm_asset` shares while their `base`/asset payment is fully consumed into the AA's balance; the attacker who controls the timing of the donation can subsequently divest and capture that value. This is a concrete AA fund-loss scenario reachable by any ordinary AA trigger sender/asset issuer — no privileged role is required, matching the class of "unauthorized spending / AA fund loss" required by the validation rules.

### Likelihood Explanation
The attack requires only sending two plain payments (a donation, then a later divest) to a publicly known AA address running this or a derived design; no race condition, node collusion, or privileged access is needed. Any AA copying this officially shipped reference pattern (or any other AA using `balance[...]` directly as a share-price denominator without tracking "accounted-for" deposits separately from raw balance) is vulnerable. This is a design-level accounting flaw, not a low-probability edge case.

### Recommendation
Reference AA designs (and the underlying `balance[...]` guidance for AA authors) should track supplied/deposited amounts in AA state variables (`var[...]`) rather than deriving share-price ratios from the AA's raw `balance[asset]`/`balance[base]`, which can always be inflated by unsolicited direct transfers. Where `balance[...]` must be used, the AA should reconcile it against an explicitly tracked "accounted" balance and treat any discrepancy (donations) as protocol-owned rather than immediately reflecting it in per-share pricing formulas. Documentation/examples shipped with ocore (e.g., `uniswap_like_market_maker.oscript`) should be updated to demonstrate this safer accounting pattern so AA authors copying the example do not inherit the vulnerability.

### Proof of Concept
1. Deploy the `uniswap_like_market_maker.oscript` AA; call `trigger.data.define` to create `$mm_asset`.
2. Attacker sends the first "invest" trigger with `trigger.output[[asset=base]] = 100001` and matching `$asset` amount → `$asset_balance==0`/`$bytes_balance==0` branch taken, `$issue_amount = balance[base] = 100001`; `mm_asset_outstanding = 100001`.
3. Attacker sends a plain payment (no matching case) of, e.g., `10_000_000_000` bytes directly to the AA address → silently absorbed into `balance[base]` via `updateInitialAABalances`, `mm_asset_outstanding` unchanged.
4. Victim sends an "invest" trigger with a modest `base` amount (e.g., `200000`) plus the ratio-matching `$asset` amount computed against the now-inflated `$bytes_balance`; `$issue_amount = round(200000/ (~10,000,100,001) * 100001)` rounds to `0` or near-0 — victim receives (almost) no `mm_asset` shares despite fully paying in.
5. Attacker sends a "divest" trigger with all `100001` of its `mm_asset` shares; since `mm_asset_outstanding ≈ 100001`, `$investor_share ≈ 1`, and the attacker receives `round(1 * balance[$asset])`/`round(1 * balance[base])` — the entire pool, including the victim's contributed funds and the attacker's own earlier donation returned in full.

### Citations

**File:** aa_composer.js (L474-514)
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
		objValidationState.assocBalances[address] = {};
		var arrAssets = Object.keys(trigger.outputs);
		conn.query(
			"SELECT asset, balance FROM aa_balances WHERE address=?",
			[address],
			function (rows) {
				var arrQueries = [];
				// 1. update balances of existing assets
				rows.forEach(function (row) {
					if (constants.bTestnet && mci < testnetAAsDefinedByAAsAreActiveImmediatelyUpgradeMci)
						reintroduceBalanceBug(address, row);
					if (!trigger.outputs[row.asset]) {
						objValidationState.assocBalances[address][row.asset] = row.balance;
						return;
					}
					conn.addQuery(
						arrQueries,
						"UPDATE aa_balances SET balance=balance+? WHERE address=? AND asset=? ",
						[trigger.outputs[row.asset], address, row.asset]
					);
					objValidationState.assocBalances[address][row.asset] = row.balance + trigger.outputs[row.asset];
					if (objValidationState.assocBalances[address][row.asset] > MAX_BALANCE)
						bOverflow = true;
				});
```

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

**File:** test/samples/uniswap_like_market_maker.oscript (L33-66)
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
				messages: [
					{
						app: 'payment',
						payload: {
							asset: "{$mm_asset}",
							outputs: [
								{address: "{trigger.address}", amount: "{ $issue_amount }"}
							]
						}
					},
					{
						app: 'state',
						state: `{
							var['mm_asset_outstanding'] += $issue_amount;
						}`
					},
				]
			},
```

**File:** test/samples/uniswap_like_market_maker.oscript (L67-101)
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
					{
						app: 'state',
						state: `{
							var['mm_asset_outstanding'] -= trigger.output[[asset=$mm_asset]];
						}`
					},
				]
			},
```
