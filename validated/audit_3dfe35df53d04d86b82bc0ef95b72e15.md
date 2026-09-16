### Title
Early-depositor exchange-rate manipulation in the reference Uniswap-like market-maker AA template - (File: `test/samples/uniswap_like_market_maker.oscript`)

### Summary
The reference "Uniswap-like market maker" AA template shipped in the repo as an example oscript (`test/samples/uniswap_like_market_maker.oscript`, exercised by `test/ojson.test.js`) computes share issuance and redemption purely from the AA's *live* on-chain `balance[...]`, with no minimum-liquidity lock and no protection against balance donations that are not accompanied by a corresponding mint of the `mm_asset` share token. This reproduces exactly the ERC4626 "early depositor manipulates exchange rate" bug class from the cited report: a first depositor can set/skew the initial deposit ratio and later inflate the AA's underlying balance without minting new shares, causing rounding losses for subsequent depositors while capturing the surplus itself.

### Finding Description
The "invest in MM" case computes the number of `mm_asset` shares to mint from the ratio of live balances: [1](#0-0) 

- On the very first investment, `$asset_balance == 0 OR $bytes_balance == 0` is true, so `$issue_amount = balance[base]` — the depositor unilaterally sets the initial byte↔asset exchange ratio with no minimum-liquidity requirement enforced anywhere in the AA.
- After that, subsequent investors must match `$current_ratio` and receive shares proportional to `var['mm_asset_outstanding']`, using `round()` — i.e., rounding down, exactly like the Tokemak `LMPVault.sol` `convertToShares` rounding cited in the report.
- Divestment pays out `round($investor_share * balance[$asset])` / `round($investor_share * balance[base])`, i.e., proportional to whatever the AA's *actual* balance is at redemption time, not to a separately tracked reserve: [2](#0-1) 

Crucially, `balance[asset]`/`balance[base]` in AA formulas reflect the AA's real, live balance (as confirmed by `aa_composer.js`'s balance bookkeeping and `formula/evaluation.js`'s `readBalance`), not an internally-tracked "reserves" variable: [3](#0-2) [4](#0-3) 

Because every one of the AA's cases requires specific trigger shapes (`>1e5` bytes for invest/exchange-bytes-to-asset, `mm_asset` receipt for divest, `asset` receipt for exchange-asset-to-bytes), any trigger that does not fit one of these patterns falls through and causes the AA to bounce. Bounce logic keeps `bounce_fees.base` (a small fixed fee, default `constants.MIN_BYTES_BOUNCE_FEE`) permanently in the AA's balance while refunding the remainder to the sender: [5](#0-4) 

This lets an attacker who is the AA's dominant/sole `mm_asset` holder repeatedly send small out-of-pattern triggers (e.g., raw bytes below the `1e5` threshold) that bounce, each time permanently donating the bounce fee into the AA's real balance without any corresponding mint of `mm_asset`. Because redemption pays out a share of the *live* balance (`balance[base]`/`balance[$asset]`) rather than a tracked reserve, this donated balance inflates the effective exchange rate used for the `round()` calculations that all *other* depositors are subject to, while the attacker — owning all or most of the outstanding shares at the time — recaptures essentially the entire donated amount (plus the rounding losses forced onto other depositors) upon their own divestment.

### Impact Explanation
This is a direct analog of the reported "early depositor exchange-rate manipulation" class: an unprivileged AA trigger sender who is also the (near-)sole holder of the share asset can inflate the AA's tracked balance relative to `var['mm_asset_outstanding']` without minting shares, causing `round()`-based share/redemption calculations for subsequent, honest depositors to be skewed in the attacker's favor. Honest depositors receive fewer shares than their contribution is worth, and/or receive less back on divestment, while the attacker extracts the difference risk-free. This is a fund-loss/theft impact affecting any user who deposits into or interacts with an AA instance built from this pattern.

### Likelihood Explanation
Likelihood is bounded by the fact that this is a *sample/template* AA (not a protocol-level bug in `ocore`'s validation or consensus code) — it only manifests in deployed AA instances that copy this exact (or similarly-designed) code without adding minimum-liquidity locks or separately-tracked reserve accounting. However, because this template is shipped as official reference code for building market-maker/liquidity AAs on Obyte, any AA author who deploys it as-is (or a close derivative) exposes their users to this exact attack, and any address can trigger it — no special privileges are required, only being an early/dominant investor.

### Recommendation
- Require a minimum initial liquidity/lock (e.g., burn or permanently lock a minimum number of shares on first deposit, analogous to Uniswap V2's `MINIMUM_LIQUIDITY`) so a single actor cannot unilaterally fix the initial exchange rate with a negligible deposit.
- Track deposited reserves in AA state variables (e.g., `var['asset_reserve']`, `var['bytes_reserve']`) updated only on explicit invest/divest/swap operations, and use these tracked reserves — not the raw `balance[...]` — for all ratio and payout calculations, so that out-of-band donations (including bounce-fee dust) cannot silently change the price used to mint/redeem shares.
- Document this pattern requirement prominently alongside the sample AA so downstream authors copying the template are aware of the risk.

### Proof of Concept
1. Attacker A defines the `mm_asset` and becomes the sole depositor: sends `base > 1e5` bytes plus `asset > 0`; since `$asset_balance == 0 OR $bytes_balance == 0`, `$issue_amount = balance[base]`, and A receives all outstanding `mm_asset` shares 1:1 with bytes deposited (`test/samples/uniswap_like_market_maker.oscript:33-48`).
2. Attacker A repeatedly sends dust triggers that match none of the defined cases (e.g., raw bytes below the `1e5` invest/exchange threshold, and not a `mm_asset`/`asset` payment). Each such trigger bounces per `aa_composer.js` `bounce()` logic, permanently leaving `bounce_fees.base` in the AA's balance while refunding the rest (`aa_composer.js:909-945`).
2. This inflates `balance[base]` relative to `var['mm_asset_outstanding']` without minting any new shares.
3. Honest depositor B now invests: `$current_ratio`/`$investor_share_of_prev_balance` are computed against the inflated `balance[base]`, and B's minted `$issue_amount = round($investor_share_of_prev_balance * var['mm_asset_outstanding'])` is reduced by the rounding-down effect of the inflated denominator (`test/samples/uniswap_like_market_maker.oscript:36-47`).
4. Attacker A later divests: `$investor_share = mm_asset_amount / var['mm_asset_outstanding']`; since A holds all (or nearly all) shares, A's payout of `round($investor_share * balance[base])`/`round($investor_share * balance[$asset])` recovers essentially the full donated bounce-fee dust plus the value siphoned from B's under-minted shares (`test/samples/uniswap_like_market_maker.oscript:70-83`).

### Citations

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

**File:** test/samples/uniswap_like_market_maker.oscript (L67-100)
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

**File:** aa_composer.js (L909-945)
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
	}
```
