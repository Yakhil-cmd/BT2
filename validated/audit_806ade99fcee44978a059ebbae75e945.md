This confirms the key mechanism: when an AA is triggered, `updateInitialAABalances` unconditionally adds the trigger's outputs to the AA's persistent `aa_balances` before any case-matching or bounce logic runs <cite repo="Ellentat/ocore--012" path="aa_composer.js" start="474,481,482,483" end="474,481,482,483" />, and even when a trigger "bounces" (e.g. `if (!err) return bounce(err)` at [1](#0-0) ), the AA keeps at least the configured `bounce_fees` while refunding the rest <cite repo="Ellentat/ocore--012" path="aa_composer.js" start="446,448" end="446,448" />. This is the exact mechanism that makes the reported ERC20-donation/first-depositor share-inflation bug class reachable in ocore's oscript AAs.

The documented sample AAs (shipped in the repo as canonical patterns, e.g. `test/samples/uniswap_like_market_maker.oscript`) implement share/LP-style accounting using the live `balance[asset]` builtin rather than an internally tracked deposit total, exactly the anti-pattern that caused the referenced Sherlock finding:

```
$asset_balance = balance[$asset] - trigger.output[[asset=$asset]];
$bytes_balance = balance[base] - trigger.output[[asset=base]];
if ($asset_balance == 0 OR $bytes_balance == 0){ // initial deposit
    $issue_amount = balance[base];
    return;
}
``` [2](#0-1) 

and later uses `balance[$asset]` / `balance[base]` directly (not an internally tracked pooled amount) to price divestment and swaps [3](#0-2) [4](#0-3) .

### Title
Share/LP-token pricing based on live `balance[asset]` enables first-depositor donation/inflation attack in AA templates - (File: test/samples/uniswap_like_market_maker.oscript)

### Summary
The market-maker style AA pattern shipped as a reference template computes LP-share ("mm_asset") issuance and redemption ratios from the AA's live on-chain balance (`balance[base]`, `balance[$asset]`) rather than from an independently tracked pool total. Because `balance[...]` reflects every unit of value the AA address has ever received — including amounts sent by any third party through unrelated or non-matching triggers — an attacker can inflate the denominator before the first genuine LP deposit or before a divest/swap operation, exactly mirroring the classic first-depositor share-price manipulation ("donation attack") from the referenced Sherlock report.

### Finding Description
In Obyte AAs, whenever any unit sends outputs to an AA address, `updateInitialAABalances()` unconditionally credits those outputs to the AA's persistent `aa_balances` table before any `case`/`if` logic or bounce decision runs [5](#0-4) . Even when the trigger fails every `if` condition and the AA "bounces," it still retains the configured `bounce_fees` for each asset while refunding the remainder [6](#0-5) [7](#0-6) . Formula evaluation of `balance[asset]` (and `balance[address][asset]`) simply reads this live, attacker-influenceable balance from `objValidationState.assocBalances`/`aa_balances` [8](#0-7) .

The market-maker template uses exactly this live balance to determine (a) whether a deposit is the "initial deposit" and how many shares to mint, and (b) the AMM price and divestment payout:
```
$asset_balance = balance[$asset] - trigger.output[[asset=$asset]];
$bytes_balance = balance[base] - trigger.output[[asset=base]];
if ($asset_balance == 0 OR $bytes_balance == 0){ // initial deposit
    $issue_amount = balance[base];
    return;
}
``` [2](#0-1) 
and
```
$mm_asset_amount = trigger.output[[asset=$mm_asset]];
$investor_share = $mm_asset_amount / var['mm_asset_outstanding'];
...
amount: "{ round($investor_share * balance[$asset]) }"
``` [9](#0-8) 

Because `var['mm_asset_outstanding']` (the tracked share supply) is a separate variable from `balance[...]` (the actual coin holdings), any party can send bytes or the paired asset directly to the AA's address in a way that increments `balance[]` without proportionally increasing `mm_asset_outstanding`. This desynchronizes the share-to-asset ratio: a subsequent depositor's minted shares are computed as `round($investor_share_of_prev_balance * var['mm_asset_outstanding'])` against an inflated `$bytes_balance`, rounding their entitlement down (potentially to zero for small deposits), while the party who inflated the balance (or who already holds shares) captures the donated value upon divestment through `round($investor_share * balance[$asset])` / `round($investor_share * balance[base])`. This is the same rounding-to-zero mechanism described in the reference report: `shares = X/(X+1) = 0`.

### Impact Explanation
An attacker who is first to hold a nonzero share balance (or who front-runs a legitimate depositor) can donate funds directly to the AA's balance to skew the `bytes_balance`/`asset_balance` used in share-minting and price formulas. Later, genuine depositors receive zero or negligible shares for real value contributed, while the attacker's existing shares entitle them to redeem the donated value on divestment. This is a direct fund-loss/theft vector for AA users of this deployed pattern — unauthorized transfer of value from later depositors to an earlier depositor/attacker, matching the accepted impact categories (AA fund loss).

### Likelihood Explanation
The attack requires only sending an ordinary payment (base bytes and/or the paired asset) to the target AA's address — something any unprivileged unit poster/AA trigger sender can always do — and does not require compromising the AA's logic or any privileged role. Because `balance[]` is guaranteed by ocore's `aa_composer.js` semantics to reflect all coins ever received by the address regardless of whether a case matched, the precondition for the attack (denominator manipulable independent of tracked share supply) is a structural property of the platform's balance accounting, not merely author error — making this class of bug apply to any AA reusing this common documented pattern.

### Recommendation
Reference AA templates and documentation should not use the raw `balance[asset]`/`balance[base]` builtins as the denominator for share/LP pricing. Instead, they should track total pooled deposits in dedicated state variables (e.g. `var['pool_base']`, `var['pool_asset']`) that are updated only through the AA's own accounted deposit/divest logic, and reject/refund any received funds that do not correspond to a recognized operation, so that unsolicited transfers cannot influence the price/ratio calculations. Additionally, enforce a minimum initial deposit (analogous to Uniswap's locked minimum liquidity) to make the initial-price-setting step economically unexploitable.

### Proof of Concept
1. AA author deploys the `uniswap_like_market_maker.oscript` pattern and defines the `mm_asset` (share asset).
2. Before any real investor deposits, attacker sends a bare payment of `$asset` (paired asset) directly to the AA address in a way that doesn't match the "invest" case's exact ratio check (e.g., sending it alone, hitting the "exchange asset to bytes" case is guarded by `var['mm_asset_outstanding']` being falsy, so it bounces) — but bounce still retains `bounce_fees.base` bytes for every failed attempt [7](#0-6) , permanently inflating `balance[base]` at near-zero net cost.
3. When the first legitimate investor deposits `X` bytes and the matching `$asset` amount, `$issue_amount = balance[base]` is computed after the trigger's own output is added, folding in all previously donated dust [10](#0-9) , corrupting `mm_asset_outstanding` relative to `balance[base]`.
4. Every subsequent depositor's `$issue_amount = round($investor_share_of_prev_balance * var['mm_asset_outstanding'])` is now computed against the corrupted `$bytes_balance`, causing rounding losses (down to zero shares for small deposits) that accrue to whoever holds the outstanding shares when they divest via `round($investor_share * balance[base])` [11](#0-10) [12](#0-11) .

### Citations

**File:** aa_composer.js (L446-448)
```javascript
	var bounce_fees = template.bounce_fees || {base: constants.MIN_BYTES_BOUNCE_FEE};
	if (!bounce_fees.base)
		bounce_fees.base = constants.MIN_BYTES_BOUNCE_FEE;
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

**File:** aa_composer.js (L1844-1845)
```javascript
		if (err)
			return bounce(err);
```

**File:** aa_composer.js (L1851-1859)
```javascript
		if (!bSecondary) {
			if ((trigger.outputs.base || 0) < bounce_fees.base) {
				return bounce('received bytes are not enough to cover bounce fees');
			}
			for (var asset in trigger.outputs) { // if not enough asset received to pay for bounce fees, ignore silently
				if (bounce_fees[asset] && trigger.outputs[asset] < bounce_fees[asset]) {
					return bounce('received ' + asset + ' is not enough to cover bounce fees');
				}
			}
```

**File:** test/samples/uniswap_like_market_maker.oscript (L35-47)
```text
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
