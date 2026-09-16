### Title
First-deposit share pricing in the Uniswap-like market-maker AA can be re-triggered to mint disproportionate shares and steal pool value - (File: test/samples/uniswap_like_market_maker.oscript)

### Summary
The `uniswap_like_market_maker.oscript` AA sample issues its `mm_asset` liquidity-share token using a "first deposit" heuristic that checks only whether the *current asset balances* are zero, not whether the outstanding share supply (`var['mm_asset_outstanding']`) is zero. Because the two conditions can diverge during the AA's normal life-cycle (asset balance can be fully drained to zero by the built-in swap logic while `mm_asset_outstanding` remains positive), an attacker can re-trigger the "initial deposit" branch after shares already exist, minting shares priced at `balance[base]` instead of the correct pro-rata ratio. This is the same class of bug as the ERC4626 "first depositor / donation" price-per-share manipulation described in the report, adapted to Obyte AA share accounting.

### Finding Description
In the `invest in MM` case: [1](#0-0) 

```
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

The "initial deposit" branch is meant to fire only once — the very first time anyone invests, when both `$asset_balance` (pre-trigger `balance[$asset]`) and `$bytes_balance` (pre-trigger `balance[base]`) are 0 and `mm_asset_outstanding` is therefore also 0. However, the guard is written against the raw asset balances, not against `var['mm_asset_outstanding']`. The `exchange asset to bytes` case can legitimately drain `balance[$asset]` to exactly zero while shares are still outstanding: [2](#0-1) 

Once `balance[$asset]` (or, less likely but symmetric, `balance[base]`) reaches 0 while `mm_asset_outstanding` > 0, any subsequent "invest" trigger re-enters the "initial deposit" branch. In that branch, `$issue_amount` is set to the *entire current* `balance[base]` (which already includes all bytes previously accumulated by other investors' capital, fees, etc.), not the caller's proportional contribution, and the ratio check against existing outstanding shares is skipped entirely.

### Impact Explanation
An attacker who drives the `$asset` balance to zero (via the built-in `exchange asset to bytes` swap path, potentially across several transactions, since they only need to be the one to make the balance hit exactly 0 right before their deposit) can then deposit a small amount of `base` bytes and receive `mm_asset` shares equal to the AA's *full current byte balance* rather than their fair share. This lets them mint far more shares than their contribution warrants, then call the `divest MM shares` case to redraw a disproportionate share of both `$asset` and `base` balances belonging to earlier depositors: [3](#0-2) 

This results in direct fund loss for other liquidity providers/shareholders and supply inflation of the `mm_asset` share token relative to actual backing — the same economic harm as the ERC4626 first-depositor exploit.

### Likelihood Explanation
Reaching `$asset_balance == 0` requires driving the pool's `$asset` reserve to exactly zero through the permissionless `exchange asset to bytes`/`exchange bytes to asset` swap cases, which are freely callable by any address at any time. Since these are integer-rounded exchanges (`round($p / balance[...])`), hitting an exact zero residual is plausible especially for small pools or via repeated small swaps designed to zero out the last unit. Because the AA has no explicit check that `var['mm_asset_outstanding'] == 0` before re-entering the "initial deposit" pricing branch, this is a straightforward, unprivileged, single-attacker exploit reachable purely by posting ordinary triggers to the AA.

### Recommendation
Gate the "initial deposit" pricing branch on `var['mm_asset_outstanding'] == 0` (or explicitly on `!var['mm_asset_outstanding']`) instead of on the raw `$asset_balance`/`$bytes_balance` being zero, e.g.:
```
if (!var['mm_asset_outstanding']){ // true initial deposit
    $issue_amount = balance[base];
    return;
}
```
This ensures that once any shares are outstanding, all subsequent deposits are always priced by the pro-rata ratio formula, regardless of whether one of the two underlying reserves has been temporarily drained to zero.

### Proof of Concept
1. AA is created and `define` is called; `mm_asset` is defined and `var['mm_asset_outstanding']` starts at 0.
2. Legitimate user A invests, e.g. sends `base=1e6` and matching `$asset` amount; since balances were 0, the "initial deposit" branch fires, `$issue_amount = balance[base] = 1e6`, and `var['mm_asset_outstanding'] = 1e6` shares are issued to A (see lines 33-65).
3. Attacker (or anyone) repeatedly calls the `exchange asset to bytes` case, sending `$asset` in and receiving `base` out, until `balance[$asset]` is driven to exactly 0 (lines 124-145). `mm_asset_outstanding` remains `1e6` (unchanged by swaps).
4. Attacker now sends a new "invest" trigger with a small `base` amount (e.g. `1e5+1`) and any positive `$asset` amount. Because `$asset_balance` computed before this trigger is 0, the code re-enters the "initial deposit" branch and sets `$issue_amount = balance[base]`, which by now equals the pool's entire accumulated bytes balance (potentially far larger than the attacker's own `1e5+1` deposit) — see lines 35-41.
5. Attacker is minted shares representing the whole current `base` balance in addition to the `1e6` shares already held by A, then immediately calls "divest MM shares" (lines 67-100) to redeem a disproportionate amount of `base`/`$asset`, extracting value contributed by A.

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
