Based on the report's bug class — **failing to reconcile an internal "supply/outstanding" accounting variable with the actual on-chain balance when that balance transiently hits zero, causing later over-minting** — I found a direct structural analog in ocore's bundled Uniswap-like market-maker AA sample.

### Title
Share-token over-minting when pool reserve hits zero while `mm_asset_outstanding` is nonzero — ([File: test/samples/uniswap_like_market_maker.oscript])

### Summary
The `uniswap_like_market_maker.oscript` AA tracks the total outstanding LP-share supply in the state variable `var['mm_asset_outstanding']`, which is supposed to always match the sum of shares issued against the pool's actual reserves (`balance[base]`, `balance[$asset]`). The "invest" branch uses a shortcut: whenever either reserve currently equals zero, it treats the deposit as a fresh "initial deposit" and issues `$issue_amount = balance[base]` shares, without regard to whatever `mm_asset_outstanding` already holds. This mirrors the AMKT `tryInflation()` bug: a value derived from "total supply" is used to gate a shortcut path, but the shortcut does not reconcile/reset the tracked outstanding-supply state, so if that state is nonzero when the shortcut fires, share accounting becomes permanently inconsistent and can be inflated arbitrarily by the next depositor.

### Finding Description
The relevant code: [1](#0-0) 

```
{ // invest in MM
    if: `{$mm_asset AND trigger.output[[asset=base]] > 1e5 AND trigger.output[[asset=$asset]] > 0}`,
    init: `{
        $asset_balance = balance[$asset] - trigger.output[[asset=$asset]];
        $bytes_balance = balance[base] - trigger.output[[asset=base]];
        if ($asset_balance == 0 OR $bytes_balance == 0){ // initial deposit
            $issue_amount = balance[base];
            return;
        }
        ...
    }`,
```

`$asset_balance` and `$bytes_balance` are the pool's pre-deposit reserves (balance minus what this trigger just deposited). If either reserve is zero, the code assumes this is the *very first* deposit ever and mints `$issue_amount = balance[base]` share tokens unconditionally — it never checks whether `var['mm_asset_outstanding']` is also zero.

The "exchange" branches use a constant-product AMM formula with integer rounding: [2](#0-1) 

Because `$new_asset_balance = round($p / balance[base])` is computed with `round()`, a sufficiently large/extreme swap (a single large `trigger.output[[asset=base]]` payment) can round one reserve down to exactly 0 while the pool still has outstanding LP shares recorded in `var['mm_asset_outstanding']` (analogous to `totalSupply()` staying nonzero as balances went to zero in the AMKT report, except here it's the reverse: reserves hit zero while share supply is still nonzero).

Once a reserve is 0, any unprivileged trigger sender can call the "invest" case again. The code takes the "initial deposit" branch, minting `$issue_amount = balance[base]` new shares — potentially the *entire* current byte balance's worth of shares — on top of the already-existing `mm_asset_outstanding`, instead of computing a share amount proportional to the depositor's contribution relative to the existing supply. This is exactly the same root cause pattern as the report: a state variable used for proportional accounting (`trackedMultiplier`/`lastKnownTimestamp` there, `mm_asset_outstanding` here) is not reconciled at the moment a boundary condition (zero) is hit, so a later normal-looking operation applies stale/incorrect math against the true supply.

### Impact Explanation
An attacker (or two colluding unprivileged trigger senders — one to zero out a reserve via a large swap, another, possibly the same address, to redeposit) can mint a disproportionate number of LP shares relative to the value actually contributed. Because `var['mm_asset_outstanding'] += $issue_amount` is unconditionally applied afterward, this permanently corrupts the share-to-reserve ratio, allowing the attacker to redeem existing pool reserves (`balance[$asset]`, `balance[base]`) far in excess of their true economic contribution when they later call the "divest" case, at the expense of other LPs. This is a direct, unauthorized value-extraction / fund-loss vulnerability for an AA that implements this well-known bundled reference pattern.

### Likelihood Explanation
Reachable entirely by unprivileged AA trigger senders posting normal payment-triggered units — no special privileges, witnessing, or network position required. The precondition (rounding one reserve to exactly zero via a large single swap) requires a large but not privileged transaction, and integer `round()` on any sufficiently skewed pool state can produce a zero reserve. Any AA deployed from this bundled sample template is exposed as-is.

### Recommendation
Do not gate the "initial deposit" shortcut solely on reserve balances being zero. Instead, key the shortcut off `var['mm_asset_outstanding']` itself: only treat the deposit as a true "initial" deposit (mint `balance[base]` shares 1:1) when `var['mm_asset_outstanding']` is also zero/undefined. If a reserve is zero but `mm_asset_outstanding` is nonzero, the pool is in a degenerate state and should either bounce the deposit or use a formula that respects the existing outstanding-share accounting (e.g., pro-rate against the last known valid ratio, or require both reserves and outstanding shares to be reset together).

### Proof of Concept
1. Deploy the AA; an initial LP deposits, `mm_asset_outstanding = N` shares are minted proportional to their contribution.
2. A trader (attacker) sends one very large `base` payment via the "exchange bytes to asset" case; due to `round($p / balance[base])`, `$new_asset_balance` rounds to `0`, driving `balance[$asset]` to (near) zero while `mm_asset_outstanding` remains `N`.
3. The attacker (or an accomplice) immediately triggers the "invest" case with a small `base` + `asset` deposit. Since `$asset_balance == 0`, the AA takes the `// initial deposit` branch and mints `$issue_amount = balance[base]` (the full current byte reserve) as new shares, added on top of the untouched `mm_asset_outstanding = N`.
4. The attacker now holds a share count wildly disproportionate to their actual contribution and can divest to drain reserves belonging to earlier LPs.

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
