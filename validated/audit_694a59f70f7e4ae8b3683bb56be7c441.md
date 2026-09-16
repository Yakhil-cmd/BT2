Found a direct analog of the ERC4626-style first-depositor inflation attack in the Obyte AA sample template shipped with ocore.

### Title
Uniswap-like Market Maker AA template is vulnerable to a first-deposit share-inflation attack - (File: `test/samples/uniswap_like_market_maker.oscript`)

### Summary
The bundled "Uniswap-like market maker" Autonomous Agent (AA) template issues LP-style shares (`mm_asset`) to depositors based on the ratio of their deposit to the AA's existing reserves. On the very first deposit, the AA unconditionally sets `$issue_amount = balance[base]` with no minimum-liquidity lock and no protection against a near-zero initial pool, exactly mirroring the ERC4626 "inflation attack" root cause described in the external report.

### Finding Description
In the "invest in MM" case, the AA computes: [1](#0-0) 

When `$asset_balance == 0 OR $bytes_balance == 0` (i.e., this is the first deposit), the AA sets `$issue_amount = balance[base]` and returns immediately — there is no floor amount permanently locked and no minimum deposit requirement to prevent a share-price manipulation. For all subsequent deposits, share issuance is computed as `round($investor_share_of_prev_balance * var['mm_asset_outstanding'])`, using integer rounding just like the vulnerable `amount * _totalSupply / _pool` formula in the referenced Solidity report.

This lets an attacker who triggers the AA first mint 1 wei-equivalent of `mm_asset` for a minimal `base` deposit (e.g. 1 unit above the `1e5` threshold), then "donate" a large amount of `base` directly to the AA address (a plain payment to the AA's address increases `balance[base]` without triggering the investment case logic, since a bare payment is a valid trigger that simply adds to the AA's byte balance). This distorts `$bytes_balance` relative to `var['mm_asset_outstanding']`. When a victim then deposits, `round($investor_share_of_prev_balance * var['mm_asset_outstanding'])` rounds down to a much smaller share count than fair, due to the artificially inflated `$bytes_balance` denominator versus the tiny `mm_asset_outstanding` numerator base.

### Impact Explanation
A successful attack lets the attacker's minimal initial share redeem a disproportionate fraction of the victim's later deposit when divesting via `round($investor_share * balance[base])` and `round($investor_share * balance[$asset])`: [2](#0-1) 
This constitutes direct theft of AA-held funds (both `base` bytes and the paired asset) from a legitimate depositor — matching the "AA fund loss" impact criteria.

### Likelihood Explanation
The template is presented as a ready-to-use AA pattern in ocore's own sample/test suite and is also mirrored verbatim in `test/ojson.test.js`, indicating it is intended as a reference implementation for AA authors building market-maker/liquidity-pool AAs on the network. Any AA author who deploys this exact pattern (or a close variant) without adding minimum-liquidity locks is exploitable by any unprivileged trigger sender able to fund two triggers (an initial tiny deposit and a raw donation payment) before a victim's deposit — a low-cost, easily repeatable griefing/theft vector whenever pool reserves are near zero (e.g., right after AA creation).

### Recommendation
Update the template (and any documentation referencing it) to:
- Lock a fixed minimum number of shares on the first deposit (permanently unredeemable, similar to OpenZeppelin's ERC4626 "virtual shares/assets" or dead-share mitigation), instead of minting shares 1:1 with `balance[base]`.
- Enforce a minimum first-deposit size so the initial share price cannot be trivially set by a 1-unit deposit.
- Consider tracking deposits exclusively through explicit `var['mm_asset_outstanding']` and reserve variables rather than deriving ratios from `balance[...]`, which can be inflated by plain (non-triggering-case) payments sent directly to the AA address.

### Proof of Concept
1. Attacker sends a trigger with `trigger.output[[asset=base]] = 1e5+1` and `trigger.output[[asset=$asset]] = 1` while `var['mm_asset_outstanding']` is unset (pool empty). Since `$asset_balance == 0`, the AA sets `$issue_amount = balance[base]` (≈1e5+1) and mints that many `mm_asset` shares to the attacker, per [3](#0-2) .
2. Attacker sends a plain payment of a large amount of `base` (and paired asset) directly to the AA's address (not matching any `if` case, so it just increases `balance[base]`/`balance[$asset]` without changing `var['mm_asset_outstanding']`).
3. Victim deposits proportionally, expecting fair share issuance, but `$investor_share_of_prev_balance = trigger.output[[asset=base]] / $bytes_balance` is computed against the attacker-inflated `$bytes_balance`, so `round(... * var['mm_asset_outstanding'])` rounds down to far fewer shares than deposited value warrants, per [4](#0-3) .
4. Attacker divests all shares via the "divest MM shares" case, receiving `round($investor_share * balance[$asset])` and `round($investor_share * balance[base])`, capturing a disproportionate share of the victim's deposit, per [2](#0-1) .

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

**File:** test/samples/uniswap_like_market_maker.oscript (L67-99)
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
```
