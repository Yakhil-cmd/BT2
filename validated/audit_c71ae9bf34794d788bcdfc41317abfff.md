### Title
First-depositor share-rounding attack in the Obyte "Uniswap-like market maker" AA reference implementation - (File: test/samples/uniswap_like_market_maker.oscript)

### Summary
The `uniswap_like_market_maker.oscript` sample AA shipped in the ocore repository as the canonical reference pattern for building AMM/liquidity-pool style Autonomous Agents mints its LP-style `mm_asset` share tokens using unchecked integer `round()` division against a `var['mm_asset_outstanding']` counter that starts at whatever amount the very first depositor chooses to mint. This reproduces the classic Compound/ERC-4626 "first depositor" bug: an attacker who is first to invest can mint the initial share supply at an arbitrarily small size, then a subsequent, legitimate depositor's proportional contribution can round down to zero newly-minted shares while their funds are still added to the AA's balance, letting the attacker capture the diluted depositor's funds on divestment.

### Finding Description
In the "invest in MM" case, the very first deposit sets `mm_asset_outstanding` to whatever the depositor chooses: [1](#0-0) 
```
if ($asset_balance == 0 OR $bytes_balance == 0){ // initial deposit
    $issue_amount = balance[base];
    return;
}
```
Because there is no minimum-liquidity lock or virtual share offset, the first investor can mint the pool with a minimal amount (e.g. 1-2 base units), setting `mm_asset_outstanding` to a tiny integer.

Subsequent deposits mint new shares proportionally, using integer `round()`: [2](#0-1) 
```
$current_ratio = $asset_balance / $bytes_balance;
$expected_asset_amount = round($current_ratio * trigger.output[[asset=base]]);
if ($expected_asset_amount != trigger.output[[asset=$asset]])
    bounce('wrong ratio of amounts, expected ' || $expected_asset_amount || ' of asset');
$investor_share_of_prev_balance = trigger.output[[asset=base]] / $bytes_balance;
$issue_amount = round($investor_share_of_prev_balance * var['mm_asset_outstanding']);
```
When `mm_asset_outstanding` is very small (as it is right after a minimal first deposit), `round($investor_share_of_prev_balance * var['mm_asset_outstanding'])` can evaluate to `0` for a legitimate second depositor whose proportional share of the tiny outstanding supply rounds down, even though their base/asset contribution is correctly added to `balance[base]`/`balance[$asset]`. The attacker's pre-existing (single) unit of `mm_asset` now represents a claim on the enlarged pool balance.

On divestment, the payout is computed purely from the ratio of `mm_asset` held to `mm_asset_outstanding`: [3](#0-2) 
```
$mm_asset_amount = trigger.output[[asset=$mm_asset]];
$investor_share = $mm_asset_amount / var['mm_asset_outstanding'];
...
{address: "{trigger.address}", amount: "{ round($investor_share * balance[$asset]) }"}
...
{address: "{trigger.address}", amount: "{ round($investor_share * balance[base]) }"}
```
so the attacker, holding the entire outstanding share supply, redeems the full (now-inflated) `balance[$asset]`/`balance[base]`, including the value contributed by the diluted depositor.

This is the direct analog of the reported CToken bug: `mintFresh`'s `mintTokens = div_(actualMintAmount, exchangeRate)` can round to a value that shortchanges a depositor when `totalSupply` is near zero, letting the first minter (who inflated the exchange rate) capture the difference. The ocore sample AA has the same structural flaw: shares minted via `round()` against an attacker-controlled, unbounded-low `mm_asset_outstanding`.

### Impact Explanation
Because this file is shipped in the ocore repository's `test/samples` directory and parsed/validated by `test/ojson.test.js` as the documented "Uniswap-like market maker" template, it is the reference pattern AA authors are expected to copy when building liquidity-pool AAs on Obyte. Any AA deployed by following this pattern verbatim is exploitable: an attacker who front-runs the pool's creation (mints the first, minimal amount of `mm_asset`) can subsequently cause later depositors' contributions to mint zero shares due to integer rounding, and redeem the diluted depositors' funds via the divest case. This results in direct theft of depositor/investor funds routed through the AA, matching the "Medium/High" impact bar (unauthorized fund loss via an AA).

### Likelihood Explanation
The attack requires no privileged access — any address ("AA trigger sender") can be first to send the "invest" trigger to a freshly-deployed instance of this AA pattern, and any subsequent depositor is at risk as long as `mm_asset_outstanding` remains small (a single malicious minimal first deposit is sufficient; the attacker does not even need to prevent the legitimate deposit, only to arrive first with a tiny amount). This is a low-cost, single-transaction setup exploitable by an unprivileged actor.

### Recommendation
Update the reference `uniswap_like_market_maker.oscript` sample (and any documentation derived from it) to:
- Enforce a minimum initial liquidity/share amount on first deposit (e.g. require `balance[base]` and the matching asset amount to exceed a floor, or mint a fixed "dead" minimum share amount that is permanently locked, similar to Uniswap V2's `MINIMUM_LIQUIDITY` burn).
- Bounce deposits whose computed `$issue_amount` would round to `0`, instead of silently accepting the funds without minting shares, so no depositor's contribution can be absorbed for zero shares.
- Consider using higher-precision internal accounting (e.g. scaling `mm_asset_outstanding` by a large fixed factor) to reduce rounding error at low outstanding-supply levels.

### Proof of Concept
1. Attacker (Alice) sends the `define` trigger to instantiate the `mm_asset`.
2. Alice sends a minimal "invest" trigger (e.g. 2 base units + matching minimal amount of `$asset`), triggering the initial-deposit branch: `$issue_amount = balance[base]` → `mm_asset_outstanding` becomes a very small integer (e.g. `2`).
3. Bob (legitimate depositor) sends a proportionally correct "invest" trigger with a normal-sized deposit. Because `var['mm_asset_outstanding']` is tiny, `round($investor_share_of_prev_balance * var['mm_asset_outstanding'])` rounds down to `0`; Bob receives no `mm_asset` shares, yet his base/asset amounts are added to `balance[base]`/`balance[$asset]`.
4. Alice sends a "divest" trigger with her `mm_asset` holdings; `$investor_share = mm_asset_amount / mm_asset_outstanding` evaluates to `1` (she holds all outstanding shares), and she is paid `balance[$asset]` and `balance[base]` in full — including Bob's contributed funds.

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
