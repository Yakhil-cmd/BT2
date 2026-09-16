## Title
Zero-share deposit / permanent fund-lock in the Uniswap-like market-maker AA due to missing "non-zero shares minted" check — ([File: test/samples/uniswap_like_market_maker.oscript])

### Summary
The `uniswap_like_market_maker.oscript` sample AA shipped in this repo implements an LP-share ("`mm_asset`") accounting scheme that is structurally identical to the vulnerable `TradingVaultV2` pattern described in the report: the number of shares minted for a deposit is computed as a ratio against the *current* pool balances/outstanding-share counter, with no floor-protection ensuring the minted amount is non-zero and no Uniswap-V2-style permanent minimum-liquidity lock. This allows the LP-share exchange rate to be driven to a state (`var['mm_asset_outstanding'] == 0` while `balance[base]`/`balance[$asset]` are non-zero) in which any further depositor mints exactly `0` shares for a real, non-trivial deposit, permanently donating/locking their funds in the AA.

### Finding Description
On the very first deposit, the AA sets the initial exchange rate arbitrarily from whatever the first LP sends: [1](#0-0) 

For all subsequent deposits, the newly minted share amount is:
```
$issue_amount = round($investor_share_of_prev_balance * var['mm_asset_outstanding']);
``` [2](#0-1) 

On divestment, each LP's payout is computed independently via `round($investor_share * balance[...])` for both legs, and `mm_asset_outstanding` is decremented by the redeemed amount: [3](#0-2) 

Because two separate `round()` operations (one per asset leg) are performed independently for each partial divest, the sum of amounts paid out to LPs when the last unit of `mm_asset` is redeemed does not necessarily equal the full pool balance — small dust amounts of `base` and/or `$asset` can remain in the AA's balance while `var['mm_asset_outstanding']` reaches exactly `0`.

When the next depositor arrives, the "initial deposit" branch is only taken `if ($asset_balance == 0 OR $bytes_balance == 0)`. If dust remains in *both* legs, this check is `false`, so the code falls into the ratio-based branch and computes:
```
$issue_amount = round($investor_share_of_prev_balance * var['mm_asset_outstanding']);
```
with `var['mm_asset_outstanding'] == 0`. This makes `$issue_amount` exactly `0` regardless of how large the new deposit is (as long as it matches the dust ratio, which is trivial to satisfy with a large amount at the same 1:1-ish ratio as the dust). The depositor's tokens/bytes are absorbed into the AA balance, `var['mm_asset_outstanding']` stays `0`, and there is no code path — since nobody holds `mm_asset` and any future mint from the same branch will also multiply by `0` — that can ever restore a positive outstanding-share supply and unlock these funds. This mirrors exactly the report's root cause: absence of `require(_shares != 0, "zero shares minted")` and absence of the Uniswap V2 "burn to zero address" floor, applied here to an oscript AA (`app: 'asset'` shares defined at lines 8-31; the vulnerable math at lines 33-48).

### Impact Explanation
Any user (an unprivileged AA trigger sender) who deposits into this AA after it has been fully divested to `mm_asset_outstanding == 0` with leftover dust can lose 100% of their deposited funds — they receive zero LP shares, and the deposited bytes/asset become permanently stuck in the AA with no mechanism to redeem them, since no one holds `mm_asset` to trigger the divest case and any further "invest" attempts from that same dust state also mint zero shares. This is a fund-freezing / fund-loss condition matching the accepted "AA fund loss or freezing" impact category.

### Likelihood Explanation
Reaching the trigger state requires only ordinary usage of the AA: an initial deposit followed by full divestment by the pool's LP(s) (which naturally occurs in a market-maker AA's lifecycle), leaving small unavoidable rounding dust in both `base` and `$asset` balances. Any subsequent legitimate depositor who is unaware of this internal dust state is affected without needing any special attacker privileges — the same "first depositor" ratio-and-rounding flaw class described in the external report, just triggered by dust from a full round-trip rather than a single wei deposit.

### Recommendation
- When `var['mm_asset_outstanding']` is `0` (whether at genesis or after being fully redeemed), always take the "initial deposit" branch and reset the exchange rate from the depositor's own contribution instead of relying on `$asset_balance == 0 OR $bytes_balance == 0`.
- Explicitly `bounce()` if the computed `$issue_amount` is `0`, so that a depositor never silently loses funds: `if (!$issue_amount) bounce('zero shares minted');`.
- Optionally, on the very first mint, permanently allocate a small minimum amount of `mm_asset` to a burn address (as in Uniswap V2) to prevent share-price manipulation and to guarantee `var['mm_asset_outstanding']` never returns to exactly `0` while real value remains in the pool.

### Proof of Concept
1. AA is deployed with `var['mm_asset_outstanding']` unset (`0`) and empty balances.
2. LP1 sends `base = 100001`, `asset = 100` → matches "invest MM" case, `$asset_balance == 0` branch taken → `$issue_amount = balance[base] = 100001`; `mm_asset_outstanding = 100001`.
3. LP1 performs several small swaps (`exchange asset to bytes` / `exchange bytes to asset` cases, lines 102-145) which apply `round()` on each trade, shifting balances slightly off the clean ratio.
4. LP1 fully divests by sending `mm_asset = 100001` (their entire balance): `$investor_share = 1`; payouts are `round(1*balance[$asset])` and `round(1*balance[base])`. Due to accumulated rounding from step 3, the amounts computed may leave 1+ unit of dust unaccounted for in one or both balances (e.g., `balance[base] = 1` remains), while `mm_asset_outstanding -= 100001 = 0`.
5. LP2 now deposits `base = 1000000`, `asset = 1000000` matching the dust ratio: `$asset_balance = 1` (non-zero), `$bytes_balance = 1` (non-zero) → "initial deposit" branch is skipped; `$issue_amount = round((1000000/1) * 0) = 0`.
6. LP2 receives `0` `mm_asset` and has no way to redeem their `1000000` deposited units — funds are permanently locked/lost in the AA, matching the report's "victim receives negligible/zero shares while depositing real value" scenario.

### Citations

**File:** test/samples/uniswap_like_market_maker.oscript (L33-41)
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
```

**File:** test/samples/uniswap_like_market_maker.oscript (L42-48)
```text
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
