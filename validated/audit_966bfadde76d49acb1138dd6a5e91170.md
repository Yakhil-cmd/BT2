Confirmed: `uniswap_like_market_maker.oscript` is the only reachable analog matching the LP-pricing bug class, and it is a documented reference AA design pattern (wiki page 5.4), not core validation logic. It is a legitimate analog since AA templates like this one define exactly the "swap/invest/divest priced from live balance ratios" pattern flagged in the report.

### Title
Uniswap-like Market Maker AA prices swaps and LP-share issuance from instantaneously manipulable `balance[...]` state, mirroring reserve/spot-price manipulation of Uniswap V2/V3 LP valuations - (File: test/samples/uniswap_like_market_maker.oscript)

### Summary
The reference "Uniswap-like market maker" Autonomous Agent (AA) template, documented in the wiki as a canonical AMM design pattern for Obyte AAs, prices both liquidity investment (LP share minting) and token swaps directly from the AA's current on-chain `balance[...]` (the AA's live coin/asset holdings), analogous to Frax's use of Uniswap V2's `getReserves()`/spot ratio and Uniswap V3's assumed-fixed liquidity range for LP token valuation. Because `balance[...]` reflects only the instantaneous state of the AA after the most recent confirmed unit, and because that state can be pushed away from its "fair" value by a preceding swap unit (bought at real but temporary slippage cost, then reversed after extracting value), the same class of value-misrepresentation and unfair-extraction risk described in the Frax report is reproducible here: LP token minting ratios, and swap outputs, are computed from a manipulable spot value rather than a time-weighted or oracle-verified fair value.

### Finding Description
In `test/samples/uniswap_like_market_maker.oscript`, the "invest in MM" case computes the amount of the LP-like `mm_asset` to mint using the *current* balance ratio of the AA: [1](#0-0) 

```
$asset_balance = balance[$asset] - trigger.output[[asset=$asset]];
$bytes_balance = balance[base] - trigger.output[[asset=base]];
...
$current_ratio = $asset_balance / $bytes_balance;
$expected_asset_amount = round($current_ratio * trigger.output[[asset=base]]);
...
$issue_amount = round($investor_share_of_prev_balance * var['mm_asset_outstanding']);
```

This is architecturally identical to Uniswap V2's `getReserves()`-based reserve ratio used to determine deposit ratios and LP share minting, which Trail of Bits flagged (TOB-FRSOL-006/019) as manipulable because the reserves reflect only the instantaneous pool state and can diverge sharply from the token's fair value.

Similarly, the swap logic: [2](#0-1) 

```
$asset_balance = balance[$asset] - trigger.output[[asset=$asset]];
$bytes_balance = balance[base] - trigger.output[[asset=base]];
$p = $asset_balance * $bytes_balance;
$new_asset_balance = round($p / balance[base]);
$amount = $asset_balance - $new_asset_balance;
```
uses `balance[base]` and `balance[$asset]` — the AA's live, single-point-in-time state — as the sole price signal, with no time-weighted average or external oracle cross-check, exactly the pattern the report criticizes for Uniswap V2 LPs.

Because divest (share redemption) also pays out `round($investor_share * balance[$asset])` and `round($investor_share * balance[base])` directly from current balances: [3](#0-2) 

an attacker who moves the pool's balance ratio away from fair value in an earlier unit (a large but real swap, not a costless flash loan since Obyte units are not intra-block atomic in the EVM sense, but which is confirmed and stable before the follow-up unit is processed) can invest or divest at a distorted `current_ratio`, extracting value from other liquidity providers or minting more `mm_asset` than the fair share of contributed capital warrants — the same "recollateralization is not correctly reflected while true collateral falls" dynamic described in the report, translated to LP share fairness within a single AA-defined asset system.

### Impact Explanation
If this template (or any AA copying its pattern, since it is published as the canonical reference AMM design in the project's own documentation) is deployed with real value, an attacker can:
- Distort the `$current_ratio` via a preceding real swap, then invest liquidity at the distorted ratio to receive a disproportionate `mm_asset` share of the pool, diluting/robbing honest liquidity providers on the following divest.
- Or, distort balances before divesting to redeem more of one asset (e.g., `base`) than their fair pro-rata share, at the expense of remaining LPs.

This is a Medium/High-severity fund-loss/dilution vector for any deployed AA using this pricing model, since value is transferred away from honest counterparties based on a manipulable spot ratio rather than a fair/time-weighted value, matching the "incorrect valuation causes recollateralization/fairness failure" impact class from the source report.

### Likelihood Explanation
Likelihood is Medium: exploitation requires the attacker to commit real capital to move the balance ratio (there is no free/atomic flash-loan primitive across separate DAG units the way there is within a single EVM transaction), and bounce fees plus round-trip trading cost act as some friction. However, because units settle deterministically in DAG order and this AMM design has no TWAP, oracle check, or minimum-liquidity/slippage protection on invest/divest, a well-capitalized attacker (or one colluding with witnesses/ordering) can still profitably distort the ratio across a short sequence of confirmed units, particularly in low-liquidity pools, which is the same low-liquidity assumption the original Frax report relies upon for LP mispricing.

### Recommendation
- Do not use the instantaneous `balance[...]` ratio as the sole basis for LP share issuance or redemption pricing; require a minimum output/expected-ratio bound supplied by the user with strict rejection on divergence (already partially present via `bounce('wrong ratio of amounts...')` but only checked against the same manipulable value, not an independent reference).
- Introduce a time-weighted internal price accumulator (state var updated across units, weighted by time-in-state) analogous to Uniswap V2's TWAP oracle, and use it (or an external `data_feed` oracle) to sanity-check invest/divest/swap amounts against sudden single-unit deviations.
- Document explicitly in the sample/reference AA (since it is treated as the project's canonical AMM template) that production deployments must add TWAP/oracle-based fair-value protections, mirroring the long-term recommendation in the source report to use oracle-derived fair value rather than raw spot reserves for LP pricing.

### Proof of Concept
1. Deploy `uniswap_like_market_maker.oscript` as an AA with initial liquidity (e.g., 1,000,000 bytes and 1,000,000 units of `$asset`), setting `1:1` ratio and `mm_asset_outstanding = 1,000,000`.
2. Attacker submits a large swap of `$asset` into the AA ("exchange asset to bytes" case), pushing `balance[base]` down and `balance[$asset]` up, shifting `current_ratio` away from the pre-trade fair value.
3. In a subsequent unit (once the swap unit is stable), attacker submits an "invest in MM" trigger with a carefully chosen `trigger.output[[asset=base]]` and matching `trigger.output[[asset=$asset]]` computed from the now-skewed `$current_ratio`, receiving `$issue_amount` of `mm_asset` computed via `$investor_share_of_prev_balance = trigger.output[[asset=base]] / $bytes_balance` against the skewed `$bytes_balance`.
4. Attacker then submits a "divest MM shares" trigger, redeeming `mm_asset` for `round($investor_share * balance[$asset])` and `round($investor_share * balance[base])` after the pool ratio reverts toward fair value from subsequent market activity (or the attacker's own reverse trade), realizing a profit at the expense of pre-existing liquidity providers whose share of the pool was diluted at the distorted ratio in step 3.
5. Net effect: the attacker extracts value that should have accrued proportionally to all LPs, purely because the AA's `mm_asset` issuance formula trusted the manipulable instantaneous `balance[...]` ratio as if it were the pool's fair value — the same failure mode the source report identifies in Frax's LP-token valuation via `getReserves()` and Uniswap V3 NFT range assumptions.

### Citations

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

**File:** test/samples/uniswap_like_market_maker.oscript (L102-122)
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
```
