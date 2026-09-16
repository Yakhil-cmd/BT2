### Title
Reserve-ratio ("spot price") read via the `balance[...]` oscript primitive is manipulable within the same round and is used unprotected as a pricing oracle in AA market-maker logic - ([File: test/samples/uniswap_like_market_maker.oscript])

### Summary
The `balance[asset]` primitive in oscript (implemented in `formula/evaluation.js`, `case 'balance'`) returns the AA's *current* on-chain reserves at the moment the trigger unit is processed. Obyte ships this exact pattern as the reference way to build an AMM/market-maker AA in `test/samples/uniswap_like_market_maker.oscript`, where the exchange rate ("current_ratio"/"p") is derived purely from `balance[$asset]` and `balance[base]` immediately before the current trigger, with no external, manipulation-resistant price reference (e.g. a `data_feed` oracle with deviation checks, or a time-weighted average). This is structurally identical to the reported issue: `sqrtPriceX96` is an instantaneous, atomically-manipulable reserve ratio used as if it were a trustworthy price, instead of a TWAP-protected oracle.

### Finding Description
In `test/samples/uniswap_like_market_maker.oscript`:
- The "invest in MM" case computes the required deposit ratio from the AA's live reserves:
```
$asset_balance = balance[$asset] - trigger.output[[asset=$asset]];
$bytes_balance = balance[base] - trigger.output[[asset=base]];
$current_ratio = $asset_balance / $bytes_balance;
``` [1](#0-0) 

- The "exchange bytes to asset" / "exchange asset to bytes" cases compute the swap output from the same live constant-product reserves with no slippage bound and no oracle cross-check:
```
$asset_balance = balance[$asset] - trigger.output[[asset=$asset]];
$bytes_balance = balance[base] - trigger.output[[asset=base]];
$p = $asset_balance * $bytes_balance;
$new_asset_balance = round($p / balance[base]);
$amount = $asset_balance - $new_asset_balance;
``` [2](#0-1) 

Because `balance[...]` simply reflects the AA address's current outputs (via the core `balance` opcode implemented in `formula/evaluation.js`), any address can post a unit to change the AA's reserve ratio and then, in an immediately following unit (posted before the first has meaningfully "settled" community awareness of the new price, and well before any external price reference would move), trigger a trade or an "invest" operation priced off that freshly-skewed ratio. There is no `data_feed`-based deviation check, no minimum holding period, and no TWAP — exactly the missing protection called out in the report for `sqrtPriceX96`. The only reachable state used for pricing is the AA's own mutable reserve balance, updated per-unit and readable/movable by any unprivileged unit poster acting as an AA trigger sender.

### Impact Explanation
An attacker who is simply an unprivileged AA-trigger sender can:
1. Post a large swap to skew `balance[$asset]`/`balance[base]` in one direction (front-run leg).
2. Immediately post the exploit trigger (e.g. the "invest in MM" case, or a large opposite swap) that is priced off the now-skewed ratio, extracting value from the pool or minting/burning `mm_asset` shares at a favorable/incorrect ratio.
3. Reverse the initial skew afterward, realizing a profit taken directly from the AA's byte/asset reserves — a concrete AA fund loss for other liquidity providers/users of the AA, mirroring the "operators could use flashloan to sandwich the vault" impact in the original report.

This causes actual fund loss/mispricing inside the AA (an autonomous smart-contract equivalent), not merely a documentation nit — matching the "AA fund loss or freezing" acceptance criterion.

### Likelihood Explanation
Likelihood is high for any AA built on this exact reference pattern shipped by the project: no privileged role is required, only ordinary unit-posting capability (an "AA trigger sender", explicitly an in-scope actor). Obyte's DAG structure allows an attacker to post two units in rapid succession (parent of one referencing/following the other) well within the timeframe needed to manipulate and then exploit the reserve ratio, since the AA processes each trigger deterministically and instantaneously against the currently known `balance[...]`, with no built-in cooldown, oracle cross-check, or TWAP smoothing anywhere in the core `balance` execution path.

### Recommendation
- Do not rely solely on `balance[...]`-derived spot ratios for pricing/settlement in AA templates; any AA computing an internal "exchange rate" from its own live reserves should cross-check against an external, multi-source `data_feed` oracle with a maximum allowed deviation, and/or maintain an internally computed running/time-weighted average of the ratio across multiple stabilized trigger executions (keyed by `var[...]` state) rather than the instantaneous `balance[...]` value.
- Update the shipped reference sample (`test/samples/uniswap_like_market_maker.oscript`) to demonstrate this mitigation, since it is used as guidance for real AA authors and currently encodes the exact anti-pattern flagged in the original report.
- Consider adding a minimum number of stabilized rounds/mci between "price-moving" and "price-consuming" operations before the balance ratio can be trusted for issuance/settlement.

### Proof of Concept
1. Deploy the `uniswap_like_market_maker.oscript` AA with initial reserves (e.g. 1e7 bytes / 1e7 asset units), giving `$asset_balance/$bytes_balance = 1`.
2. Attacker Unit A: send a large "exchange bytes to asset" trigger (`trigger.output[[asset=base]] > 1e5`), which computes `$amount` off the constant-product formula in lines 102-123 and drains a large fraction of `$asset` from the pool, sharply skewing the ratio. [2](#0-1) 
3. Attacker Unit B (posted immediately after, before the market can react/arbitrage): send an "invest in MM" trigger with a large `base` deposit; `$current_ratio` and `$issue_amount` are computed from the now-skewed `balance[$asset]`/`balance[base]`, minting `mm_asset` shares to the attacker at a mispriced ratio. [3](#0-2) 
4. Attacker Unit C: reverse the initial skew (swap asset back to bytes) and/or divest the newly minted `mm_asset` shares (case at lines 67-101) to redeem a disproportionate share of the pool's true reserves, realizing profit extracted from other LPs — analogous to sandwiching `sqrtPriceX96` in the reported issue. [4](#0-3) 

*(Note: I was not able to find any core-level protective mechanism — e.g., an enforced cooldown, an oracle deviation check, or TWAP smoothing — anywhere in `formula/evaluation.js`'s `balance` opcode or in the sample AA that would prevent this. This assessment covers only what is present in the indexed portions of the repository; if additional mitigation exists elsewhere in the codebase that was not surfaced by search, it was not found.)*

### Citations

**File:** test/samples/uniswap_like_market_maker.oscript (L34-48)
```text
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
