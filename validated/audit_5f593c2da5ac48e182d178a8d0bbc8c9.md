### Title
Rounding in AA share-minting formula causes permanent user fund loss in the reference market-maker AA - (File: `test/samples/uniswap_like_market_maker.oscript`)

### Summary
The bundled Uniswap-like market-maker AA sample (which is the canonical Obyte reference implementation that real-world AA authors copy when building pooled/LP-token AAs) mints pool-share tokens (`$mm_asset`) using `round()` on a division-based ratio instead of first computing the exact redeemable value and only accepting that amount from the depositor. Exactly like the Aave V3 `supplyTokenTo()` bug, an investor's deposit is taken in full while the number of shares minted is rounded, so the investor can receive strictly less value back than they put in — and this understatement grows with pool size/precision exactly as in the original report.

### Finding Description
In the "invest in MM" case, the AA computes the new investor's share of the pool and mints `$mm_asset` accordingly: [1](#0-0) 

```
$investor_share_of_prev_balance = trigger.output[[asset=base]] / $bytes_balance;
$issue_amount = round($investor_share_of_prev_balance * var['mm_asset_outstanding']);
```
`$issue_amount` is the number of `$mm_asset` shares minted to the investor for the exact `trigger.output[[asset=base]]` (and matching asset amount) they paid in full. Because `round()` performs standard rounding of a division result, `$issue_amount` will frequently be lower than the exact fractional share the deposit is entitled to (any time the true share has a fractional remainder ≥ conceptually below the rounding threshold, or systematically whenever `var['mm_asset_outstanding']` is large relative to `$bytes_balance` and the token unit is coarse). Unlike the AaveV3 fix recommendation — take back only the amount corresponding to the rounded share — this AA takes the investor's entire payment (`trigger.output[[asset=base]]` and `trigger.output[[asset=$asset]]`) unconditionally and mints only the rounded-down share count.

The same pattern repeats on withdrawal:
```
$investor_share = $mm_asset_amount / var['mm_asset_outstanding'];
... amount: "{ round($investor_share * balance[$asset]) }"
... amount: "{ round($investor_share * balance[base]) }"
``` [2](#0-1) 

Every deposit/withdrawal event compounds this rounding effect against the depositor, particularly once the pool has accrued value (fees from the swap cases) so that one pool "byte" is worth more than one deposited byte — the exact "balance/supply ratio is high" condition flagged in the original report. A low-decimal / high-value token pool (or simply a mature pool with many fee-accrued bytes) makes the loss non-negligible per the report's own severity reasoning.

### Impact Explanation
Depositors into an AA built on this reference pattern permanently lose the fractional/rounded-down portion of their deposit's value on every investment, and the same understatement recurs on withdrawal. Because this file is shipped as ocore's canonical AA example for implementing a token pool with shares (analogous to an LP/vault share token), any AA author following it inherits the same fund-loss vulnerability class as the AaveV3 finding: unprivileged trigger senders (investors) lose real value with each interaction, and the effect scales with pool size and precision exactly as described in the source report. This is a Medium severity fund-loss issue consistent with the original finding's downgraded severity.

### Likelihood Explanation
This occurs on every ordinary "invest" and "divest" trigger — no attacker or privileged actor is required, and no malicious counterparty is needed. It happens purely due to normal use of the AA by any unprivileged trigger sender, making the likelihood high for any AA deployed from this template, especially as the pool accumulates trading fees and the `bytes`/`asset` per share ratio drifts away from 1:1.

### Recommendation
Follow the same fix pattern recommended for the AaveV3 report: compute the share count first, then derive the exact `bytes`/`asset` amount that corresponds to that (already-rounded) share count, and only accept/credit that exact amount instead of the full raw trigger output. Concretely:
```
$issue_amount = round($investor_share_of_prev_balance * var['mm_asset_outstanding']);
$exact_bytes_amount = round($issue_amount / var['mm_asset_outstanding'] * $bytes_balance); // amount actually credited
// return the difference (trigger.output[[asset=base]] - $exact_bytes_amount) back to the investor as change
```
Alternatively, use `ceil()` when computing the amount taken from the user (so the AA never under-mints for a fully-paid deposit) and `floor()` when computing amounts paid out to the user on withdrawal, ensuring the AA never rounds in the user's favor at its own expense nor silently keeps excess funds without returning them.

### Proof of Concept
1. Deploy the AA from `test/samples/uniswap_like_market_maker.oscript` and let it operate normally so that `var['mm_asset_outstanding']` becomes large relative to `$bytes_balance` accrued fees (e.g. through repeated `exchange bytes to asset`/`exchange asset to bytes` swap fees increasing pool value without minting new shares).
2. An investor sends `trigger.output[[asset=base]]` and matching `trigger.output[[asset=$asset]]` computed exactly via `$expected_asset_amount = round($current_ratio * trigger.output[[asset=base]]))`.
3. `$issue_amount = round($investor_share_of_prev_balance * var['mm_asset_outstanding'])` rounds down due to integer share-token denomination.
4. The AA mints the investor `$issue_amount` shares but keeps 100% of the investor's deposited bytes/asset — the investor's `$mm_asset` holdings are now worth strictly less than what they deposited, mirroring the exact `_tokenToShares`/`_sharesToToken` mismatch from the referenced AaveV3 report.

### Citations

**File:** test/samples/uniswap_like_market_maker.oscript (L33-65)
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
