### Title
`otherwise` operator treats a genuine oracle/data-feed value of `0` as "no value", causing fallback to a stale alternative price - (File: `formula/evaluation.js`)

### Summary
The oscript `otherwise` operator, used in AA formulas to fall back to an alternative expression when the left-hand side has "no value," treats a numeric `0` result exactly the same as `false` or `''` (empty). This means that if an AA's oscript formula reads a legitimate price/rate via `data_feed[[...]]` and that value happens to be exactly `0` (e.g., an asset genuinely trading at zero, a depegged price, or an oracle explicitly reporting `0`), the `otherwise` operator will discard that current value and fall through to whatever stale/alternative price expression the author supplied — mirroring the GMX bug where a legitimate zero secondary price was treated as "empty" and the stale primary price was used instead.

### Finding Description
In `formula/evaluation.js`, the `otherwise` case explicitly normalizes any zero-valued `Decimal` to the plain JS number `0`, then uses a JS truthiness check (`if (param1)`) to decide whether to keep the evaluated left-hand-side or evaluate the fallback branch: [1](#0-0) 

Because `0` is falsy in JavaScript, there is no way to distinguish "the left side legitimately evaluated to zero" from "the left side had no value" (e.g., an undefined trigger field or a missing data feed handled elsewhere via `ifnone`). This is architecturally identical to the GMX `Price.isEmpty()` sentinel bug: a real, freshly-posted value of zero is silently discarded in favor of an older/alternative value supplied on the right-hand side of `otherwise`.

A typical AA pattern for reading a data feed with fallback is:
```
$price = data_feed[[oracles='ORACLE', feed_name='PRICE']] otherwise $stale_price;
```
If the oracle legitimately posts `PRICE = 0` in the newest data feed record (e.g., the asset has crashed to zero, or is intentionally used as a zero/reset signal), the AA will use `$stale_price` instead of `0`, exactly as in the GMX finding where the more recent (correct) price of zero was ignored in favor of an older price.

### Impact Explanation
An AA that uses `otherwise` (or any construct relying on falsy semantics) to combine a freshly-read oracle/data-feed value with a fallback/previous value will price trades, collateral, or payouts using a stale, incorrect value whenever the true current value is `0`. A counterparty who is aware of this (e.g., a trader interacting with an AA-based synthetic asset, prediction market, or exchange-rate contract) can exploit the block/trigger where the real price touches `0` to extract funds from the AA's reserve or from the other side of the trade at the stale, non-zero valuation — a direct fund-loss/mispricing impact for the AA and its counterparties, analogous to the GMX pool loss described in the report.

### Likelihood Explanation
This requires an AA author to combine `data_feed`/trigger-derived numeric values with `otherwise` (a documented, commonly used oscript idiom for supplying defaults), and for the oracle/data feed to legitimately report exactly `0` at some point (a plausible real-world event for prices, rates, or counters, not a fabricated edge case). Any AA whose formulas rely on `otherwise` to provide a fallback price is affected without any special privilege by the caller — merely triggering the AA in the block where the real value is `0` suffices.

### Recommendation
The `otherwise` operator should not conflate an evaluated-but-legitimately-zero decimal with "no value." Only genuinely missing/undefined evaluations (e.g., `null` returned by `data_feed` when nothing is found, or unresolved trigger/state fields) should trigger the fallback branch of `otherwise`; a successfully evaluated numeric `0` should be returned as-is. This requires distinguishing "expression evaluated to `null`/failure" from "expression evaluated to `0`" at the `evaluate()` call site instead of relying on JS truthiness.

### Proof of Concept
1. Deploy an AA whose price-reading formula is `$price = data_feed[[oracles='X', feed_name='RATE']] otherwise $var['last_price'];` and which uses `$price` to compute payout/exchange amounts.
2. Oracle `X` posts a new, legitimate data feed value `RATE = 0` in unit `U` (mci `M`), superseding a previous non-zero value.
3. Once unit `U` is stable (or in the unstable/AA data-feed lookup window), any trigger causing the AA to evaluate the formula in the block associated with mci `M` will see `data_feed[[...]] == 0`, which the `otherwise` operator treats as "no value," causing `$price` to be set to the old `$var['last_price']` instead of `0`.
4. A user submits a trigger to exchange/withdraw against the AA in that same window, receiving output computed at the stale non-zero price rather than the correct `0` rate, extracting value from the AA's reserve.

### Citations

**File:** formula/evaluation.js (L578-589)
```javascript
			case 'otherwise':
				evaluate(arr[1], function (param1) {
					if (fatal_error)
						return cb(false);
					// wrappedObject stays intact
					if (Decimal.isDecimal(param1) && param1.toNumber() === 0)
						param1 = 0;
					if (param1)
						return cb(param1);
					// else: false, '', or 0
					evaluate(arr[2], cb);
				});
```
