### Title
Rounding of small `earned_headers_commission_share` percentages to 0 in headers-commission distribution causes silent loss of funds - ([File: headers_commission.js])

### Summary
The RFP `_distribute` bug class (percentage-based amount calculation that can round down to 0 with no zero-amount check) has a direct analog in `ocore`'s headers-commission distribution logic, where a unit author can split their earned headers commission among multiple recipient addresses using an integer percentage `earned_headers_commission_share`, and the resulting per-recipient amount is computed via `Math.round(full_amount * share / 100.0)` without any check that the result is non-zero.

### Finding Description
When headers commissions are calculated for a winning child unit, if the unit specifies `earned_headers_commission_recipients` (multiple authors or a delegated recipient address with a percentage share), the payout to each recipient is computed as: [1](#0-0) 
and, for the SQL-driven path: [2](#0-1) 
The same rounding pattern exists in the MySQL query variant: [3](#0-2) 

`full_amount` (the parent's `headers_commission`) is an integer number of bytes, and `share` is validated as an integer percentage (this codebase enforces shares sum to 100 across recipients, but does not enforce a minimum non-zero resulting byte amount). If `full_amount * share / 100` is less than 0.5, `Math.round` yields `0`, and that recipient's `INSERT INTO headers_commission_contributions` row is written with `amount=0`, or in the JS path an amount of `0` is pushed into `arrValues` — the recipient effectively receives nothing for that unit's headers commission, even though they were nominally entitled to a share of it. There is no check anywhere in this flow (`_distribute`-equivalent) that rejects or corrects a zero-value distribution, unlike the audited RFP finding's recommendation.

This differs from the TPS-fee distribution code (`storage.js` `updateTpsFees`/`getPaidTpsFee`) which uses `Math.floor`/`Math.round` similarly but operates on fee *balances* that accumulate over many units (any rounding dust nets out over time via the running balance mechanism, so it is not a comparable one-shot loss).

### Impact Explanation
For headers-commission splitting, the round-to-zero outcome causes silent underpayment: a legitimate recipient entitled to a small percentage of a small `headers_commission` amount can receive `0` bytes instead of their fractional due, with the remainder implicitly absorbed by rounding rather than explicitly redistributed or flagged. This is a fund-loss condition analogous to the RFP issue, but the magnitude is inherently capped by `headers_commission` size (a small per-unit reward, generally at most a few hundred bytes) and by the percentage granularity (integer 1-100), so the loss per unit is at most a few bytes/dust per affected recipient — this is a genuine but low-magnitude, recurring loss rather than large one-shot fund loss.

### Likelihood Explanation
Reachable by any ordinary unit poster: authors can freely set `earned_headers_commission_recipients` with arbitrary percentage splits (e.g., a recipient with 1% share on a small `headers_commission`) when composing units, so triggering the round-to-zero condition requires no special privilege — just constructing units with small headers_commission values and enough recipients/small shares. This is a normal, permitted unit-authoring pattern, not a rare edge case, so it can recur naturally whenever headers_commission values are small (which is common) and shares are skewed.

### Recommendation
Add validation/handling in the distribution logic (`headers_commission.js`, both the JS in-memory path and the SQL queries) to detect when `Math.round(full_amount * share / 100.0)` (or the SQL `ROUND(...)` equivalent) evaluates to `0` for a valid nonzero `share`, and either: (a) guarantee a minimum of 1 byte to any recipient with `share > 0`, adjusting the largest-share recipient's payout downward to keep the total equal to `full_amount`, or (b) reject/flag such splits at unit-validation time by enforcing a minimum `headers_commission * share / 100 >= 1` where practical.

### Proof of Concept
1. Author composes a unit with `earned_headers_commission_recipients` containing an address with `earned_headers_commission_share = 1` (and other recipients summing shares to 100).
2. That unit's parent `headers_commission` is small (e.g., a few dozen bytes, common for typical parent units).
3. When `calcHeadersCommissions` runs and this unit wins the header-commission race as `child_unit`, `amount = Math.round(full_amount * 1 / 100.0)` evaluates to `0` for `full_amount` below ~50 bytes.
4. `headers_commission_contributions` records `amount=0` for that recipient — see `headers_commission.js` lines 183 and 202 — and the recipient receives no payout despite being a designated commission recipient, with no error or correction anywhere in the flow. [4](#0-3)

### Citations

**File:** headers_commission.js (L50-51)
```javascript
					SELECT punits.unit, earned_headers_commission_recipients.address, \n\
						ROUND(punits.headers_commission*earned_headers_commission_share/100.0) AS hc \n\
```

**File:** headers_commission.js (L180-204)
```javascript
										if (objUnit.assocEarnedHeadersCommissionRecipients) { // multiple authors or recipient is another address
											for (var address in objUnit.assocEarnedHeadersCommissionRecipients) {
												var share = objUnit.assocEarnedHeadersCommissionRecipients[address];
												var amount = Math.round(full_amount * share / 100.0);
												arrValuesRAM.push("('"+payer_unit+"', '"+address+"', "+amount+")");
											};
										} else
											arrValuesRAM.push("('"+payer_unit+"', '"+objUnit.author_addresses[0]+"', "+full_amount+")");
									}
								}
								// sql result
								var arrValues = conf.bFaster ? arrValuesRAM : [];
								if (!conf.bFaster){
									profit_distribution_rows.forEach(function(row){
										var child_unit = row.unit;
										for (var payer_unit in assocWonAmounts[child_unit]){
											var full_amount = assocWonAmounts[child_unit][payer_unit];
											if (!full_amount)
												throw Error("no amount for child unit "+child_unit+", payer unit "+payer_unit);
											// note that we round _before_ summing up header commissions won from several parent units
											var amount = (row.earned_headers_commission_share === 100) 
												? full_amount 
												: Math.round(full_amount * row.earned_headers_commission_share / 100.0);
											// hc outputs will be indexed by mci of _payer_ unit
											arrValues.push("('"+payer_unit+"', '"+row.address+"', "+amount+")");
```
