### Title
Headers-commission distribution rounds individual recipient shares up, allowing byte-supply inflation when a unit defines multiple `earned_headers_commission_recipients` - ([File: headers_commission.js])

### Summary
When a stable unit wins a header commission (`headers_commission`), the payout to `earned_headers_commission_recipients` is computed by rounding *each* recipient's share independently with `Math.round()`, instead of first summing the fractional shares and rounding the aggregate (or rounding down and distributing the remainder). This is the same rounding-direction defect class as the MetaMorpho `_supplyMorpho` bug: a value that must stay bounded by a fixed total (`full_amount`/`supplyCap`) is derived from a per-item computation that rounds toward the recipient's benefit instead of toward the payer's (protocol's) benefit, so the sum of the parts can exceed the whole.

### Finding Description
`earned_headers_commission_recipients` is a unit-level field that **any unit author controls** — a multi-authored unit (or any unit with a defined shared address) can list several recipients with `earned_headers_commission_share` values that must sum to 100.

When headers commissions are distributed in `calcHeadersCommissions()`, for every payer/child unit pair the code computes, per recipient: [1](#0-0) 

and, in the SQL-backed path: [2](#0-1) 

Each recipient's payout is `Math.round(full_amount * share / 100.0)`, applied **independently per recipient**. Because rounding is applied to each fractional share separately rather than to the aggregate, it is straightforward to choose a set of shares (summing exactly to 100) such that the fractional remainders of `full_amount * share/100.0` for every recipient are ≥ 0.5, causing every individual term to round **up**. The sum of the rounded amounts credited across all recipients can then exceed `full_amount`, the actual commission amount collected from the payer unit.

This mirrors exactly the MetaMorpho defect: `supplyCap.zeroFloorSub(supplyAssets)` needed `supplyAssets` to round up so the difference under-estimates headroom; here, each recipient's `amount` needs to round **down** (with only the *last* recipient absorbing the remainder, or the whole sum rounded once) so the total payout never exceeds `full_amount`. Instead the code rounds every fractional share independently, which structurally biases the sum upward.

### Impact Explanation
Header commissions are inserted directly into `headers_commission_contributions`, which back real, spendable byte balances for the credited addresses. If the sum of independently-rounded shares exceeds `full_amount`, the network credits more bytes to recipients than were actually paid by the payer unit for that header commission. Because this computation runs on every stable MC index for every unit that wins a header commission, an attacker who consistently sets `earned_headers_commission_recipients` with shares engineered to round up (e.g., splitting across several addresses they control) can systematically mint small amounts of extra bytes on every commission cycle — an incremental, repeatable base-asset supply inflation bug, analogous to `supplyCap` being exceeded in the reported MetaMorpho issue.

### Likelihood Explanation
Reachable by any unprivileged unit poster: `earned_headers_commission_recipients` is set directly in a unit's header by its author(s) (multi-authored units, or explicitly via `params.earned_headers_commission_recipients` in `composer.js`), and is only constrained by the requirement that shares sum to 100 and count/size limits enforced in `validation.js`. No special privilege, hub cooperation, or malicious peer/node behavior is required — a single author crafts shares to trigger the rounding bias and simply waits for the unit to win a header commission at MC stabilization, which happens routinely as part of normal consensus. The per-event gain is small, but the exploit is deterministic and repeatable at essentially every stabilized MCI where the attacker's units win, so it accumulates over time.

### Recommendation
Do not round each recipient's share independently. Instead:
1. Round down (`Math.floor`) every recipient's amount except possibly the last, guaranteeing `sum(recipient_amounts) <= full_amount`.
2. Assign the leftover remainder (`full_amount - sum(floored_amounts)`) to a single designated recipient (e.g., the first author or the one with the largest share) so the total distributed equals exactly `full_amount`, never more.
3. Apply the same fix symmetrically in both the SQL-comparison ("RAM") path and the SQL query result path in `calcHeadersCommissions()` so the two computations continue to match under the `_.isEqual` consistency check.

### Proof of Concept
1. Author a unit (single- or multi-authored) that defines `earned_headers_commission_recipients` with, e.g., 3 addresses controlled by the attacker with shares `[34, 33, 33]`.
2. Ensure the unit becomes the "winning child" for a header commission of an amount `full_amount` chosen (or naturally occurring) such that `full_amount * 34/100`, `full_amount * 33/100`, `full_amount * 33/100` each have fractional parts ≥ 0.5 (attacker can pick/await a `full_amount` value satisfying this, since header commissions vary per unit and MC index and recipients can be redefined per unit).
3. When `calcHeadersCommissions()` runs at MC stabilization, each of the three `Math.round()` calls rounds up, so `sum(amounts) > full_amount`.
4. The extra bytes are inserted into `headers_commission_contributions` for the attacker-controlled addresses via: [3](#0-2) 
credited to real spendable balances that exceed what the network actually collected — repeatable on every winning unit, yielding cumulative byte-supply inflation.

### Citations

**File:** headers_commission.js (L180-188)
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
```

**File:** headers_commission.js (L199-204)
```javascript
											// note that we round _before_ summing up header commissions won from several parent units
											var amount = (row.earned_headers_commission_share === 100) 
												? full_amount 
												: Math.round(full_amount * row.earned_headers_commission_share / 100.0);
											// hc outputs will be indexed by mci of _payer_ unit
											arrValues.push("('"+payer_unit+"', '"+row.address+"', "+amount+")");
```

**File:** headers_commission.js (L212-214)
```javascript
								conn.query("INSERT INTO headers_commission_contributions (unit, address, amount) VALUES "+arrValues.join(", "), function(){
									cb();
								});
```
