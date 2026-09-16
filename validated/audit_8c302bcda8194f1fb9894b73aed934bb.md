### Title
Rounding of `earned_headers_commission_share` percentages can inflate total headers-commission payouts beyond the fee actually collected - (File: `headers_commission.js`)

### Summary
`calcHeadersCommissions` distributes a fixed headers-commission fee (`punits.headers_commission`) among the addresses named in a unit's author-controlled `earned_headers_commission_recipients` list by computing each recipient's share with `Math.round(full_amount * share / 100.0)`. Because `Math.round` is applied independently per recipient rather than tracking a running remainder, the sum of the rounded amounts can exceed (or fall short of) the original `full_amount`, mirroring the `rewardRate` rounding-loss pattern from the external report but here on the "mint" side — creating spendable `headers_commission_outputs` value that was never actually deducted from `punits.headers_commission`.

### Finding Description
In `headers_commission.js`, when a child unit wins the headers commission of a parent unit, the payout is split per-recipient: [1](#0-0) 

and again when aggregating from SQL: [2](#0-1) 

`share` values come from the `earned_headers_commission_recipients` field that a unit's authors are free to set when composing a multi-authored unit: [3](#0-2) 

The rounding is done independently for each `(address, share)` pair with no compensating remainder distributed to a "last" recipient and no post-hoc check that `SUM(amount) == full_amount`. `Math.round` rounds `.5` up, so with many recipients whose shares each round a fractional unit up (e.g., a set of small shares that each map to `x.5` before rounding), the total paid out via `headers_commission_contributions`/`headers_commission_outputs` can exceed `full_amount`, effectively creating bytes that were never backed by an actual fee. The consistency check the code performs (`throwError("different arrValues...")`, `headers_commission.js:207-209`) only compares the SQL-computed distribution against the RAM-computed distribution for equality — it does not verify either computation against the true `full_amount`, so a rounding-driven surplus (or deficit) passes silently.

### Impact Explanation
Headers-commission outputs are ordinary spendable UTXOs of the base asset. If the rounded sum of `earned_headers_commission_recipients` shares systematically exceeds `full_amount`, an attacker who controls the recipient list of a multi-authored unit could mint small amounts of extra bytes with every winning unit, which is a supply-inflation bug at the protocol accounting layer, analogous to how the referenced report's rounding produced under- or over-distribution relative to the intended total. Conversely, systematic under-rounding causes commission to be permanently lost (unspendable), matching the "locked funds" flavor of the original report.

### Likelihood Explanation
Reachable by any ordinary multi-authored-unit poster (no special privilege required) who can choose the `earned_headers_commission_recipients` list and shares for their own units and wait for one of their units to win a parent's headers commission — a routine, permissionless DAG-posting operation. The magnitude per event is small (bounded by rounding to the nearest integer per recipient), so repeated/automated exploitation over many units would be required to accumulate a material amount; I was not able to fully confirm within the available index whether `validation.js` enforces that the shares in `earned_headers_commission_recipients` must sum to exactly 100 or caps the number of recipients, which materially affects how large the aggregate rounding drift can be made per unit. This should be verified directly in `validation.js` before treating exploitability as fully proven.

### Recommendation
Distribute `full_amount` deterministically without a rounding-induced surplus/deficit: iterate recipients, allocate `Math.floor(full_amount * share / 100)` to all but the last recipient, and assign the last recipient the true remainder (`full_amount - sum_of_previous_allocations`). Additionally, assert (and treat as a validation/consensus error rather than silently proceeding) that the sum of all `earned_headers_commission_recipients` shares in a unit equals exactly 100, and that the sum of computed `amount`s for a given `full_amount` equals `full_amount` exactly, both in the RAM path and the SQL path of `calcHeadersCommissions`.

### Proof of Concept
1. An author composes a multi-authored unit and sets `earned_headers_commission_recipients` to, e.g., 100 recipients each with `earned_headers_commission_share = 1` (summing to 100%, satisfying any "shares sum to 100" check if present).
2. That unit becomes the "winner" child unit for a parent whose `headers_commission` (`full_amount`) is set such that `full_amount * 1/100` lands near `x.5` for each recipient (e.g., `full_amount = 150` → each share computes to `1.5`).
3. In `headers_commission.js:183`/`202`, `Math.round(150 * 1 / 100)` = `Math.round(1.5)` = `2` for every one of the 100 recipients, yielding a total of `200` inserted into `headers_commission_contributions` for a `full_amount` of only `150` — a 33% inflation of the payout, with no consistency check against `full_amount` to catch it.
4. These inflated `headers_commission_contributions` are summed into `headers_commission_outputs` (`headers_commission.js:222-227`) and become spendable, permanently adding bytes to the effective circulating amount beyond what any input actually paid.

### Citations

**File:** headers_commission.js (L176-187)
```javascript
								for (var child_unit in assocWonAmounts){
									var objUnit = storage.assocStableUnits[child_unit];
									for (var payer_unit in assocWonAmounts[child_unit]){
										var full_amount = assocWonAmounts[child_unit][payer_unit];
										if (objUnit.assocEarnedHeadersCommissionRecipients) { // multiple authors or recipient is another address
											for (var address in objUnit.assocEarnedHeadersCommissionRecipients) {
												var share = objUnit.assocEarnedHeadersCommissionRecipients[address];
												var amount = Math.round(full_amount * share / 100.0);
												arrValuesRAM.push("('"+payer_unit+"', '"+address+"', "+amount+")");
											};
										} else
											arrValuesRAM.push("('"+payer_unit+"', '"+objUnit.author_addresses[0]+"', "+full_amount+")");
```

**File:** headers_commission.js (L199-205)
```javascript
											// note that we round _before_ summing up header commissions won from several parent units
											var amount = (row.earned_headers_commission_share === 100) 
												? full_amount 
												: Math.round(full_amount * row.earned_headers_commission_share / 100.0);
											// hc outputs will be indexed by mci of _payer_ unit
											arrValues.push("('"+payer_unit+"', '"+row.address+"', "+amount+")");
										}
```

**File:** composer.js (L248-253)
```javascript
	if (params.earned_headers_commission_recipients) // it needn't be already sorted by address, we'll sort it now
		objUnit.earned_headers_commission_recipients = params.earned_headers_commission_recipients.concat().sort(function(a,b){
			return ((a.address < b.address) ? -1 : 1);
		});
	else if (bMultiAuthored) // by default, the entire earned hc goes to the change address
		objUnit.earned_headers_commission_recipients = [{address: arrChangeOutputs[0].address, earned_headers_commission_share: 100}];
```
