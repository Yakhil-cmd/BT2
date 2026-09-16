### Title
Rounding-to-zero in headers-commission profit sharing lets a low `earned_headers_commission_share` recipient receive 0 while total commission is under-distributed - (File: `headers_commission.js`)

### Summary
`calcHeadersCommissions()` distributes a unit author's `headers_commission` among multiple `earned_headers_commission_recipients` by multiplying the full commission amount by each recipient's percentage share and rounding, exactly the same "amount × percentage / 100" pattern flagged in the external RFP-simple report. When a recipient's share (or the payer's `headers_commission`) is small, `Math.round(full_amount * share / 100.0)` truncates to 0, so that recipient is silently paid nothing.

### Finding Description
In `headers_commission.js`, once winning child units for headers commission are determined, the commission owed by the payer unit (`headers_commission`) is split across `earned_headers_commission_recipients` addresses according to each address's `earned_headers_commission_share`: [1](#0-0) 

```js
for (var child_unit in assocWonAmounts){
    var objUnit = storage.assocStableUnits[child_unit];
    for (var payer_unit in assocWonAmounts[child_unit]){
        var full_amount = assocWonAmounts[child_unit][payer_unit];
        if (objUnit.assocEarnedHeadersCommissionRecipients) {
            for (var address in objUnit.assocEarnedHeadersCommissionRecipients) {
                var share = objUnit.assocEarnedHeadersCommissionRecipients[address];
                var amount = Math.round(full_amount * share / 100.0);
                arrValuesRAM.push(...);
            };
        } else
            arrValuesRAM.push(...full_amount...);
    }
}
``` [2](#0-1) 

The equivalent SQL/DB path performs the same computation: `ROUND(full_amount * earned_headers_commission_share / 100.0)`. [3](#0-2) 

`earned_headers_commission_recipients` and the per-address `earned_headers_commission_share` are set by the unit's author (an unprivileged unit poster defining who shares in headers commission earned by their units), validated in `validation.js`, and consumed identically when writing units in `writer.js`. If an author configures many recipients with small shares (analogous to the reported milestone-percentage split summing to 1e18 but with tiny numerator), or if the `headers_commission` itself is a small integer (a few satoshis, which is common because headers commission per unit is typically only a handful of bytes), `Math.round(full_amount * share / 100.0)` rounds down to 0 for low-share recipients. Because rounding is applied independently per recipient rather than distributing a remainder, the sum of all recipients' rounded amounts can be strictly less than `full_amount`, meaning part of the commission that was already deducted from the payer's declared fee is never credited to any address.

### Impact Explanation
Byte value is lost: the commission amount is committed/reserved as part of the payer unit's `headers_commission` (already accounted for in fee accounting and unit validity), but the rounded-down share is never inserted into `headers_commission_contributions`, so it is never paid to any output/balance. This is a systemic value-loss bug reachable by any unit author who defines `earned_headers_commission_recipients` with a low-share address (or by the natural case of many small-value units earning tiny headers commissions split among several recipients), causing a small amount of funds to be permanently unaccounted for/frozen rather than delivered to the intended recipient — directly analogous to the reported "0 amount distributed when proposalBid is very low" issue.

### Likelihood Explanation
Headers commission per unit is very small (a handful of bytes based on unit size), and any author can freely set `earned_headers_commission_recipients` with arbitrary percentage shares (as long as they sum to 100). Because commission values are frequently tiny while multiple recipients are common, share fractions that round to 0 are easily reachable in normal operation, not just adversarial edge cases, making this readily triggerable by an ordinary unit author.

### Recommendation
Distribute headers commission using integer division with an explicit remainder allocation (e.g., sort recipients deterministically, give the largest share the leftover remainder) instead of independently rounding each recipient's share, ensuring the sum of distributed amounts always equals `full_amount`. Alternatively, accumulate fractional remainders across contributions before flooring so no commission is lost, and reuse the same fix for the analogous `updateTpsFees` share distribution in `storage.js`, which uses `Math.floor(total_tps_fees_delta * share / 100)` per recipient with the same non-remainder-preserving pattern. [4](#0-3) 

### Proof of Concept
1. Author A creates a unit whose `headers_commission` (per DAG rules) is computed as, e.g., 3 bytes.
2. Author A defines `earned_headers_commission_recipients` for the paying unit with two addresses: Address X with `earned_headers_commission_share = 90`, Address Y with `earned_headers_commission_share = 10`.
3. When `calcHeadersCommissions()` runs after the unit stabilizes:
   - Address X: `Math.round(3 * 90 / 100.0) = Math.round(2.7) = 3`
   - Address Y: `Math.round(3 * 10 / 100.0) = Math.round(0.3) = 0`
4. Address Y receives 0 even though they are entitled to a share of the fee, and the total distributed (3) may not correctly reflect intended proportional splitting for small `full_amount`s — in general cases with more recipients and lower per-recipient shares, more of the commission is lost entirely (sum of rounded shares < `full_amount`).

### Citations

**File:** headers_commission.js (L176-188)
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
									}
```

**File:** headers_commission.js (L192-209)
```javascript
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
										}
									});
									if (!_.isEqual(arrValuesRAM.sort(), arrValues.sort())) {
										throwError("different arrValues, db: "+JSON.stringify(arrValues)+", ram: "+JSON.stringify(arrValuesRAM));
									}
```

**File:** storage.js (L1265-1271)
```javascript
			const recipients = getTpsFeeRecipients(objUnitProps.assocEarnedHeadersCommissionRecipients, objUnitProps.author_addresses);
			for (let address in recipients) {
				const share = recipients[address];
				const tps_fees_delta = Math.floor(total_tps_fees_delta * share / 100);
				const [row] = await conn.query("SELECT tps_fees_balance FROM tps_fees_balances WHERE address=? AND mci<=? ORDER BY mci DESC LIMIT 1", [address, mci]);
				const tps_fees_balance = row ? row.tps_fees_balance : 0;
				await conn.query("REPLACE INTO tps_fees_balances (address, mci, tps_fees_balance) VALUES(?,?,?)", [address, mci, tps_fees_balance + tps_fees_delta]);
```
