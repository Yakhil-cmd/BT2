## Title
Rounding in multi-recipient headers-commission (and TPS-fee) distribution can mint extra spendable bytes, inflating total base-currency supply - (File: headers_commission.js)

### Summary
`calcHeadersCommissions()` splits a winning header's commission (`full_amount`) among multiple `earned_headers_commission_recipients` by independently rounding each recipient's share with `Math.round(full_amount * share / 100.0)`. The protocol only guarantees that the declared `earned_headers_commission_share` values sum to 100 [1](#0-0) , but it never re-normalizes or caps the sum of the *rounded* per-recipient amounts against `full_amount`. Because `Math.round` can round several fractional shares up at once, the sum of paid-out amounts can exceed `full_amount`, creating spendable `headers_commission_outputs` value that was never actually collected as commission — i.e., new bytes minted out of thin air.

### Finding Description
The relevant logic:
- SQL (MySQL) path computes per-recipient commission with `ROUND(punits.headers_commission*earned_headers_commission_share/100.0)` independently for each row [2](#0-1) .
- The JS/SQLite path does the same thing per recipient with `Math.round(full_amount * share / 100.0)` [3](#0-2) , and the "authoritative" DB-driven path repeats the identical unguarded rounding [4](#0-3) .

The only invariant enforced anywhere is on the *declared* shares, requiring they sum to exactly 100 at validation time [5](#0-4) . Nothing constrains the sum of the *rounded* per-recipient payouts to equal `full_amount`.

Standard `Math.round()` rounds `.5` away from zero (up for positive numbers), so multiple recipients can each round up simultaneously. For example, with `full_amount = 5` and two recipients each with `earned_headers_commission_share = 50`:
```
Math.round(5 * 50/100) = Math.round(2.5) = 3
Math.round(5 * 50/100) = Math.round(2.5) = 3
```
Total paid = 6, but only 5 units of commission were actually collected from the payer unit. The resulting rows are inserted directly into `headers_commission_contributions` and subsequently aggregated into `headers_commission_outputs` without any check against the original `headers_commission` amount [6](#0-5) [7](#0-6) . These outputs are treated as ordinary spendable UTXOs by wallets and the input-selection code, so the extra unit becomes real, spendable base currency.

An attacker (any multi-authored unit's author, since `earned_headers_commission_recipients` is only required/allowed when a unit has more than one author) can freely choose the share percentages to maximize the rounding-up effect across many recipients (e.g., splitting into many recipients each just above a `.5` rounding boundary), repeatedly winning headers commissions to accumulate inflated bytes over time.

### Impact Explanation
This is a genuine (though small-magnitude per event) supply-inflation bug: units of base currency (bytes) are created that were never paid in by anyone, and they are fully spendable once matured to `headers_commission_outputs`. Because headers commissions are won extremely frequently (every stable unit potentially wins commission from its parents), an attacker fully controlling the recipient share list of their own multi-author units can repeat this pattern at will to accumulate inflated funds over time, which is a protocol-level integrity violation, not merely a UX inconvenience. This matches the "supply inflation" impact category.

### Likelihood Explanation
Likelihood is at least medium: producing a unit with multiple authors and a crafted `earned_headers_commission_recipients` list is trivial and fully within an ordinary user's control (validated fields only require positive integer shares summing to 100, sorted by address) [8](#0-7) . The attacker does not need any privileged role — any unit poster who authors a multi-authored unit and later wins headers commission from a parent can exploit the rounding by choosing shares such as 50/50, 16.67/16.67/16.67x3+... etc. that maximize aggregate rounding-up.

### Recommendation
Do not round each recipient independently. Instead, compute all rounded shares but track the running total, and allocate any remainder/deficit to a single designated recipient (e.g., largest share or last recipient in sorted order) so that the sum of paid-out amounts always equals exactly `full_amount`. Apply the same fix to the equivalent SQL implementation for MySQL, and audit other proportional-splitting code paths in the codebase (e.g. `paid_witnessing.js` per-witness division and `storage.js`'s `updateTpsFees` TPS-fee delta split) for the same class of issue, ensuring a global reconciliation step so the sum of distributed amounts never exceeds the source amount.

### Proof of Concept
1. Attacker controls two addresses A and B and authors a 2-author unit `U` with `earned_headers_commission_recipients = [{address: A, earned_headers_commission_share: 50}, {address: B, earned_headers_commission_share: 50}]`. This passes validation because shares sum to 100 [8](#0-7) .
2. `U` (or a child unit authored the same way) wins a parent unit's headers commission where `headers_commission` (i.e., `full_amount`) is an odd number, e.g. `5`.
3. During `calcHeadersCommissions`, for each recipient: `Math.round(5 * 50 / 100) = Math.round(2.5) = 3` [9](#0-8) .
4. Two rows are inserted into `headers_commission_contributions` for amount `3` each, totaling `6`, one more than the `5` actually collected as commission from the parent unit [10](#0-9) .
5. These are aggregated unchecked into `headers_commission_outputs` [7](#0-6)  and become spendable by addresses A and B, netting the attacker 1 extra unit of base currency created from nothing. Repeating this across many won commissions over time compounds the inflation.

### Citations

**File:** validation.js (L1101-1124)
```javascript
function validateHeadersCommissionRecipients(objUnit, cb){
	if (objUnit.authors.length > 1 && typeof objUnit.earned_headers_commission_recipients !== "object")
		return cb("must specify earned_headers_commission_recipients when more than 1 author");
	if ("earned_headers_commission_recipients" in objUnit){
		if (!isNonemptyArray(objUnit.earned_headers_commission_recipients))
			return cb("empty earned_headers_commission_recipients array");
		var total_earned_headers_commission_share = 0;
		var prev_address = "";
		for (var i=0; i<objUnit.earned_headers_commission_recipients.length; i++){
			var recipient = objUnit.earned_headers_commission_recipients[i];
			if (!isPositiveInteger(recipient.earned_headers_commission_share))
				return cb("earned_headers_commission_share must be positive integer");
			if (hasFieldsExcept(recipient, ["address", "earned_headers_commission_share"]))
				return cb("unknown fields in recipient");
			if (!isValidAddress(recipient.address))
				return cb("invalid recipient address checksum");
			if (recipient.address <= prev_address)
				return cb("recipient list must be sorted by address");
			total_earned_headers_commission_share += recipient.earned_headers_commission_share;
			prev_address = recipient.address;
		}
		if (total_earned_headers_commission_share !== 100)
			return cb("sum of earned_headers_commission_share is not 100");
	}
```

**File:** headers_commission.js (L49-56)
```javascript
					UNION ALL \n\
					SELECT punits.unit, earned_headers_commission_recipients.address, \n\
						ROUND(punits.headers_commission*earned_headers_commission_share/100.0) AS hc \n\
					FROM units AS chunits \n\
					JOIN earned_headers_commission_recipients USING(unit) \n\
					JOIN parenthoods ON chunits.unit=parenthoods.child_unit \n\
					JOIN units AS punits ON parenthoods.parent_unit=punits.unit \n\
					JOIN units AS next_mc_units ON next_mc_units.is_on_main_chain=1 AND next_mc_units.main_chain_index=punits.main_chain_index+1 \n\
```

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

**File:** headers_commission.js (L192-206)
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
```

**File:** headers_commission.js (L212-214)
```javascript
								conn.query("INSERT INTO headers_commission_contributions (unit, address, amount) VALUES "+arrValues.join(", "), function(){
									cb();
								});
```

**File:** headers_commission.js (L221-238)
```javascript
		function(cb){
			conn.query(
				"INSERT INTO headers_commission_outputs (main_chain_index, address, amount) \n\
				SELECT main_chain_index, address, SUM(amount) FROM units CROSS JOIN headers_commission_contributions USING(unit) \n\
				WHERE main_chain_index>? \n\
				GROUP BY main_chain_index, address",
				[since_mc_index],
				function(){
					if (conf.bFaster)
						return cb();
					conn.query("SELECT DISTINCT main_chain_index FROM units CROSS JOIN headers_commission_contributions USING(unit) WHERE main_chain_index>?", [since_mc_index], function(contrib_rows){
						if (contrib_rows.length === 1 && contrib_rows[0].main_chain_index === since_mc_index+1 || since_mc_index === 0)
							return cb();
						throwError("since_mc_index="+since_mc_index+" but contributions have mcis "+contrib_rows.map(function(r){ return r.main_chain_index}).join(', '));
					});
				}
			);
		},
```
