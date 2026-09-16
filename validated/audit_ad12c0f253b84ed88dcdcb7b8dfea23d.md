### Title
Independent per-recipient rounding in headers-commission distribution can inflate the byte supply - (File: `headers_commission.js`)

### Summary
`calcHeadersCommissions` splits a fixed `headers_commission` (or `payload_commission`, see `paid_witnessing.js`) amount that a unit reserved among multiple `earned_headers_commission_recipients` by independently applying `Math.round(full_amount * share / 100.0)` to each recipient's share. [1](#0-0)  Because each recipient's payout is rounded separately rather than the remainder being distributed once, the sum of the rounded amounts can exceed the original `full_amount` that the payer unit set aside, i.e., new spendable value materializes without a corresponding deduction, similar in spirit to the Mellow `ratiosX96Value` bug where independent rounding on one side of an equation causes the amount actually paid out to diverge from — and exceed — the amount that should back it.

### Finding Description
When an author of a stable, "good"-sequence unit specifies `earned_headers_commission_recipients` (validated only for `isPositiveInteger` shares, sorted addresses, and a sum equal to 100 in `validateHeadersCommissionRecipients`), the unit poster fully controls how many recipients there are and what share each one gets, as long as the shares sum to exactly 100. [2](#0-1) 

During header-commission settlement, for every payer unit whose `headers_commission` was won by this child unit, the code computes, for each recipient, `Math.round(full_amount * share / 100.0)` independently: [3](#0-2)  and, in the multi-parent aggregation branch, does so again per payer/recipient pair with the explicit comment that "we round _before_ summing up header commissions won from several parent units": [4](#0-3) . Note the equivalent SQL path performs the same operation with `ROUND(punits.headers_commission*earned_headers_commission_share/100.0)`. [5](#0-4) 

Because rounding is performed on each fractional share independently (instead of, e.g., giving the last recipient the remainder), the sum `Σ round(full_amount * share_i / 100)` is not guaranteed to equal `full_amount`. A unit poster who controls the recipient list and share values can deliberately choose a large number of near-`x.5` shares so that most/all of the individual roundings round up, making the total distributed to `headers_commission_outputs` (which subsequently become spendable base-asset inputs, see `INSERT INTO headers_commission_outputs ... SUM(amount)` aggregation) exceed the `headers_commission` that was actually reserved on the payer unit. [6](#0-5)  This is the analog of the Mellow bug: a value that should be conserved between payer and recipients is instead allowed to grow via independently-rounded shares, ending up favoring the party that controls the split (the unit's author) at the expense of protocol-wide currency conservation.

### Impact Explanation
Each abuse instance creates only a small amount of extra base currency (bounded by roughly `(recipient_count - 1) * 0.5` bytes per settled headers-commission event), but:
- It is directly reachable by any unprivileged unit poster who authors units with multiple authors/recipients — no special privilege, hub cooperation, or network-level manipulation is required.
- It is repeatable indefinitely: an attacker can post many multi-recipient units over time to accumulate inflated supply.
- It breaks the invariant that `headers_commission_outputs` paid out for a given payer unit must equal exactly the `headers_commission` value that unit reserved, which is a supply-conservation guarantee the protocol otherwise strictly enforces (e.g., validation requires shares to sum to exactly 100).

This matches the "supply inflation" impact category called out in the analog bug class.

### Likelihood Explanation
Likelihood is high in terms of reachability (any unit author with `earned_headers_commission_recipients` can attempt it), but the magnitude per exploit is small (sub-byte-per-recipient rounding), so meaningful inflation requires repeated, deliberate abuse across many units/recipients. The mechanism is deterministic and fully attacker-controlled (choice of shares/recipient count), unlike a probabilistic bug, which raises confidence that the divergence is systematically exploitable rather than incidental noise.

### Recommendation
Do not round each recipient's share independently. Instead:
- Compute the rounded amount for all but the last recipient, then assign the last recipient `full_amount - Σ(previous rounded amounts)` so the total always equals `full_amount` exactly, or
- Use a largest-remainder (Hamilton) apportionment method to distribute `full_amount` across recipients so the sum is conserved by construction.
Apply the same fix consistently to both the JS in-memory path and the MySQL `ROUND(...)` SQL path in `headers_commission.js`, and audit `paid_witnessing.js`'s analogous `Math.round(payload_commission / count)` distribution for the same conservation property.

### Proof of Concept
1. Attacker authors a unit with multiple `earned_headers_commission_recipients`, choosing addresses/shares summing to 100, e.g. 3 recipients with shares `33`, `33`, `34` for a `full_amount` of, say, 100 bytes of headers commission won from a parent unit.
2. `Math.round(100*33/100)=33`, `Math.round(100*33/100)=33`, `Math.round(100*34/100)=34` → sums to 100 (no drift in this trivial case). By instead choosing shares like `17, 17, 17, 17, 16, 16` (sum 100) against carefully chosen `full_amount` values where each product lands just above `x.5` before rounding, the attacker can make several terms round up simultaneously, so `Σround(...) > full_amount`.
3. Repeat this pattern across many self-authored units (headers commission is earned by any unit's authors whose unit becomes the majority-witnessed "best child" of a parent), accumulating the excess as spendable `headers_commission_outputs` inputs credited to attacker-controlled addresses. [7](#0-6) 

Note: I was unable to fully verify whether there is any additional cap on the number of `earned_headers_commission_recipients` entries per unit within the available index (the `MAX_AUTHORS_PER_UNIT` constant governs authors, not necessarily this recipients list), which affects how much excess can be engineered per unit; a Devin session with full repository access would be needed to confirm this bound precisely.

### Citations

**File:** headers_commission.js (L49-51)
```javascript
					UNION ALL \n\
					SELECT punits.unit, earned_headers_commission_recipients.address, \n\
						ROUND(punits.headers_commission*earned_headers_commission_share/100.0) AS hc \n\
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

**File:** headers_commission.js (L212-214)
```javascript
								conn.query("INSERT INTO headers_commission_contributions (unit, address, amount) VALUES "+arrValues.join(", "), function(){
									cb();
								});
```

**File:** headers_commission.js (L221-237)
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
```

**File:** validation.js (L1101-1126)
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
	cb();
}
```
