### Title
Independent per-recipient rounding of `earned_headers_commission_share` allows attacker-controlled headers-commission inflation - (File: headers_commission.js)

### Summary
`headers_commission.js` splits a parent unit's fixed `headers_commission` among the child unit's `earned_headers_commission_recipients` by rounding each recipient's share **independently** with `Math.round`, instead of rounding once and giving the remainder to a single recipient (or rounding down and giving dust to a designated party). Because `earned_headers_commission_recipients` and their percentage `earned_headers_commission_share` values are fully attacker-controlled fields on any unit a user posts (`validation.js:validateHeadersCommissionRecipients` only requires shares to sum to 100), a malicious unit poster can choose share percentages such that the sum of independently-rounded amounts exceeds the original `full_amount`, minting extra spendable bytes commission that were never actually paid in fees by the payer unit.

### Finding Description
When a child unit "wins" the headers commission of a parent unit, the commission is split into `headers_commission_contributions` per address: [1](#0-0) 

```
for (var address in objUnit.assocEarnedHeadersCommissionRecipients) {
    var share = objUnit.assocEarnedHeadersCommissionRecipients[address];
    var amount = Math.round(full_amount * share / 100.0);
    arrValuesRAM.push("('"+payer_unit+"', '"+address+"', "+amount+")");
};
``` [2](#0-1) 

and, for the SQL-verified path:
```
var amount = (row.earned_headers_commission_share === 100) 
    ? full_amount 
    : Math.round(full_amount * row.earned_headers_commission_share / 100.0);
arrValues.push("('"+payer_unit+"', '"+row.address+"', "+amount+")");
``` [3](#0-2) 

Each recipient's slice is rounded to the nearest integer independently, with no correction step to ensure `SUM(amount) == full_amount`. `earned_headers_commission_share` values are set by the unit's own author(s) and validated only for range/uniqueness and that the shares sum to exactly 100:

```
total_earned_headers_commission_share += recipient.earned_headers_commission_share;
...
if (total_earned_headers_commission_share !== 100)
    return cb("sum of earned_headers_commission_share is not 100");
``` [4](#0-3) 

No check anywhere requires `sum(round(full_amount*share/100))` to equal `full_amount`. Because standard rounding (`Math.round`, round-half-up) is applied per recipient, an attacker can pick shares (e.g., two recipients at 50%/50%) so that when `full_amount` is odd, both shares round up (`Math.round(0.5*odd)` rounds up for both halves), yielding `sum = full_amount + 1`. These per-address amounts are subsequently aggregated unconditionally into `headers_commission_outputs`: [5](#0-4) 

and are later spendable as ordinary bytes via `type: "headers_commission"` inputs, validated in `validation.js`, which simply trusts the pre-computed `calcEarnings` result as the correct spendable total: [6](#0-5) 

This constitutes an unauthorized minting path: the amount paid out to the union of recipients can permanently exceed the commission actually deducted from the payer unit's size-based fee, i.e. new base-currency value appears with no corresponding payer input.

### Impact Explanation
This directly causes byte supply inflation: an attacker who authors a unit and sets `earned_headers_commission_recipients` with carefully chosen shares (any unprivileged unit poster can do this — no special witness/hub/operator privilege needed) receives more total headers commission than the parent unit paid, whenever their unit wins the headers-commission lottery for that parent and `full_amount` has the right parity relative to the chosen split. Repeated over many units/parents, this steadily inflates total currency supply, degrading the network's currency-supply invariant that all bytes in circulation trace back to the fixed genesis issuance and legitimate fees. This is a Medium/High severity issue because it is a systemic, repeatable inflation bug reachable purely by posting ordinary units, not requiring any privileged role.

### Likelihood Explanation
Likelihood is high: `earned_headers_commission_recipients` is a normal, documented unit field available to any author; splitting to exactly two recipients at 50/50 with an odd `headers_commission` value (which happens routinely, since header commission scales with unit/parent size in a way that is not always even) triggers the excess. An attacker does not need to control which unit "wins" the header-commission lottery deterministically for a specific parent — they simply need to post many qualifying multi-recipient units over time so that, statistically, roughly half of the wins occur against an odd `full_amount`, each yielding a 1-unit gain. This can be scripted and repeated cheaply (cost is one ordinary unit's fee vs. gain of a whole extra commission unit), making it economically incentivized to run continuously.

### Recommendation
Compute the split deterministically so the parts sum exactly to `full_amount`:
- Round all-but-the-last recipient's share normally (or floor), then assign the last recipient (sorted deterministically, e.g. by address) the remainder `full_amount - sum(previous rounded amounts)`.
- Alternatively, use largest-remainder apportionment: compute floors for all recipients, then distribute the leftover `full_amount - sum(floors)` units one-by-one to the recipients with the largest fractional remainders (in a deterministic tie-break order, e.g. by address) until the deficit is exhausted.
- Apply the identical algorithm consistently in both the SQL/DB code path and the in-memory (`conf.bFaster`) RAM code path in `headers_commission.js`, since they must remain equal per the existing consistency check.
- Add an assertion in `calcHeadersCommissions` that `SUM(amount)` per `(payer_unit)` group equals the parent's `headers_commission` before insertion, to guarantee no accidental future regression reintroduces excess/shortfall.

### Proof of Concept
1. Attacker posts unit `U` with two authors (or uses `earned_headers_commission_recipients` targeting two addresses A and B under their control) with:
```
earned_headers_commission_recipients: [
  { address: "A...", earned_headers_commission_share: 50 },
  { address: "B...", earned_headers_commission_share: 50 }
]
```
This passes `validateHeadersCommissionRecipients` since `50 + 50 = 100`.
2. Attacker structures/waits for `U` to be the winning child unit (per `getWinnerInfo` hash-lottery logic) for a parent unit `P` whose `headers_commission` (`full_amount`) is odd, e.g. `full_amount = 1001`.
3. In `calcHeadersCommissions`, for each recipient:
   - `amount_A = Math.round(1001 * 50 / 100) = Math.round(500.5) = 501`
   - `amount_B = Math.round(1001 * 50 / 100) = 501`
   - Total inserted into `headers_commission_contributions`/`headers_commission_outputs` = `1002`, i.e., 1 byte more than `P` actually paid (`1001`).
4. Addresses A and B can later spend these `headers_commission_outputs` as ordinary base-asset inputs (validated in `validation.js` around lines 2588–2599), realizing the extra byte as real spendable value.
5. Repeating this across many units/parents accumulates supply inflation proportional to the number of odd-`full_amount` wins the attacker can obtain.

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

**File:** headers_commission.js (L200-204)
```javascript
											var amount = (row.earned_headers_commission_share === 100) 
												? full_amount 
												: Math.round(full_amount * row.earned_headers_commission_share / 100.0);
											// hc outputs will be indexed by mci of _payer_ unit
											arrValues.push("('"+payer_unit+"', '"+row.address+"', "+amount+")");
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

**File:** validation.js (L1107-1123)
```javascript
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
```

**File:** validation.js (L2588-2599)
```javascript
						var calcFunc = (type === "headers_commission") ? mc_outputs.calcEarnings : paid_witnessing.calcWitnessEarnings;
						calcFunc(conn, type, input.from_main_chain_index, input.to_main_chain_index, address, {
							ifError: function(err){
								throw Error(err);
							},
							ifOk: function(commission){
								if (commission === 0)
									return cb("zero "+type+" commission");
								total_input += commission;
								checkInputDoubleSpend(cb);
							}
						});
```
