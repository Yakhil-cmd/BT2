Confirmed: `headers_commission_contributions.amount` is later summed directly into `headers_commission_outputs` via a plain `SUM(amount)` aggregation with no cross-check that the sum of split amounts equals the original `headers_commission` paid by the parent unit. [1](#0-0) 

### Title
Rounding in multi-recipient headers-commission split allows supply inflation - (File: headers_commission.js)

### Summary
When a unit that wins a parent's headers commission has multiple authors (or a designated `earned_headers_commission_recipients` list), the total commission `full_amount` is split among recipients by `Math.round(full_amount * share / 100.0)` per recipient, with no reconciliation step ensuring the sum of the rounded per-recipient amounts equals `full_amount`. This is the exact bug class in the referenced report: a "total pool" divided among N parties using independent rounding per party, with no pessimistic/leftover accounting, so the sum of individual shares can diverge from the actual funds available/paid.

### Finding Description
`validateHeadersCommissionRecipients()` only checks that the recipient shares (percentages) sum to exactly 100: [2](#0-1) 

It does **not** constrain the shares to avoid rounding drift when applied to arbitrary `full_amount` values. In `calcHeadersCommissions()`, the actual currency split is computed independently per recipient: [3](#0-2) [4](#0-3) 

Because each recipient's amount is rounded to the nearest integer independently (`Math.round(full_amount * share / 100.0)`), the sum over all recipients for a given `full_amount` can be **greater than** `full_amount` (e.g., two recipients with a 50/50 split and an odd `full_amount`: `Math.round(x*0.5)` rounds `.5` up for both halves, producing `full_amount + 1` in total). These rounded amounts are inserted directly into `headers_commission_contributions` with no correction, and are later aggregated verbatim into `headers_commission_outputs`: [5](#0-4) [1](#0-0) 

`headers_commission_outputs` rows become directly spendable balances via `headers_commission` type payment inputs, validated/consumed through `mc_outputs.calcEarnings()` (a plain `SUM(amount)` over the output table) and `validation.js`'s payment-input handling: [6](#0-5) [7](#0-6) 

Since these outputs are treated as first-class spendable bytes (no different from a witness/headers commission that was actually collected from headers space), any rounding surplus is money created out of thin air — unlike the referenced report where rounding+dust caused a *shortfall*, here the analogous flaw (independent per-recipient rounding of a shared pool with no total-conservation check) produces a *surplus*, i.e., supply inflation.

### Impact Explanation
This directly matches the accepted impact category "supply inflation": the network's total byte/commission supply can be inflated beyond what parent units actually paid in `headers_commission`. An attacker who repeatedly wins headers commissions (feasible since anyone can post units, and any single/multi-author unit can become a "winning child" for its parent's headers commission by chance or by strategically posting many competing children) and who controls a 2+-author winning unit can choose share percentages (e.g., odd `full_amount` with 50/50, or other combinations proven to round up) to consistently mint 1+ extra unit of currency per event, accumulating supply inflation over time across the whole network — every node computes the same (inflated) result deterministically from consensus data, so there is no node-disagreement, but the supply itself silently grows.

### Likelihood Explanation
Multi-author units and `earned_headers_commission_recipients` are a standard, unprivileged feature — any user can post a unit with 2+ authors and choose the recipient share percentages (only constrained to sum to 100). Headers commissions are awarded to arbitrary winning child units chosen via a hash-based "lottery" among candidate children, so an attacker controlling several candidate children (all their own multi-author units) can guarantee that whichever of their own units wins, its recipient list is crafted to trigger rounding surplus. This can be repeated arbitrarily often over time, making exploitation entirely feasible for a patient, unprivileged attacker.

### Recommendation
Do not round each recipient's share independently. Instead, use a conservation-preserving distribution algorithm (e.g., compute one recipient's amount as the remainder `full_amount - sum(previous rounded amounts)`, or floor all shares and distribute the residual dust deterministically to a fixed recipient, similar to the `runningBalance`-avoidance recommendation in the original report). Add a runtime/validation-time invariant that `SUM(amount)` inserted into `headers_commission_contributions` for a given `(unit)` never exceeds the parent's `headers_commission` value, rejecting or truncating any unit-processing that would violate it.

### Proof of Concept
1. Attacker creates unit `P` (parent) with some `headers_commission` value that is odd, e.g. 355 (this can be arranged by controlling header/parent-count structure).
2. Attacker crafts a child unit `C` with 2 authors (both attacker-controlled addresses) and `earned_headers_commission_recipients = [{address:A, share:50}, {address:B, share:50}]` (sums to 100, passes `validateHeadersCommissionRecipients`).
3. Attacker ensures `C` wins the headers-commission lottery for `P` (e.g., by posting several candidate children and relying on the deterministic hash-sort winner selection, or by only having a single valid candidate child).
4. When `calcHeadersCommissions()` runs, `full_amount = 355`; for both A and B, `Math.round(355 * 50 / 100.0) = Math.round(177.5) = 178`, giving a total of `356` inserted into `headers_commission_contributions` versus the actual `355` paid by `P`.
5. This surplus of `1` is aggregated into `headers_commission_outputs` for addresses A and B, becoming spendable balance indistinguishable from legitimately earned commission.
6. Repeating this pattern across many won headers commissions accumulates network-wide supply inflation.

### Citations

**File:** headers_commission.js (L179-188)
```javascript
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

**File:** headers_commission.js (L221-227)
```javascript
		function(cb){
			conn.query(
				"INSERT INTO headers_commission_outputs (main_chain_index, address, amount) \n\
				SELECT main_chain_index, address, SUM(amount) FROM units CROSS JOIN headers_commission_contributions USING(unit) \n\
				WHERE main_chain_index>? \n\
				GROUP BY main_chain_index, address",
				[since_mc_index],
```

**File:** validation.js (L1119-1123)
```javascript
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

**File:** mc_outputs.js (L116-132)
```javascript
function calcEarnings(conn, type, from_main_chain_index, to_main_chain_index, address, callbacks){
	var table = type + '_outputs';
	conn.query(
		"SELECT SUM(amount) AS total \n\
		FROM "+table+" \n\
		WHERE main_chain_index>=? AND main_chain_index<=? AND +address=?",
		[from_main_chain_index, to_main_chain_index, address],
		function(rows){
			var total = rows[0].total;
			if (total === null)
				total = 0;
			if (typeof total !== 'number')
				throw Error("mc outputs total is not a number");
			callbacks.ifOk(total);
		}
	);
}
```
