### Title
Rounding of split headers-commission shares silently mints or destroys bytes - (File: headers_commission.js)

### Summary
The reported AMM bug class is: a value is split between parties using a percentage/ratio, the actual on-chain settlement can only occur in discrete units, and the modulo/rounding remainder is silently discarded (or, symmetrically, invented) instead of being tracked and reconciled. The same discretization pattern exists in `calcHeadersCommissions()` in `headers_commission.js`, where a fixed integer `headers_commission` amount owed by a payer unit is split among multiple `earned_headers_commission_recipients` using independent `Math.round()` operations per recipient, with no reconciliation step to make the parts sum back to the whole.

### Finding Description
When a unit has multiple authors (or explicitly declares `earned_headers_commission_recipients`), any author who "wins" headers commission from a parent unit does not receive the whole `headers_commission` amount as a single output. Instead, the amount is split per recipient address according to `earned_headers_commission_share` (a percentage), using: [1](#0-0) 

and, in the non-`bFaster` SQL-verification path: [2](#0-1) 

Each recipient's share of `full_amount` is rounded independently to the nearest integer with `Math.round(full_amount * share / 100.0)`. Validation only guarantees that the declared `earned_headers_commission_share` values sum to exactly 100: [3](#0-2) 

but summing 100% of *shares* does not guarantee that the sum of independently-rounded integer *amounts* equals `full_amount`. For example, with `full_amount = 10` split three ways as `34/33/33`, the rounded amounts are `3.4→3`, `3.3→3`, `3.3→3`, summing to `9`, one byte short of the original `10`. Conversely, other share splits can round up and produce one byte more than `full_amount`.

These rounded amounts are what actually get written to `headers_commission_contributions` and subsequently aggregated into `headers_commission_outputs`: [4](#0-3) 

The resulting `headers_commission_outputs` rows are the only source the recipients can later spend from as a `headers_commission` input in a payment (validated/summed via `mc_outputs.calcEarnings`, referenced in `validation.js`): [5](#0-4) 

So the byte(s) lost (or gained) to rounding are not tracked anywhere and are not recoverable by any party — precisely the "leftover discarded" pattern described in the AMM report, except here the analog is "supply drift" rather than a discarded trade remainder.

### Impact Explanation
Every multi-author unit whose author chooses to (or is forced to, when co-authoring) split `earned_headers_commission_recipients` into shares that don't divide `full_amount` evenly introduces a ±1 (or occasionally more, with many recipients) byte discrepancy between the commission actually owed by the payer unit (`headers_commission`, a value baked into the unit and consensus-verified as `objectLength.getHeadersSize`) and the sum of the amounts recipients can actually claim. Because this happens deterministically and identically on every full node (all nodes recompute the same `Math.round` split), it does not cause a consensus fork or node disagreement — but it is a genuine, network-wide, uncontrolled drift in total spendable/circulating bytes (deflation when rounding down in aggregate, inflation when rounding up), which occurs entirely outside of the intended fixed-total-supply design of the base asset.

### Likelihood Explanation
This is trivially reachable by any address that authors a multi-author unit (or is included as an `earned_headers_commission_recipients` entry) — no special privileges are required, only the ability to post a unit with 2+ authors and to choose share percentages that do not evenly divide arbitrary future `headers_commission` amounts. Since `headers_commission` values vary per unit (header size dependent) and shares are chosen ahead of time, exact reconciliation is impossible by design, so essentially every real-world multi-author/multi-recipient unit is affected to a small degree, and an attacker wanting to systematically bias the rounding in their favor across many units controls the share values directly.

### Recommendation
- Track the reconciliation remainder explicitly: compute all recipients' shares with `Math.floor`, then add the leftover `full_amount - sum(floored_amounts)` to one deterministically-chosen recipient (e.g., last in sorted address order) so the total distributed always equals `full_amount` exactly.
- Alternatively, document (as the original report recommends for the AMM/`Perpetual.liquidateFrom` case) that headers-commission splitting with more than one recipient can result in a ±1-byte-per-recipient rounding drift, and that this is an accepted design trade-off rather than a bug.
- Add a consensus-level invariant check (already partially done via the `_.isEqual` cross-check between RAM and SQL computations) that also asserts `sum(distributed amounts) === full_amount` for each payer unit, failing loudly if violated, to make any future drift immediately visible instead of silently compounding.

### Proof of Concept
1. Construct a 3-author unit (`A`, `B`, `C`) with `earned_headers_commission_recipients` shares `34`, `33`, `33` (sums to 100, passes `validateHeadersCommissionRecipients` in `validation.js` lines 1101-1126).
2. Have this unit stabilize and win headers commission from a parent whose `headers_commission = 10` (a small header size is easy to arrange).
3. `calcHeadersCommissions()` computes, for each recipient: `Math.round(10*34/100)=3`, `Math.round(10*33/100)=3`, `Math.round(10*33/100)=3` — total `9`, not `10` — as seen in the split logic at [6](#0-5) .
4. One byte of the payer's `headers_commission` (which was deducted from the payer's spendable balance as part of the unit's fee, per `objectLength.getHeadersSize` validated equal to `headers_commission` in `validation.js` lines 257-258) is now unaccounted for in `headers_commission_outputs` and can never be claimed by anyone — net destruction of 1 byte from total circulating supply. Repeating with share splits like `1/1/98` instead produces rounding in the opposite direction and net creation of bytes.

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

**File:** validation.js (L2582-2599)
```javascript
						var max_mci = (type === "headers_commission") 
							? headers_commission.getMaxSpendableMciForLastBallMci(objValidationState.last_ball_mci)
							: paid_witnessing.getMaxSpendableMciForLastBallMci(objValidationState.last_ball_mci);
						if (input.to_main_chain_index > max_mci)
							return cb(type+" to_main_chain_index is too large");

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
