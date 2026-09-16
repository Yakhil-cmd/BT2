### Title
Independent per-recipient rounding in headers commission distribution can inflate total bytes paid out beyond the collected commission - ([File: headers_commission.js])

### Summary
`calcHeadersCommissions()` splits a parent unit's `headers_commission` among multiple `earned_headers_commission_recipients` by independently rounding each recipient's share with `Math.round(full_amount * share / 100.0)`. Because rounding is done per-recipient instead of using a remainder-preserving allocation, the sum of the rounded amounts can exceed `full_amount`, creating base-currency ("bytes") funds that were never actually collected from the payer unit — the same class of bug as the reported issue, where per-item integer/rounding math silently drops the constraint that outputs must equal the true input value.

### Finding Description
When a child unit has multiple authors (or otherwise defines `earned_headers_commission_recipients`), `validateHeadersCommissionRecipients` only enforces that the recipient shares are positive integers summing to exactly 100: [1](#0-0) 

Later, when headers commissions are actually calculated and paid out, each recipient's payout is computed independently as:
```
var amount = Math.round(full_amount * share / 100.0);
```
for the SQLite/in-memory path, and equivalently `ROUND(punits.headers_commission*earned_headers_commission_share/100.0)` for the MySQL path: [2](#0-1) [3](#0-2) 

There is no post-processing step that adjusts the last recipient's share to make the total match `full_amount` (a "largest remainder"/"give the rounding error to one recipient" approach). Because `Math.round` rounds `.5` up, a pair of recipients whose exact shares each end in `.5` can each round up, so the sum of amounts credited across `headers_commission_contributions` (and later `headers_commission_outputs`) can be strictly greater than `full_amount`, i.e., greater than the `headers_commission` value that was actually paid by the payer unit and validated against `objectLength.getHeadersSize(objUnit)`: [4](#0-3) 

Concretely: if `full_amount = 7` and two recipients each hold a 50% share, `Math.round(7*50/100) = Math.round(3.5) = 4` for both, for a total of `8` — one unit of bytes materialized out of nothing. This total is inserted directly into `headers_commission_contributions`/`headers_commission_outputs`, which later become spendable via a `headers_commission` input type, validated in `validatePaymentInputsAndOutputs` purely by looking up the precomputed table value (via `mc_outputs.calcEarnings`), not by re-deriving it from the actual payer's commission: [5](#0-4) 

An attacker who controls all authors of a multi-authored unit can freely choose the number of authors and the `earned_headers_commission_share` percentages (only constrained to be positive integers summing to 100) to engineer rounding patterns that leak extra bytes whenever that unit wins the headers-commission race for one of its parent units.

### Impact Explanation
This allows an attacker-controlled set of addresses to accumulate spendable base-currency ("bytes") outputs that exceed what was actually paid as `headers_commission` by real payer units — a form of supply inflation of the network's native currency. Because `headers_commission_outputs` entries are treated as authoritative and directly redeemable, the extra bytes are real, spendable value drained from the overall commission pool distribution, degrading the accounting invariant that headers-commission payouts must equal headers-commission collected.

### Likelihood Explanation
Exploitation only requires posting an ordinary multi-authored unit (or any unit with `earned_headers_commission_recipients`) with author/share combinations chosen to produce rounding-up on multiple recipients simultaneously, and then winning the headers-commission race for a parent unit (deterministic, not adversarial-timing dependent, and controllable by author's own follow-up units). No privileged role, hub, or malicious peer behavior is required — an ordinary unit poster can trigger this via crafted `earned_headers_commission_recipients` shares.

### Recommendation
Replace independent per-recipient rounding with an allocation method that guarantees the sum of distributed amounts equals `full_amount` exactly, e.g., compute all-but-last recipients with `Math.round`/`Math.floor` and assign the last recipient `full_amount - sum(previous amounts)`, or use a canonical largest-remainder method. Apply the same fix to both the SQLite in-memory path and the MySQL `ROUND(...)` SQL path in `headers_commission.js`.

### Proof of Concept
1. Create two addresses `A` and `B` controlled by the attacker.
2. Author a unit with authors `[A, B]` and `earned_headers_commission_recipients: [{address: A, earned_headers_commission_share: 50}, {address: B, earned_headers_commission_share: 50}]` — passes `validateHeadersCommissionRecipients` since the shares sum to 100.
3. Arrange (via normal DAG structure/parent selection, which the attacker controls for their own units) for this unit to win the headers-commission race for a parent unit whose `headers_commission` (an odd number, e.g., 7 bytes, achievable by controlling header content/size) is being distributed.
4. `calcHeadersCommissions` computes `amount_A = Math.round(7*50/100) = 4` and `amount_B = Math.round(7*50/100) = 4`, inserting a total of `8` bytes into `headers_commission_contributions`/`headers_commission_outputs` for a `full_amount` of `7`.
5. Both `A` and `B` later spend their `headers_commission` inputs normally via `validatePaymentInputsAndOutputs`, which only checks the precomputed `calcEarnings` value, realizing `8` bytes of spendable value from `7` bytes actually paid — a 1-byte inflation per occurrence, repeatable at scale.

### Citations

**File:** validation.js (L257-258)
```javascript
		if (objectLength.getHeadersSize(objUnit) !== objUnit.headers_commission)
			return callbacks.ifJointError("wrong headers commission, expected "+objectLength.getHeadersSize(objUnit));
```

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

**File:** headers_commission.js (L49-66)
```javascript
					UNION ALL \n\
					SELECT punits.unit, earned_headers_commission_recipients.address, \n\
						ROUND(punits.headers_commission*earned_headers_commission_share/100.0) AS hc \n\
					FROM units AS chunits \n\
					JOIN earned_headers_commission_recipients USING(unit) \n\
					JOIN parenthoods ON chunits.unit=parenthoods.child_unit \n\
					JOIN units AS punits ON parenthoods.parent_unit=punits.unit \n\
					JOIN units AS next_mc_units ON next_mc_units.is_on_main_chain=1 AND next_mc_units.main_chain_index=punits.main_chain_index+1 \n\
					WHERE chunits.is_stable=1 \n\
						AND +chunits.sequence='good' \n\
						AND punits.main_chain_index>? \n\
						AND chunits.main_chain_index-punits.main_chain_index<=1 \n\
						AND +punits.sequence='good' \n\
						AND punits.is_stable=1 \n\
						AND next_mc_units.is_stable=1 \n\
						AND chunits.unit=( "+best_child_sql+" )", 
					[since_mc_index, since_mc_index], 
					function(){ cb(); }
```

**File:** headers_commission.js (L176-202)
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
```
