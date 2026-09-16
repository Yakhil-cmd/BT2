## Title
Rounding of `earned_headers_commission_share` splits inflates headers-commission payouts beyond the paying unit's `headers_commission` - (File: `headers_commission.js`)

### Summary
The Uniswap report describes two mathematically-related quantities (`getAmountIn`/`getAmountOut`) that are supposed to be exact inverses but diverge because a fee is rounded independently in each direction, letting a caller extract 1 extra wei. The same class of bug — a fixed total amount being split among several recipients using independent, per-recipient rounding with no reconciliation against the original total — exists in ocore's headers-commission distribution logic.

### Finding Description
When a unit wins a headers commission from a parent unit, the fixed amount to distribute (`full_amount`, taken from the payer unit's `headers_commission` field) is split among the child unit's `earned_headers_commission_recipients` by percentage share: [1](#0-0) 

Each recipient's payout is computed independently with `Math.round(full_amount * share / 100.0)`: [2](#0-1) 

The same rounding is used in the SQL/legacy code path: [3](#0-2) 

`validateHeadersCommissionRecipients` only enforces that the declared `earned_headers_commission_share` values are positive integers summing to exactly 100 — it never verifies that rounding the shares of the (fixed, integer) `full_amount` reproduces `full_amount` exactly: [4](#0-3) 

Because `Math.round` is applied per recipient rather than once (e.g., rounding all but the last recipient down and giving the last recipient the remainder), the sum of the rounded shares can be 1 (or more, with more recipients) unit **greater** than `full_amount`. These rounded amounts are inserted into `headers_commission_contributions` and later aggregated into `headers_commission_outputs` via a plain `SUM(amount)`, with no cross-check against the original payer's `headers_commission`: [5](#0-4) 

That aggregated, potentially-inflated total then becomes spendable bytes via a `headers_commission`-type input, whose validation only checks MCI ranges and double-spends — never that the cumulative amount paid out for a given MC index range matches the sum of `headers_commission` fields of the payer units: [6](#0-5) [7](#0-6) 

### Impact Explanation
Any unpriviledged unit poster can author a multi-authored unit (e.g., two addresses they control) and set `earned_headers_commission_recipients` shares (must sum to 100, each a positive integer) so that the per-recipient rounding rounds up for more than one address. For example, with 2 recipients at 50/50 and an odd `full_amount` (a very common value, since `headers_commission` is derived from header byte size), `Math.round(full_amount*0.5)` rounds up for both addresses, so the sum paid out is `full_amount + 1`. This extra unit of value is created out of thin air and is fully spendable, constituting a supply-inflation bug reachable by an ordinary user without requiring privileged network position — it only requires being the author (or one of the authors) of a unit that wins the deterministic (SHA1-hash-tiebreak) headers-commission race for some parent, which any active poster achieves routinely in the normal course of DAG growth.

### Likelihood Explanation
The bug triggers whenever a multi-author unit with more than one `earned_headers_commission_recipients` entry wins headers commission and the chosen percentage split causes rounding to round up on more than one recipient share (easily engineered, e.g. via 50/50 splits against odd `headers_commission` values, or via 3+ recipients each rounding up). Winning the headers-commission race requires no special privilege — it's the ordinary process by which any unit that becomes the majority-selected child of a stable parent earns the commission; an attacker can simply post many candidate units to increase the chance one of theirs wins, or wait for one of their own units to naturally become the winner.

### Recommendation
Do not round each recipient's share independently. Instead, round all recipients except the last down (`Math.floor`), and assign the last recipient `full_amount - sum_of_previous_roundings` so the total distributed always equals `full_amount` exactly — the same fix pattern recommended in the report (avoid independently rounding two values that must reconcile to a fixed total). Additionally, add a consistency check (as is already done for divisible-asset input/output balance, `total_input !== total_output`) verifying that the sum of `headers_commission_contributions`/`headers_commission_outputs` for a payer unit never exceeds that unit's `headers_commission` field.

### Proof of Concept
1. Attacker controls addresses A and B.
2. Attacker authors a 2-author unit (`authors: [A, B]`) that becomes the winning child (per the SHA1 hash tie-break in `getWinnerInfo`) of some stable parent unit whose `headers_commission` is an odd number, e.g. `3`.
3. Attacker sets `earned_headers_commission_recipients = [{address: A, earned_headers_commission_share: 50}, {address: B, earned_headers_commission_share: 50}]` — this passes `validateHeadersCommissionRecipients` since shares sum to 100.
4. When `calcHeadersCommissions` runs, `Math.round(3*50/100)=Math.round(1.5)=2` for both A and B, inserting contributions of 2+2=4 into `headers_commission_contributions`/`headers_commission_outputs`, i.e., 1 unit more than the original `headers_commission` of 3.
5. Both A and B can later spend their `headers_commission`-type inputs (2 each, 4 total) via a payment message; validation of that input type (`validation.js:2579-2599`, `mc_outputs.js:116-132`) never checks the payout against the original `headers_commission` field of the payer unit, so the extra 1 unit passes validation and is spendable — constituting inflation of the total byte supply. [2](#0-1) [8](#0-7)

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

**File:** headers_commission.js (L200-205)
```javascript
											var amount = (row.earned_headers_commission_share === 100) 
												? full_amount 
												: Math.round(full_amount * row.earned_headers_commission_share / 100.0);
											// hc outputs will be indexed by mci of _payer_ unit
											arrValues.push("('"+payer_unit+"', '"+row.address+"', "+amount+")");
										}
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

**File:** validation.js (L2579-2599)
```javascript
					mc_outputs.readNextSpendableMcIndex(conn, type, address, objValidationState.arrConflictingUnits, function(next_spendable_mc_index){
						if (input.from_main_chain_index < next_spendable_mc_index)
							return cb(type + " ranges must not overlap"); // gaps allowed, in case a unit becomes bad due to another address being nonserial
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
