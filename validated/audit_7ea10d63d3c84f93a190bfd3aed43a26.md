### Title
Headers‑commission redistribution rounding lets a multi‑author unit inflate byte supply - ([File: headers_commission.js])

### Summary
The Allo report shows that splitting a percentage‑based fee into many small pieces and always forcing the division to round down lets an attacker pay (or receive) less than the correct amount. `ocore` has the mirror‑image bug in the headers‑commission redistribution logic: a unit author fully controls `earned_headers_commission_recipients`, and the network computes each recipient's share of the won commission **independently** with `Math.round()`. Because independent rounding of several fractional shares that individually sum to exactly 100% does not guarantee the rounded amounts sum to the original integer amount, an attacker can pick shares that make every fractional share end near `.5` and have `Math.round` push every one of them up, so the *sum credited to recipients exceeds the commission actually paid by the parent unit* — new bytes are created out of thin air.

### Finding Description
`validateHeadersCommissionRecipients()` only checks that the shares are positive integers, addresses are sorted, and that they sum to exactly 100: [1](#0-0) 

It performs no check on how the rounded distribution of an arbitrary `full_amount` (the headers commission won from a parent unit) behaves — it just accepts any list of (address, share) pairs whose shares sum to 100.

When headers commissions are actually distributed, each recipient's amount is computed independently via `Math.round(full_amount * share / 100.0)`, both in the JS/in‑memory path and in the raw SQL path used for the MySQL/sqlite backends: [2](#0-1) [3](#0-2) [4](#0-3) 

Because each recipient's rounding is done separately, and no remainder correction is applied to make the rounded amounts sum back to `full_amount`, a carefully chosen split of shares can make the sum of rounded amounts *larger* than `full_amount`. For example, with `full_amount = 1` and two recipients each given `share = 50`, each gets `Math.round(1 * 50 / 100) = Math.round(0.5) = 1`, for a total of `2` — double the commission that was actually paid by the parent unit. With more recipients (the array size is bounded only by unit size limits, not by author count — recipients need not be authors), the same `.5`‑boundary trick can be repeated to accumulate a larger absolute excess in a single unit, and this can be done repeatedly by any user composing multi‑authored units, since the attacker fully controls `earned_headers_commission_recipients` via `composeJoint()`: [5](#0-4) 

The distributed amounts are inserted verbatim into `headers_commission_contributions`, summed into `headers_commission_outputs`, and later spendable as `type: "headers_commission"` inputs (see the validation/spend path referencing `headers_commission.getMaxSpendableMciForLastBallMci`): [6](#0-5) [7](#0-6) 

There is no compensating burn elsewhere: the parent unit paid a fixed, size‑based `headers_commission` amount once; if the winner distributes it to itself/its own addresses via rounding‑favorable shares, the total bytes credited to `headers_commission_outputs` can exceed what was actually paid in, which is a supply‑inflation bug reachable by any ordinary user who can post a multi‑authored unit and win a headers‑commission distribution.

### Impact Explanation
This allows an unprivileged unit poster to mint extra bytes (or other network‑fee‑denominated units of headers commission) beyond what any parent unit actually paid, i.e. concrete supply inflation of the base currency. Because headers commissions are a core, protocol‑level economic mechanism (every unit that acts as a "best child" collects a commission from its parents), even small per‑unit rounding gains compound across many units/recipients over time, and the technique can be deliberately repeated to maximize gain within a single unit by choosing shares that hit the `.5` rounding boundary for many recipients at once.

### Likelihood Explanation
Any user can create a multi‑authored unit and freely set `earned_headers_commission_recipients` (only constraint is that shares are positive integers summing to 100, per `validateHeadersCommissionRecipients`). Winning the headers commission from a parent is probabilistic (decided by a hash-based winner selection among candidate children), but is fully within reach of a normal user who structures their DAG activity to become the winning child — this does not require any special/validator privilege, network position, or leaked key, only crafting of unit contents that any wallet/API user can do.

### Recommendation
When distributing `full_amount` across `earned_headers_commission_recipients`, do not round each recipient's share independently. Instead:
- Compute all shares' amounts with a method that guarantees the sum of rounded amounts equals `full_amount` exactly (e.g., largest‑remainder method: floor each share, then distribute the leftover units one‑by‑one to the recipients with the largest fractional remainders), or
- Give the last recipient (by sorted address) `full_amount - sum_of_previous_roundings` instead of independently rounding it.

Apply the same fix consistently in the JS in‑memory path (`headers_commission.js:183`, `headers_commission.js:200-202`) and in the raw SQL path used by the MySQL backend (`headers_commission.js:49-51`), since divergence between the two would itself trigger the code's own `throwError` consistency checks.

### Proof of Concept
1. Create two addresses A and B, both controlled by the same attacker (multi‑authored unit with A and B as authors, or simply naming any address as an "earned commission recipient" — recipients need not even be authors).
2. Ensure the attacker's unit is a winning child of a parent unit whose `headers_commission` is an odd number (e.g. any parent whose headers commission is 1, 3, 5, … or generally leads to a `.5` fractional value after multiplying by 50%).
3. Set `earned_headers_commission_recipients = [{address: A, earned_headers_commission_share: 50}, {address: B, earned_headers_commission_share: 50}]` via `composeJoint()`'s `params.earned_headers_commission_recipients`.
4. When `calcHeadersCommissions()` runs, both `headers_commission.js:183` and `headers_commission.js:200-202` compute `Math.round(full_amount * 50 / 100)`. For `full_amount = 1`, each recipient is credited `Math.round(0.5) = 1`, for a total of `2` credited into `headers_commission_contributions`/`headers_commission_outputs`, i.e. double the commission the parent unit actually paid.
5. Repeat this pattern with many recipients (limited only by unit size limits) across many units to accumulate a materially larger amount of "free" bytes credited to attacker‑controlled addresses, which can later be spent via `type: "headers_commission"` inputs.

### Citations

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

**File:** headers_commission.js (L49-51)
```javascript
					UNION ALL \n\
					SELECT punits.unit, earned_headers_commission_recipients.address, \n\
						ROUND(punits.headers_commission*earned_headers_commission_share/100.0) AS hc \n\
```

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

**File:** headers_commission.js (L193-209)
```javascript
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

**File:** headers_commission.js (L212-245)
```javascript
								conn.query("INSERT INTO headers_commission_contributions (unit, address, amount) VALUES "+arrValues.join(", "), function(){
									cb();
								});
							}
						);
					}
				);
			} // sqlite
		},
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
		function(cb){
			conn.query("SELECT MAX(main_chain_index) AS max_spendable_mci FROM headers_commission_outputs", function(rows){
				max_spendable_mci = rows[0].max_spendable_mci;
				cb();
			});
		}
	], onDone);
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
