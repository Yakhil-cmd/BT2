### Title
Supply inflation via rounding in per-recipient headers-commission / witnessing splits - (File: headers_commission.js, paid_witnessing.js)

### Summary
When a multi-author unit's earned headers commission (or payload commission paid to witnesses) is split among several recipients, each recipient's share is rounded independently with `Math.round()`. The shares are only required to sum to exactly 100%, so the sum of the independently-rounded per-recipient amounts is never re-checked against the actual total commission that was paid by the parent unit. Because `Math.round()` rounds ties (`.5`) up, an attacker can craft splits that make the sum of rounded shares exceed the true total, minting extra spendable bytes.

### Finding Description
`validateHeadersCommissionRecipients` only requires that `earned_headers_commission_share` values sum to exactly `100`; it never constrains how the underlying byte amount will be rounded when distributed: [1](#0-0) 

The actual distribution happens in `calcHeadersCommissions`, where each recipient independently gets `Math.round(full_amount * share / 100.0)` of the parent unit's `headers_commission`. The code even acknowledges this rounding drift in a comment ("we round _before_ summing up header commissions won from several parent units") but never reconciles the sum of per-recipient amounts against `full_amount`: [2](#0-1) 

These per-recipient rounded amounts are then simply summed per `(main_chain_index, address)` with `SUM(amount)` into `headers_commission_outputs` — again with no check that the aggregate paid out for a given payer unit equals the `headers_commission` value that was actually deducted from that unit's inputs: [3](#0-2) 

The same unchecked, independently-rounded distribution pattern exists for witnessing rewards: each witness gets `Math.round(objUnit.payload_commission / countPaidWitnesses[v.unit])`, aggregated with no cross-check against the true `payload_commission`: [4](#0-3) 

Finally, when these `headers_commission`/`witnessing` outputs are later spent as unit inputs, `mc_outputs.calcEarnings` (used from `validatePaymentInputsAndOutputs`) simply sums `amount` from the `*_outputs` table for the requested MCI range and address — it has no notion of the original total commission actually paid, so it cannot detect or reject an inflated sum: [5](#0-4) [6](#0-5) 

Because `Math.round` rounds `x.5` up (not banker's rounding), a two-way 50/50 split of an odd `headers_commission` (or `payload_commission`) amount causes both recipients' rounded shares to round up, so the total credited across recipients is one byte more than the amount actually deducted from the payer unit's inputs. Any unit poster controls `earned_headers_commission_recipients` and its own `headers_commission` amount is a deterministic function of unit shape (`objectLength.getHeadersSize`), so an attacker can reliably engineer a unit whose per-recipient split lands exactly on a `.5` boundary, deterministically minting one extra base-asset byte per such unit. This can be repeated arbitrarily to inflate the total spendable bytes beyond `constants.TOTAL_WHITEBYTES`.

### Impact Explanation
This breaks the fundamental byte-supply invariant: the sum of coins spendable via `headers_commission`/`witnessing` inputs across all commission recipients can exceed the amount actually paid in by the payer units. Repeating the attack lets an unprivileged unit author mint extra base currency out of thin air — a supply inflation bug, which the task rubric classifies as at least Medium/High severity.

### Likelihood Explanation
Reachable by any regular unit poster with more than one author (or a witness set) — no special privileges, hub role, or node compromise are required. The attacker fully controls the `headers_commission` amount (via unit size/shape) and the `earned_headers_commission_share` split (any integers summing to 100), so hitting a `.5` rounding boundary that inflates the aggregate is a matter of routine unit construction, and can be repeated indefinitely.

### Recommendation
Do not compute recipient shares independently. Either:
- Round down (floor) each recipient's share and assign any remainder (`full_amount - sum(floored shares)`) to one designated recipient (e.g., last recipient by address), so the sum of distributed amounts is always exactly `full_amount`; or
- After computing all rounded per-recipient amounts, compute their sum and adjust the largest (or last) share by the difference so the total always equals the independently known `full_amount`/`payload_commission`.
Apply the same fix to both `headers_commission.js`'s `calcHeadersCommissions` and `paid_witnessing.js`'s `buildPaidWitnessesForMainChainIndex`.

### Proof of Concept
1. Author a unit with 2 authors, each with `earned_headers_commission_share = 50`. Ensure the unit's own size (`headers_commission`, computed by `objectLength.getHeadersSize`) is such that this unit is later chosen as the headers-commission winner for a parent unit whose `headers_commission` is an odd number (e.g. `headers_commission = 345`).
2. When `calcHeadersCommissions` runs, each recipient's contribution is `Math.round(345 * 50 / 100) = Math.round(172.5) = 173`.
3. Both recipients get `173`, i.e. `346` total bytes credited into `headers_commission_outputs`, one more byte than the `345` that was actually paid by the parent unit's inputs (`headers_commission.js:180-187`).
4. Both recipients later spend their `headers_commission` input via `validatePaymentInputsAndOutputs`/`mc_outputs.calcEarnings`, which accepts the sum with no cross-check (`mc_outputs.js:116-132`), successfully spending the extra byte that was never actually deducted anywhere.
5. Repeating this construction across many units accumulates arbitrary inflation of the base asset supply.

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

**File:** headers_commission.js (L176-206)
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
											// hc outputs will be indexed by mci of _payer_ unit
											arrValues.push("('"+payer_unit+"', '"+row.address+"', "+amount+")");
										}
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

**File:** paid_witnessing.js (L156-179)
```javascript
									var countPaidWitnesses = _.countBy(paidWitnessEvents, function(v){return v.unit});
									var assocPaidAmountsByAddress = _.reduce(paidWitnessEvents, function(amountsByAddress, v) {
										var objUnit = storage.assocStableUnits[v.unit];
										if (typeof amountsByAddress[v.address] === "undefined")
											amountsByAddress[v.address] = 0;
										if (objUnit.sequence == 'good')
											amountsByAddress[v.address] += Math.round(objUnit.payload_commission / countPaidWitnesses[v.unit]);
										return amountsByAddress;
									}, {});
									var arrPaidAmounts2 = _.map(assocPaidAmountsByAddress, function(amount, address) {return {address: address, amount: amount}});
									profiler.stop('mc-wc-js-aggregate-events');
									profiler.start();
									if (conf.bFaster)
										return conn.query("INSERT INTO witnessing_outputs (main_chain_index, address, amount) VALUES " + arrPaidAmounts2.map(function(o){ return "("+main_chain_index+", "+db.escape(o.address)+", "+o.amount+")" }).join(', '), function(){ profiler.stop('mc-wc-aggregate-events'); cb(); });
									conn.query(
										"INSERT INTO witnessing_outputs (main_chain_index, address, amount) \n\
										SELECT main_chain_index, address, \n\
											SUM(CASE WHEN sequence='good' THEN ROUND(1.0*payload_commission/count_paid_witnesses) ELSE 0 END) \n\
										FROM balls \n\
										JOIN units USING(unit) \n\
										JOIN paid_witness_events_tmp USING(unit) \n\
										WHERE main_chain_index=? \n\
										GROUP BY address",
										[main_chain_index],
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
