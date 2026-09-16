## Title
Rounding overshoot in headers-commission distribution among multiple recipients breaks the invariant that redistributed commission equals fee actually paid, permitting supply inflation - (File: headers_commission.js)

### Summary
When a unit's authors declare `earned_headers_commission_recipients` (percentage shares that must sum to exactly 100, enforced in `validateHeadersCommissionRecipients`), the headers-commission earned by that unit is split among the recipients in `calcHeadersCommissions` using independent `Math.round()`/SQL `ROUND()` calls per recipient. Because each recipient's share is rounded independently rather than the remainder being tracked and subtracted, the sum of the rounded amounts can exceed the original `headers_commission` amount that was actually collected as a fee from the payer unit. This is the same root cause as the Allora finding: an amount is distributed to multiple parties based on independently rounded shares, and the sum of distributed shares is not reconciled against the actual pool/fee that funds them, so more value ends up credited to recipients than was ever paid in.

### Finding Description
`headers_commission` is a real fee taken from a unit's inputs (`objUnit.headers_commission = objectLength.getHeadersSize(objUnit)`), enforced during validation so that `total_input === total_output + headers_commission + payload_commission + ...` [1](#0-0) . It is later refunded/distributed to the child units that "won" it and, if multi-authored, further split among named `earned_headers_commission_recipients`, whose shares must sum to exactly 100 [2](#0-1) .

The split is done per recipient independently:
```
var amount = Math.round(full_amount * share / 100.0);
``` [3](#0-2) 
and in the SQL/DB-driven path:
```
var amount = (row.earned_headers_commission_share === 100) 
    ? full_amount 
    : Math.round(full_amount * row.earned_headers_commission_share / 100.0);
``` [4](#0-3) 
and the MySQL query variant:
```
ROUND(punits.headers_commission*earned_headers_commission_share/100.0) AS hc
``` [5](#0-4) 

Each recipient's amount is rounded to the nearest integer independently of the others. Since percentages only need to sum to 100 (not necessarily divide `full_amount` evenly), rounding each share separately can push the sum of the rounded amounts above `full_amount`. For example, with `full_amount = 3` split 50/50 between two recipients: `round(3*50/100) = round(1.5) = 2` for each, giving a total of `4`, one unit more than the `3` that was actually collected from the payer unit.

These amounts are inserted into `headers_commission_contributions` and then aggregated per address into `headers_commission_outputs` [6](#0-5) , which are real spendable balances: they are later consumed as `type: "headers_commission"` inputs in payments, added straight into `total_input` after being computed by `mc_outputs.calcEarnings` [7](#0-6) , and they are counted directly into the network's `total_amount`/`circulating_amount` supply figures [8](#0-7) .

Nothing in `calcHeadersCommissions` reconciles the sum of per-recipient rounded amounts back down to `full_amount`; the rounding overshoot for a given payer unit is simply added to the total money in circulation.

### Impact Explanation
This breaks the invariant "amount distributed to headers-commission recipients == headers_commission fee actually collected from the payer unit," analogous to the Allora finding where "sum of distributed rewards" diverged from the pool balance owed. Here the divergence goes in the inflationary direction: the sum of per-recipient rounded shares can exceed the fee taken from the payer, creating spendable value (headers_commission_outputs, eventually real base-asset outputs) that was never actually paid in by anyone. Any single author can trigger this simply by naming several `earned_headers_commission_recipients` with percentages chosen so independent rounding overshoots (e.g. an odd `headers_commission` split 50/50, or three-way splits like 33/33/34 on amounts not divisible by 3). This is a supply-inflation-class issue reachable by any ordinary unit poster who is a multi-author on a unit that wins headers commission, not requiring any privileged role.

### Likelihood Explanation
Any multi-authored unit can set `earned_headers_commission_recipients` with arbitrary percentages (only constraint: positive integers summing to 100, sorted by address) [9](#0-8) . Whether that unit ends up "winning" headers commission from a parent is determined by the DAG/witness selection logic in `calcHeadersCommissions`/`getWinnerInfo`, which is a normal, frequently occurring condition (any unit that is chosen as the best child of a parent). Triggering rounding overshoot on any one payer/recipient split requires only that the fee amount is not evenly divisible by the declared percentage shares - a trivially achievable condition, repeatable across many units to accumulate meaningful inflation over time.

### Recommendation
Do not round each recipient's share independently. Instead, either:
- Compute all shares with floor/truncation and assign only the remainder (`full_amount - sum(floored shares)`) to one designated recipient (e.g., the last, or the address with largest remainder), or
- Track a running remainder across recipients so that the cumulative sum of distributed amounts never exceeds `full_amount`.

Apply the same fix to the equivalent per-witness rounding path in `paid_witnessing.js` (`Math.round(objUnit.payload_commission / countPaidWitnesses[v.unit])` and the SQL `ROUND(1.0*payload_commission/count_paid_witnesses)`) [10](#0-9) , which has the same independent-rounding-per-recipient pattern and the same risk of the sum exceeding the actual `payload_commission` collected.

### Proof of Concept
1. Compose a multi-authored unit `U` with two authors A and B, and `earned_headers_commission_recipients = [{address: A, earned_headers_commission_share: 50}, {address: B, earned_headers_commission_share: 50}]`.
2. Ensure `U` becomes the "winner" child of a parent unit `P` whose `headers_commission` is an odd number, e.g. `3` (headers_commission depends on header size and is generally attacker-influenceable indirectly, or can be waited for opportunistically).
3. When `calcHeadersCommissions` runs for the MCI in question, it computes `full_amount = 3` and, since there are two recipients with 50% shares each, computes `amount_A = Math.round(3*50/100) = 2` and `amount_B = Math.round(3*50/100) = 2`, inserting both into `headers_commission_contributions` [3](#0-2) .
4. `headers_commission_outputs` for that MCI now sums to `4` for addresses A+B combined, one more than the `3` actually paid as `headers_commission` by `P`'s issuer, i.e., `SUM(amount) FROM units CROSS JOIN headers_commission_contributions USING(unit) GROUP BY main_chain_index, address` [6](#0-5)  yields more spendable value than was collected.
5. A and B can each later spend their `headers_commission` input via a normal payment, and `validatePaymentInputsAndOutputs` will accept `total_input` computed from `calcEarnings` over these outputs without any check that the sum matches the original fee [7](#0-6) , permanently minting the extra unit of value into circulating base-asset supply as tracked by `balances.js` [11](#0-10) .

### Citations

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

**File:** validation.js (L2666-2667)
```javascript
				if (total_input !== total_output + objUnit.headers_commission + objUnit.payload_commission + oversize_fee + tps_fee + burn_fee + vote_count_fee)
					return callback("inputs and outputs do not balance: "+total_input+" !== "+total_output+" + "+objUnit.headers_commission+" + "+objUnit.payload_commission+" + "+oversize_fee+" + "+tps_fee+" + "+burn_fee+" + "+vote_count_fee);
```

**File:** headers_commission.js (L50-51)
```javascript
					SELECT punits.unit, earned_headers_commission_recipients.address, \n\
						ROUND(punits.headers_commission*earned_headers_commission_share/100.0) AS hc \n\
```

**File:** headers_commission.js (L180-185)
```javascript
										if (objUnit.assocEarnedHeadersCommissionRecipients) { // multiple authors or recipient is another address
											for (var address in objUnit.assocEarnedHeadersCommissionRecipients) {
												var share = objUnit.assocEarnedHeadersCommissionRecipients[address];
												var amount = Math.round(full_amount * share / 100.0);
												arrValuesRAM.push("('"+payer_unit+"', '"+address+"', "+amount+")");
											};
```

**File:** headers_commission.js (L199-203)
```javascript
											// note that we round _before_ summing up header commissions won from several parent units
											var amount = (row.earned_headers_commission_share === 100) 
												? full_amount 
												: Math.round(full_amount * row.earned_headers_commission_share / 100.0);
											// hc outputs will be indexed by mci of _payer_ unit
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

**File:** balances.js (L171-197)
```javascript
		headers_commission_amount: 0,
		payload_commission_amount: 0,
	};
	db.query(`SELECT address, COUNT(*) AS count, SUM(amount) AS amount
		FROM outputs
		CROSS JOIN units USING(unit)
		WHERE is_spent=0 AND asset IS NULL AND units.sequence='good'
		GROUP BY address`,
		function (rows) {
		if (rows.length) {
			supply.addresses += rows.length;
			rows.forEach(function(row) {
				supply.txouts += row.count;
				supply.total_amount += row.amount;
				if (!exclude_from_circulation.includes(row.address)) {
					supply.circulating_txouts += row.count;
					supply.circulating_amount += row.amount;
				}
			});
		}
		db.query('SELECT "headers_commission_amount" AS amount_name, SUM(amount) AS amount FROM headers_commission_outputs WHERE is_spent=0 UNION SELECT "payload_commission_amount" AS amount_name, SUM(amount) AS amount FROM witnessing_outputs WHERE is_spent=0;', function(rows) {
			if (rows.length) {
				rows.forEach(function(row) {
					supply.total_amount += row.amount;
					supply.circulating_amount += row.amount;
					supply[row.amount_name] += row.amount;
				});
```

**File:** paid_witnessing.js (L157-173)
```javascript
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
```
