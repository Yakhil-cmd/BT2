## Precision-Loss Analog Found: Headers-Commission Redistribution Rounding [1](#0-0) 

### Title
Independent Per-Recipient Rounding in Headers-Commission Redistribution Allows Byte Supply Inflation - (File: `headers_commission.js`)

### Summary
The external report describes precision loss from independently rounding down accumulator shares of a divided total. `ocore` has the same bug class in `calcHeadersCommissions()`, but in the opposite (and more dangerous) direction: each recipient's headers-commission share is rounded independently with `Math.round`, and the individually-rounded amounts are never reconciled against the original `full_amount`. When a unit's authors split their earned commission with a 50/50-style share, rounding can make the sum of the parts *exceed* the whole, minting bytes that were never actually paid as a fee.

### Finding Description
When a unit is credited with headers commission and it has `earned_headers_commission_recipients`, the payout to each recipient is computed independently: [2](#0-1) 

and again in the SQL/RAM cross-check path: [3](#0-2) 

`Math.round(full_amount * share / 100.0)` is evaluated separately per `address`. Validation only guarantees that the *shares* (percentages) sum to exactly 100: [4](#0-3) 

It never validates that the resulting *rounded amounts* sum back to `full_amount`. Since JavaScript's `Math.round` rounds `x.5` toward positive infinity, an author can choose two recipient addresses with shares `50`/`50`. Whenever `full_amount` (the parent unit's `headers_commission`, an integer number of bytes) is odd, `full_amount/2` has a `.5` fractional part, and *both* halves round up, so:

```
round(full_amount*50/100) + round(full_amount*50/100) = full_amount + 1
```

The extra unit is not phantom bookkeeping — it flows directly into `headers_commission_contributions` and then into `headers_commission_outputs`: [5](#0-4) 

`headers_commission_outputs` rows are directly spendable as `headers_commission`-type inputs in later payments (validated via `mc_outputs.calcEarnings`, which just sums `headers_commission_outputs.amount` for the claimed MCI range): [6](#0-5) [7](#0-6) 

and this table is explicitly counted as part of total network byte supply: [8](#0-7) 

### Impact Explanation
This is a supply-inflation bug: `headers_commission_outputs` amounts are spendable base-asset inputs and are counted in `total_amount`/`circulating_amount` of the byte supply (`balances.js:readAllUnspentOutputs`). Any attacker who authors a multi-authored unit that wins headers commission from a parent with an odd `headers_commission` fee, and sets `earned_headers_commission_recipients` to a 50/50 split between two addresses they control, mints one extra byte per occurrence beyond what the network actually collected as fees. This can be repeated indefinitely across the many units such an attacker authors over time, since headers commission is won routinely by ordinary unit authors (it's the standard witnessing/headers-fee mechanism), giving an unbounded, cost-free accumulation path.

### Likelihood Explanation
Any unpriviledged unit author with more than one author on their unit (a normal, permitted configuration) can set `earned_headers_commission_recipients` freely as long as the shares sum to 100 — this passes `validateHeadersCommissionRecipients` unmodified. Odd-valued `headers_commission` fees occur naturally (fee is a function of header byte size), so roughly half the qualifying commission wins let the attacker realize the +1 inflation deterministically by choosing the 50/50 split. No other party's cooperation, timing, or malicious infrastructure is required — repeatable at will by posting ordinary units.

### Recommendation
When distributing `full_amount` across `earned_headers_commission_recipients`, round all-but-the-last recipient normally and assign the last recipient `full_amount - sum(previous_rounded_amounts)` (or otherwise track and correct the residual) so the sum of distributed amounts is always exactly `full_amount`, mirroring the fix pattern from the reported bottle-module patch of scaling/normalizing before dividing.

### Proof of Concept
1. Author address `A` creates a 2-author unit with author `B`, setting `earned_headers_commission_recipients = [{address: A, earned_headers_commission_share: 50}, {address: B, earned_headers_commission_share: 50}]`.
2. This unit becomes the "winning child" (per `getWinnerInfo`) of a parent unit whose `headers_commission` is odd (e.g., 101 bytes) — attacker can simply try repeatedly since headers_commission size varies with header content/size and wins are randomly assigned by hash tie-break, guaranteeing eventual odd-fee wins.
3. `calcHeadersCommissions()` computes `Math.round(101*50/100)=51` for `A` and `51` for `B`, total `102` inserted into `headers_commission_contributions`/`headers_commission_outputs`, one byte more than the `101` actually collected.
4. `A` and `B` later spend their `headers_commission_outputs` as `headers_commission` inputs in ordinary payments; validation (`validation.js:2588-2599`) accepts them because it merely re-sums the (already-inflated) `headers_commission_outputs` table.

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

**File:** balances.js (L162-200)
```javascript
function readAllUnspentOutputs(exclude_from_circulation, handleSupply) {
	if (!exclude_from_circulation)
		exclude_from_circulation = [];
	var supply = {
		addresses: 0,
		txouts: 0,
		total_amount: 0,
		circulating_txouts: 0,
		circulating_amount: 0,
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
			}
			handleSupply(supply);
		});
```
