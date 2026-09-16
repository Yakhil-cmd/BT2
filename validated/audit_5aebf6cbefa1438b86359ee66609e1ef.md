### Title
Headers-commission distribution rounds each recipient's share independently, allowing the sum of paid-out commission to exceed the commission actually earned - ([File: headers_commission.js])

### Summary
When a unit with multiple authors specifies `earned_headers_commission_recipients` to split its share of headers commission, `calcHeadersCommissions` computes each recipient's payout independently with `Math.round(full_amount * share / 100.0)` instead of using a remainder-preserving allocation. Because `Math.round` rounds `.5` up, an author can choose recipient share percentages (which must only sum to exactly 100, per validation) such that several recipients each round up simultaneously, making the sum of the individual payouts exceed `full_amount` — the actual commission collected from the payer unit. This is the exact rounding-based over-distribution bug class described in the external report (there it was `mulWadUp` causing outputs to sum above the amount received; here it is per-recipient `Math.round` causing spendable outputs to sum above the amount earned).

### Finding Description
Any unit with more than one author must declare `earned_headers_commission_recipients`, and `validateHeadersCommissionRecipients` only requires that the shares sum to exactly 100: [1](#0-0) 

An attacker fully controls this list (addresses and integer percentages) as long as they sum to 100 — there is no constraint tying the percentages to values that avoid rounding boundaries.

Later, when the commission is actually distributed to those recipients, `calcHeadersCommissions` computes each recipient's payout separately from the full payer amount using `Math.round`, and inserts the independently rounded amounts directly into `headers_commission_contributions`/`headers_commission_outputs`, with no reconciliation against the true `full_amount`: [2](#0-1) 

Because each recipient's share is rounded independently (`Math.round` rounds `.5` up), a set of shares/`full_amount` combinations that hit the `.5` boundary for multiple recipients simultaneously causes `Σ amount_i > full_amount`. For example, with two recipients at 50%/50% and an (attacker-influenced, since headers commission scales with unit/payload size) odd `full_amount` such as 355:
- `Math.round(355 * 50 / 100) = Math.round(177.5) = 178` for each recipient
- `178 + 178 = 356 > 355`

With more recipients hitting `.5` simultaneously (e.g., 4 recipients at 25% each with `full_amount` divisible by 2 but not 4), the inflation ratio grows further (e.g., `full_amount=2` → each recipient rounds `0.5`→`1`, total `4` vs `2`, a 2x inflation).

These over-counted amounts are inserted as real spendable `headers_commission_outputs`: [3](#0-2) 

and are later spendable via `headers_commission` inputs, whose validity is checked purely against the sum stored in this table with no cross-check to what was actually paid by the payer units: [4](#0-3) [5](#0-4) 

### Impact Explanation
This allows an attacker who authors multi-author units (which is unprivileged — anyone can compose a multi-authored unit and set `earned_headers_commission_recipients`) to mint spendable bytes that were never actually paid as headers commission by any payer unit, by choosing recipient addresses/shares under their control that maximize rounding-up overlap. This is a supply-inflation bug: units validate individually with `calcHeadersCommissions` deterministically producing these outputs for every full node, so all nodes agree on the (inflated) spendable amount, and the attacker can later spend the excess bytes as legitimate headers-commission income.

### Likelihood Explanation
Likelihood is high: the attacker needs only to author ordinary multi-authored units with self-controlled recipient addresses and craft integer percentages that sum to 100 and align with the size-derived `headers_commission` values to hit rounding boundaries (e.g., simple 50/50 or 25/25/25/25 splits repeatedly). No special privileges, timing, or race conditions are required, and the mechanism runs automatically as part of normal DAG stabilization/headers-commission calculation.

### Recommendation
Distribute the full amount using a remainder-preserving (largest-remainder / Hamilton) method instead of rounding each recipient's share independently: compute `Math.floor` amounts for each recipient, sum them, and allocate the residual (`full_amount - Σ floor_amounts`) one unit at a time to the recipients with the largest fractional remainders, guaranteeing `Σ amount_i === full_amount` exactly for every distribution.

### Proof of Concept
1. Attacker creates two addresses `A1` and `A2` they control.
2. Attacker composes a multi-authored unit (authored by `A1` and `A2`) with `earned_headers_commission_recipients = [{address: A1, earned_headers_commission_share: 50}, {address: A2, earned_headers_commission_share: 50}]` (passes `validateHeadersCommissionRecipients` since the shares sum to 100).
3. Attacker arranges (via normal unit composition, since `headers_commission` for a payer unit is derived from payload/header size, which the attacker controls by choosing what data/parents to include) for a payer unit whose `headers_commission` awarded to this child unit is an odd number, e.g. `355`.
4. When `calcHeadersCommissions` runs (`headers_commission.js`, lines 176-206), it computes for each of `A1`/`A2`: `Math.round(355 * 50 / 100) = 178`.
5. `headers_commission_outputs` ends up crediting `A1` and `A2` with `178` each — a total of `356` bytes — even though only `355` bytes of commission were actually paid by the payer unit, creating `1` byte out of thin air. Repeating this pattern across many crafted multi-author units accumulates arbitrarily large amounts of unbacked spendable bytes.

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
