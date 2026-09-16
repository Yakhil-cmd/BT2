### Title
Header-commission profit-split rounding allows an unprivileged unit author to mint extra bytes (supply inflation) - ([File: headers_commission.js])

### Summary
When a unit's parent's headers commission is split among multiple `earned_headers_commission_recipients`, each recipient's share is independently rounded with `Math.round()`. Because the individual roundings are not reconciled against the total commission actually paid by the parent unit, an attacker who controls the recipient list can choose share percentages that make the sum of the rounded amounts exceed the true `headers_commission` of the payer unit, creating bytes that were never paid into `headers_commission_outputs`. This mirrors the Huma Finance incident, where a logic flaw in fee-accounting let more value be withdrawn from an accumulated fee pool than was legitimately owed.

### Finding Description
`calcHeadersCommissions()` computes, for each winning child unit, the `full_amount` of headers commission it won from a parent unit, then distributes it to one or more recipients declared in `earned_headers_commission_recipients`: [1](#0-0) 

Each recipient's payout is `Math.round(full_amount * share / 100.0)`, computed independently per address with no correction to make the sum equal `full_amount`. The same independent-rounding pattern is used in the MySQL/non-`bFaster` code path: [2](#0-1) 

These per-address amounts are inserted directly into `headers_commission_contributions`, and subsequently aggregated into the spendable `headers_commission_outputs` table: [3](#0-2) 

The only validation applied to `earned_headers_commission_recipients` is that the declared shares sum to exactly 100 (a percentage constraint), not that the rounded output amounts sum to the actual paid amount: [4](#0-3) 

Because `Math.round` in JavaScript rounds `.5` up, splitting a commission with an odd `full_amount` between two (or more) equal-share recipients (e.g. 50/50) causes each half to round up, so `round(full_amount/2) + round(full_amount/2) = full_amount + 1` whenever `full_amount` is odd. The recipient list, and hence the exploitable split, is entirely author-controlled at unit-posting time and stored verbatim via `writer.js`: [5](#0-4) 

Since `headers_commission` is deterministic from the parent's serialized header size (`objectLength.getHeadersSize`), and a single-authored or low-traffic child unit routinely becomes the sole/winning child of its parent (`getWinnerInfo`), an ordinary wallet author can reliably select parents with an odd `headers_commission` and repeatedly harvest the 1-byte rounding surplus across many recipients/units.

### Impact Explanation
Every triggered rounding-up event mints bytes into `headers_commission_outputs` that were never actually collected from a payer unit's `headers_commission` deduction. This is an unbacked issuance of the base currency — a supply-inflation bug. While the per-event gain is small (bounded by the number of recipients minus one, typically 1 byte), it is repeatable at will by posting ordinary units and costs the attacker only normal network fees, so it can be automated and scaled over time, degrading protocol currency-supply integrity, exactly analogous to the Huma Finance case where a fee-accounting logic flaw let more be withdrawn than was legitimately accrued.

### Likelihood Explanation
High from a mechanics standpoint: any unprivileged wallet can set `earned_headers_commission_recipients` on its own units (required only to sum to 100), can choose 50/50 splits between two addresses it controls, and can reliably become the sole/winning child of its own or ordinary parent units in normal usage — no special network conditions, witnessing majority, or privileged role is required.

### Recommendation
When distributing `full_amount` across multiple recipients, avoid independent per-recipient rounding. Instead, compute rounded amounts sequentially while tracking the remaining unallocated amount (e.g., give the last recipient `full_amount - sum(previous roundings)` instead of an independently rounded share), guaranteeing the total distributed exactly equals `full_amount`. Apply the same fix to the parallel SQL/RAM reconciliation path.

### Proof of Concept
1. Attacker controls addresses A and B.
2. Attacker posts a unit as sole child of a parent unit whose `headers_commission` (an odd number, e.g. 343) is being contested; being the only qualifying child guarantees it wins via `getWinnerInfo`.
3. The winning child unit declares `earned_headers_commission_recipients = [{address: A, earned_headers_commission_share: 50}, {address: B, earned_headers_commission_share: 50}]` (passes `validateHeadersCommissionRecipients` since shares sum to 100).
4. During `calcHeadersCommissions`, `full_amount = 343`; A gets `Math.round(343*50/100) = Math.round(171.5) = 172`; B gets the same `172`. Total distributed = 344, one byte more than the 343 actually owed.
5. Repeating this across many units/parents accumulates unbacked byte issuance into `headers_commission_outputs`, which the attacker can later spend via ordinary `headers_commission` payment inputs (validated in `validation.js` `validatePaymentInputsAndOutputs`, `mc_outputs.calcEarnings`).

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

**File:** headers_commission.js (L193-210)
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

**File:** writer.js (L290-295)
```javascript
		if ("earned_headers_commission_recipients" in objUnit){
			for (var i=0; i<objUnit.earned_headers_commission_recipients.length; i++){
				var recipient = objUnit.earned_headers_commission_recipients[i];
				conn.addQuery(arrQueries, 
					"INSERT INTO earned_headers_commission_recipients (unit, address, earned_headers_commission_share) VALUES(?,?,?)", 
					[objUnit.unit, recipient.address, recipient.earned_headers_commission_share]);
```
