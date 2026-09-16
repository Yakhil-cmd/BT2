## Vulnerability Analog Found

### Title
Per-recipient rounding of `earned_headers_commission_share` in headers-commission distribution can inflate total bytes paid out - ([File: headers_commission.js])

### Summary
`headers_commission.js` splits a parent unit's `headers_commission` among multiple `earned_headers_commission_recipients` by independently rounding each recipient's share with `Math.round`, instead of rounding down and assigning the remainder to a single recipient (or otherwise guaranteeing the split sums to the exact total). Because rounding is applied per-recipient rather than being constrained to preserve the total, the sum of rounded outputs can exceed the actual commission amount available, analogous to the reported issue where a liability estimate should be rounded conservatively (up for liabilities / down for payouts) rather than rounded independently per component.

### Finding Description
When a headers commission (`full_amount`) is won by a unit that has multiple authors or a custom `earned_headers_commission_recipients` list, the amount is split per recipient using: [1](#0-0) 

and, in the non-`bFaster` SQL-cross-check path, similarly: [2](#0-1) 

Each recipient's share of `full_amount` is rounded to the nearest integer independently (`Math.round(full_amount * share / 100.0)`), except for the trivial 100%-share case which uses the exact `full_amount`. Because `Math.round` in JavaScript rounds `.5` up, and each recipient's fractional remainder is rounded separately, the sum of all rounded amounts is not guaranteed to equal `full_amount` — it can be strictly greater than `full_amount` (extra bytes “created” from rounding) or strictly less (dust lost).

The set of recipients and their `earned_headers_commission_share` values are attacker-controlled: any multi-authored unit can specify an arbitrary list of recipients whose shares are validated only to sum to exactly 100 (not to avoid rounding drift): [3](#0-2) 

By choosing shares that create favorable rounding (e.g., several recipients each with shares that round `.5` up, such as `50/50` splits or similar fractional combinations), an unprivileged unit poster can cause the sum of rounded `headers_commission_contributions` entries for a won headers commission to exceed the actual `full_amount` (i.e. the payer unit's `headers_commission`), effectively inflating the total bytes paid into `headers_commission_contributions`, which are later spendable as `type='headers_commission'` inputs.

### Impact Explanation
This is a supply-inflation vector: the total bytes distributed via `headers_commission_contributions` can exceed the amount actually collected as headers commission from the payer unit, when an attacker crafts a multi-author unit and a recipient-share list that produces favorable rounding. Although the drift per event is small (bounded by roughly the number of recipients), it is systematically exploitable and repeatable across many won headers-commission events, allowing accumulation of bytes not backed by any real commission — a violation of protocol invariants around commission accounting.

### Likelihood Explanation
Reachable by any unprivileged unit poster: authoring a multi-authored unit with a custom `earned_headers_commission_recipients` list (only constrained to sum to 100 and be sorted by address) is a normal, permitted operation. No special privileges, witness status, or AA access are required — the attacker only needs to also win the headers commission distribution occasionally (a normal DAG event), which is a routine part of protocol operation.

### Recommendation
Do not round each recipient's share independently. Use a rounding method that guarantees the total distributed equals `full_amount` exactly, e.g.:
- Round down (`Math.floor`) each share except the last recipient (sorted deterministically), and assign the remainder (`full_amount - sum_of_floored_shares`) to that last recipient, or
- Use the "largest remainder" method to distribute the leftover units deterministically to the recipients with the largest fractional remainders.

This mirrors the report's guidance of using a safe/conservative rounding rule (i.e., never rounding in a way that can exceed the true total) rather than independently rounding each share, which can systematically over- or under-allocate value.

### Proof of Concept
1. Attacker creates a multi-authored unit `U` with `earned_headers_commission_recipients = [{address: A, earned_headers_commission_share: 50}, {address: B, earned_headers_commission_share: 50}]` — valid per `validateHeadersCommissionRecipients` since shares sum to 100.
2. `U` wins a headers commission with `full_amount` such that `full_amount * 0.5` ends in `.5` (e.g., `full_amount = 3`, giving `1.5` per recipient).
3. In `calcHeadersCommissions`, each recipient's amount is computed as `Math.round(3 * 50 / 100.0)` = `Math.round(1.5)` = `2` for both `A` and `B`.
4. Total inserted into `headers_commission_contributions` = `2 + 2 = 4`, exceeding the actual `full_amount` of `3` — a net inflation of `1` byte per occurrence, repeatable across many won headers-commission events authored by the attacker.

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

**File:** headers_commission.js (L193-206)
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
