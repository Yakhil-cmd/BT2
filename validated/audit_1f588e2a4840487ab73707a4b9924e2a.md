### Title
Rounding dust loss in headers-commission distribution among multiple recipients — permanently unrecoverable ([File: headers_commission.js])

### Summary
The Kairos report describes value being permanently locked because a fractional-share distribution (`RayMath`) is rounded per-recipient, and the sum of the rounded shares no longer equals the actual pooled amount, with no mechanism to recover the difference. `headers_commission.js` in ocore has the same structural flaw: when a stable unit's headers commission is shared among several `earned_headers_commission_recipients`, each recipient's payout is independently rounded, and the rounded amounts are not reconciled against the actual commission collected from the payer unit.

### Finding Description
Any unprivileged unit poster can author a unit with more than one author and attach an `earned_headers_commission_recipients` array, which is only required to sum to exactly 100 (percentage points), enforced in `validateHeadersCommissionRecipients` [1](#0-0) .

When such a unit later wins headers commission from a parent unit, `calcHeadersCommissions` computes each recipient's payout independently as `Math.round(full_amount * share / 100.0)` and inserts these amounts as separate `headers_commission_contributions` rows, one per recipient address [2](#0-1) . The MySQL code path performs the identical per-row `ROUND(punits.headers_commission*earned_headers_commission_share/100.0)` computation [3](#0-2) , and the sqlite code path repeats the same rounding again when merging contributions from multiple parent units [4](#0-3) .

Because rounding is applied per recipient rather than to the pooled total, the sum of the individually rounded amounts can differ from `full_amount` (the actual headers commission earned from the payer unit). Only when a single recipient holds 100% of the share is the exact `full_amount` preserved without rounding [5](#0-4) ; for any split among 2+ addresses, the classic "sum of roundings ≠ rounding of sum" discrepancy applies. Each `headers_commission_contributions`/`headers_commission_outputs` row becomes the exact, final spendable amount for that address — there is no leftover-collecting mechanism, no adjustment applied to the last recipient, and no later step that redistributes or reclaims any shortfall or excess.

### Impact Explanation
When the rounded amounts sum to less than the true collected commission, that difference in bytes is never credited to any address and can never be spent by anyone — it is permanently and silently removed from circulation, mirroring the "excess assets locked and cannot be withdrawn" pattern in the source report. Conversely, when rounding biases upward (e.g., an attacker deliberately choosing many small equal shares, such as several 100/n%, n>2 splits among self-controlled addresses to maximize `.5`-rounding gains), the total credited across recipients can exceed the actual commission the payer unit generated, creating bytes that were never actually paid as commission — a supply-accounting mismatch. Both directions violate the invariant that "total headers commission paid out" should equal "total headers commission collected," which is a protocol-level value-conservation bug, not merely a user-facing UX issue.

### Likelihood Explanation
Any user can trivially construct a multi-authored unit and freely choose the recipient share breakdown (subject only to the sum being 100), so triggering the rounding discrepancy requires no special privilege — just composing a unit with `earned_headers_commission_recipients` split among 2 or more addresses (which `composer.js` already supports by default for multi-authored units) [6](#0-5) . Actually winning the headers-commission "lottery" for a given parent unit is probabilistic (decided by a SHA1-based tie-break among candidate children, `getWinnerInfo`) [7](#0-6) , so an attacker cannot deterministically choose which unit wins on a given attempt, but the magnitude of dust per occurrence is bounded by the commission size and number of recipients, and can accumulate over time across the network as more multi-author units are posted.

### Recommendation
Compute recipient shares using a remainder-aware allocation instead of independent rounding: round all recipients except the last using the standard method, then assign the last recipient `full_amount - sum(previous roundings)` so the total always reconciles exactly to `full_amount`. Apply this both in the sqlite JS path (`headers_commission.js` lines 178-188 and 193-206) and in the MySQL SQL computation (lines 49-51), ensuring both storage backends produce identical, exactly-reconciled totals.

### Proof of Concept
1. Post a unit `U` authored by 2 addresses `A` and `B` (attacker-controlled), with `earned_headers_commission_recipients = [{address:A, earned_headers_commission_share:50}, {address:B, earned_headers_commission_share:50}]` (valid per `validateHeadersCommissionRecipients`, sums to 100).
2. Ensure `U` (or a unit chained appropriately) wins headers commission with an odd `full_amount`, e.g., `headers_commission = 3` from its payer parent unit.
3. `calcHeadersCommissions` computes `Math.round(3*50/100.0) = Math.round(1.5) = 2` for both `A` and `B`, crediting a total of `4` bytes into `headers_commission_outputs`, one more than the `3` bytes actually collected — an inflationary discrepancy, or with different share/amount combinations a deflationary one where the sum is `<3`, permanently discarding the shortfall since no other code path reclaims or redistributes it [2](#0-1) .

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

**File:** headers_commission.js (L49-51)
```javascript
					UNION ALL \n\
					SELECT punits.unit, earned_headers_commission_recipients.address, \n\
						ROUND(punits.headers_commission*earned_headers_commission_share/100.0) AS hc \n\
```

**File:** headers_commission.js (L178-188)
```javascript
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

**File:** headers_commission.js (L249-259)
```javascript
function getWinnerInfo(arrChildren){
	if (arrChildren.length === 1)
		return arrChildren[0];
	if (arrChildren.length === 0)
		throw Error("no children for hc");
	arrChildren.forEach(function(child){
		child.hash = crypto.createHash("sha1").update(child.child_unit + child.next_mc_unit, "utf8").digest("hex");
	});
	arrChildren.sort(function(a, b){ return ((a.hash < b.hash) ? -1 : 1); });
	return arrChildren[0];
}
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
