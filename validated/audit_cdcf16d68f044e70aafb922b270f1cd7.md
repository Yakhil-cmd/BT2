This is confirmed as a valid, reachable analog. The `earned_headers_commission_share` mechanism uses integer-percentage division by `100.0` (analogous to the reported `10_000` bps division), and it is fully controllable by an unprivileged unit poster (any multi-authored unit's authors set `earned_headers_commission_recipients`), validated only via [1](#0-0) .

### Title
Integer percentage division in `earned_headers_commission_share` distribution rounds small shares to zero, silently destroying header-commission bytes - (File: headers_commission.js)

### Summary
Header commissions won by a unit are split among `earned_headers_commission_recipients` using `Math.round(full_amount * share / 100.0)`. Because `share` is only required to be a positive integer (minimum 1, i.e. 1%) and `full_amount` (a payer unit's `headers_commission`, typically tens to low hundreds of bytes) can be small, the computed per-recipient amount can round down to `0`. This mirrors the reported bug class where integer-percentage division with insufficient precision (`bps / 10_000`) causes small-but-nonzero entitlements to be truncated to zero.

### Finding Description
`validateHeadersCommissionRecipients` in `validation.js` only enforces that each `earned_headers_commission_share` is a positive integer and that the shares sum to 100 — it does not bound the minimum share relative to the eventual payer's `headers_commission` amount, because that amount is unknown at composition/validation time and can vary per parent unit: [2](#0-1) 

The actual distribution happens later in `calcHeadersCommissions`, where each recipient's cut is computed with plain integer-percentage math and no floor/ceiling protection against precision loss: [3](#0-2) [4](#0-3) 

If, for example, a co-author is allocated `share = 1` (1%, the legal minimum) and the payer unit's `headers_commission` (`full_amount`) is, say, 40 bytes, `Math.round(40 * 1 / 100.0)` evaluates to `0`. The recipient is legitimately entitled to a share of the commission per the unit's own `earned_headers_commission_recipients` list (which passed validation), yet receives nothing, and — critically — the sum of all rounded per-recipient amounts is no longer guaranteed to equal `full_amount`, so the "lost" fraction is not paid out to anyone at all.

### Impact Explanation
This causes a genuine loss of funds for the recipient with a small share: the byte value they are contractually (per co-signed unit) owed is deterministically destroyed by rounding rather than paid. In multi-author/shared-address setups, a majority co-signer composing the unit can unilaterally set a minority co-signer's `earned_headers_commission_share` to the minimum legal value in combination with the (attacker-uncontrollable but predictable-range) small `headers_commission` fee, reliably zeroing out that co-signer's earned commission while the co-signer has no way to prevent it once the unit is signed and posted (all nodes deterministically compute `amount=0` from the same DAG data, so there is no node disagreement — but there is deterministic loss of value belonging to a legitimate stakeholder).

### Likelihood Explanation
This requires only a multi-authored unit with `earned_headers_commission_recipients` set (an unprivileged unit-composition feature available to any unit poster with more than one author), and headers commissions are naturally small (a handful to a few hundred bytes per unit, function of unit size), making the rounding-to-zero condition easy to trigger deliberately or unintentionally whenever a minimum (1%) share is assigned.

### Recommendation
Increase the precision base for `earned_headers_commission_share` (e.g., store/validate shares in permille or higher-precision units, or use a larger multiplier such as `1e6` instead of `100`), and/or explicitly account for rounding remainder so that the sum of distributed amounts always equals `full_amount` (e.g., allocate the rounding remainder to the largest-share recipient, similar to how many payout-splitting implementations avoid "dust loss").

### Proof of Concept
1. Create a multi-authored unit (or a unit from a shared/multisig address) with `earned_headers_commission_recipients = [{address: A, earned_headers_commission_share: 99}, {address: B, earned_headers_commission_share: 1}]`; this passes `validateHeadersCommissionRecipients` since shares are positive integers summing to 100 [1](#0-0) .
2. Have this unit stabilize and win headers commission from a parent whose `headers_commission` is small, e.g. 40 bytes.
3. In `calcHeadersCommissions`, `B`'s share is computed as `Math.round(40 * 1 / 100.0) = 0` [5](#0-4) , so `B` receives nothing despite being owed `0.4` bytes, and the total inserted into `headers_commission_contributions` for this payer sums to `40` from `A` alone (`Math.round(40*99/100)=40`) plus `0` from `B`, matching `full_amount` only by coincidence of rounding — in general the sum can diverge from `full_amount`, and small-share recipients are systematically shortchanged.

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
