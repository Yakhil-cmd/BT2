### Title
Independent per-recipient rounding in commission distribution can mint bytes that were never collected as fees - (File: paid_witnessing.js / headers_commission.js)

### Summary
This is the same bug class as the Panoptic finding: computing a shared pool's per-owner share by rounding each share independently (`ROUND(total * share_i)`), instead of deriving shares from one consistent, order-independent computation, can make `Σ shares_i > total`. In `ocore`, `payload_commission` and `headers_commission` of a stable unit are a fixed, already-collected fee that must be redistributed to the witnesses/authors entitled to it. Both distribution paths round each recipient's amount independently, so the sum handed out can exceed the fee actually collected from the payer unit.

### Finding Description
In `paid_witnessing.js`, `buildPaidWitnessesForMainChainIndex` distributes a unit's `payload_commission` among the witnesses who "won" it by rounding the *same* per-witness quotient independently for every witness: [1](#0-0) 

and the equivalent SQL path does the same with `ROUND(1.0*payload_commission/count_paid_witnesses)`: [2](#0-1) 

Because `Math.round(payload_commission / count_paid_witnesses)` is computed once and then multiplied by `count_paid_witnesses` (each witness gets the *same* rounded value), whenever the true quotient has a fractional part ≥ 0.5, every one of the `count_paid_witnesses` witnesses receives the rounded-up amount, and the total paid out (`count_paid_witnesses * rounded_amount`) exceeds `payload_commission`. For example `payload_commission = 100`, `count_paid_witnesses = 6` → `100/6 = 16.667` → rounds to `17` → total distributed `= 102`, i.e. 2 bytes more than were actually collected as commission on that unit.

The analogous pattern exists in `headers_commission.js`, where each `earned_headers_commission_recipients` entry's share of `full_amount` is rounded independently: [3](#0-2) [4](#0-3) 

Here `full_amount` (the actual headers commission collected from the payer unit) is split among multiple recipients whose `earned_headers_commission_share` values are validated to sum to exactly 100: [5](#0-4) 

but that 100% invariant is enforced only on the *shares*, not on the *rounded amounts* derived from them. `Σ Math.round(full_amount * share_i / 100)` is not guaranteed to equal `full_amount` — this is exactly the `[A] - [B]` vs `A - B` rounding-order fallacy from the Panoptic report, applied to a "split total into N shares" instead of "difference of two fee-growth snapshots," but the root cause (rounding applied per-piece rather than to the whole before splitting) is identical.

The resulting `headers_commission_outputs` / `witnessing_outputs` amounts are inserted directly into spendable-output tables with no cross-check against the actual fee reserved by the payer unit's size/commission fields: [6](#0-5) 

so any rounding surplus becomes new, unbacked spendable bytes.

### Impact Explanation
`payload_commission` and `headers_commission` represent bytes that were reserved/paid by the unit's author when the unit was composed (deducted from the author's balance as a network fee). Witnesses and authors of winning parent units later claim these bytes back through `witnessing_outputs` / `headers_commission_outputs`, which become spendable MC-commission inputs (see `inputs.js` `addHeadersCommissionInputs`/`addWitnessingInputs`, and `validation.js` input validation around lines 2579-2600 using `mc_outputs.calcEarnings` / `paid_witnessing.calcWitnessEarnings`). If the sum of per-recipient rounded shares exceeds the fee actually collected from the payer unit, the excess bytes are created out of thin air and become spendable — a small, deterministic form of unbacked supply inflation reachable simply by any unit being posted and reaching stability with a witness/parent count whose commission does not divide evenly. Because the computation is identical and deterministic on every full node (both the RAM path and the SQL path are cross-checked for *equality with each other*, not for correctness against the collected fee), this does not cause consensus disagreement — it consistently inflates the byte supply network-wide by the same (small) amount per affected unit, which nonetheless breaches the invariant "money paid out to fee recipients ≤ money actually collected as fee."

### Likelihood Explanation
This path executes on essentially every stabilized unit (`calcCommissions` is called from `markMcIndexStable` for every MC index) and requires no special privilege — any ordinary unit poster, once their unit stabilizes and is witnessed by more than ~2 witnesses (for `payload_commission`) or has multiple `earned_headers_commission_recipients` (for `headers_commission`), can trigger the rounding surplus whenever the arithmetic quotient's fractional part is ≥ 0.5. This happens routinely in normal operation, not only under adversarial conditions, making the likelihood of triggering the rounding drift high; the per-instance magnitude is small (a few bytes), matching the "partial loss/gain, dependent on conditions" medium-severity characterization used in the original Panoptic finding.

### Recommendation
Compute a single deterministic split that preserves the total exactly, e.g. round all-but-the-last recipient's share and assign the last recipient `total - Σ(previous rounded shares)`, or use a largest-remainder/Bresenham-style allocation so `Σ amounts == total` by construction, both for `paid_witnessing.js`'s per-witness division and for `headers_commission.js`'s `earned_headers_commission_recipients` distribution.

### Proof of Concept
Given `payload_commission = 100` and `count_paid_witnesses = 6` (a unit witnessed by 6 addresses that were not itself majority-witnessed, or 6 designated witnesses paid equally when nobody witnessed):
- True per-witness share: `100 / 6 = 16.6667`
- `Math.round(16.6667) = 17`
- Total distributed to `witnessing_outputs` across the 6 witnesses: `6 * 17 = 102`
- `102 > 100` → 2 bytes credited to `witnessing_outputs` in excess of the `payload_commission` actually reserved by the unit, per `paid_witnessing.js` lines 156-178.

The same arithmetic pattern applies to `headers_commission.js` lines 179-206 whenever `earned_headers_commission_recipients` shares (summing to 100) produce a rounding-favorable split, e.g. `full_amount = 100`, shares `{34, 33, 33}` → rounded amounts `{34, 33, 33} = 100` (no drift here), but shares `{17,17,17,17,16,16}` type splits or any combination whose fractional remainders each round up in the recipient's favor can push `Σ amount_i` above `full_amount`.

### Citations

**File:** paid_witnessing.js (L156-164)
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
```

**File:** paid_witnessing.js (L170-178)
```javascript
									conn.query(
										"INSERT INTO witnessing_outputs (main_chain_index, address, amount) \n\
										SELECT main_chain_index, address, \n\
											SUM(CASE WHEN sequence='good' THEN ROUND(1.0*payload_commission/count_paid_witnesses) ELSE 0 END) \n\
										FROM balls \n\
										JOIN units USING(unit) \n\
										JOIN paid_witness_events_tmp USING(unit) \n\
										WHERE main_chain_index=? \n\
										GROUP BY address",
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

**File:** headers_commission.js (L199-206)
```javascript
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
