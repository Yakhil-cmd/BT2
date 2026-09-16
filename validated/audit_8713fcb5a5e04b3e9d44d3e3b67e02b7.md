### Title
Rounding error in per-recipient headers-commission split allows byte supply inflation - (File: headers_commission.js)

### Summary
`calcHeadersCommissions` distributes a unit's `headers_commission` (a fixed integer number of bytes taken as a fee from a payer unit) among one or more `earned_headers_commission_recipients`. Each recipient's share is calculated independently using `Math.round(full_amount * share / 100.0)` and validation only guarantees the recipient shares sum to exactly 100 (percent), never that the rounded byte amounts sum to `full_amount`. Because each recipient's payout is rounded independently, the sum of the rounded outputs can exceed the original `full_amount`, creating extra bytes that were never actually paid in as a fee — the same class of bug as the Catalyst rounding issue, except inverted: instead of the payer under-transferring due to truncation, the recipients over-receive due to independent rounding.

### Finding Description
When a unit has multiple authors, `earned_headers_commission_recipients` must be specified and its `earned_headers_commission_share` values must sum to exactly 100, as enforced in [1](#0-0) 

However, when the headers commission is actually calculated and inserted, each recipient's byte amount is computed with independent rounding: [2](#0-1) 

specifically:
```
var amount = Math.round(full_amount * share / 100.0);
```
and the SQL-computed equivalent:
```
var amount = (row.earned_headers_commission_share === 100)
    ? full_amount
    : Math.round(full_amount * row.earned_headers_commission_share / 100.0);
```
There is no step that clamps the last recipient's share to `full_amount - sum(previous rounded shares)` (the standard "largest remainder" technique used to avoid rounding drift). Because `Math.round` rounds each fractional byte independently, and shares are attacker-controlled integers (only constrained to sum to 100), an author can choose share splits (e.g. two recipients with share 50/50, or several recipients each landing exactly on a `.5` byte boundary) such that every individual rounded amount rounds up, causing `Σ amount > full_amount`.

For example, with `full_amount = 3` bytes and two recipients each with `share = 50`:
`Math.round(3 * 50 / 100) = Math.round(1.5) = 2` for each recipient → `2 + 2 = 4` bytes distributed for only 3 bytes actually paid — one extra byte is minted out of nothing per multi-authored unit where the poster controls both recipient addresses (e.g. both being the poster's own addresses, or colluding addresses).

This affects `headers_commission_contributions`/`headers_commission_outputs`, which later become spendable coin inputs via `mc_outputs.calcEarnings` referenced in [3](#0-2) 
i.e. the inflated byte amounts are eventually spendable as real base-asset coins by network participants, meaning the mismatch is not merely bookkeeping — it lets attacker-controlled addresses redeem more bytes than were actually paid into the fee pool.

### Impact Explanation
This is a supply-inflation bug: an unprivileged unit poster who controls (or colludes with) more than one author address can deliberately choose `earned_headers_commission_share` splits that cause rounding to always favor the recipients, minting fractional extra bytes per qualifying multi-authored unit that wins the headers-commission race. While the per-unit gain is small (bounded by roughly `0.5 * (number_of_recipients - 1)` bytes), it is a systemic, repeatable, and directly attacker-controlled inflation of the network's fixed byte supply, which is a core invariant of the ledger. Repeated at scale (many multi-authored units posted over time), this compounds into a measurable, illegitimate increase in circulating base-asset supply, undermining the ledger's total-supply guarantee.

### Likelihood Explanation
Likelihood is high in terms of reachability: any unit poster can trivially author a unit with 2+ authors, specify `earned_headers_commission_recipients` with attacker-chosen shares summing to 100, and repeatedly attempt to win the headers-commission race for parent units (deterministic by SHA1/hash-based winner selection, but the poster can retry over many candidate units). The attacker does not need any special privilege, node compromise, or timing advantage beyond normal unit posting — this matches the "unprivileged unit poster" reachability required by the rules. The magnitude per unit is small, which is the main limiting factor on severity/likelihood of large-scale exploitation, but the bug is deterministic and reproducible on demand.

### Recommendation
Use a remainder-preserving allocation algorithm instead of independent rounding per recipient: compute all recipients' shares with `Math.floor` first, sum them, then distribute the leftover remainder (`full_amount - Σfloor(amount_i)`) one byte at a time to the recipients with the largest fractional remainders (largest-remainder / Hamilton apportionment method), guaranteeing `Σ amount_i === full_amount` exactly. Apply the same fix consistently in both the in-memory (`arrValuesRAM`) and SQL (`profit_distribution_rows`) code paths in `headers_commission.js` so the two computations continue to match.

### Proof of Concept
1. Post a 2-author unit `U` where `earned_headers_commission_recipients` is:
   ```
   [{ address: A, earned_headers_commission_share: 50 }, { address: B, earned_headers_commission_share: 50 }]
   ```
   This passes `validateHeadersCommissionRecipients` since shares sum to 100.
2. Ensure `U` wins the headers-commission race as a child of a parent unit `P` whose `headers_commission` (bytes) is an odd number, e.g. `full_amount = 3` (achievable by controlling unit sizes/parent selection, or simply repeating attempts until a winning odd-`headers_commission` parent is found).
3. When `calcHeadersCommissions` runs for the relevant main-chain index range, in `headers_commission.js`:
   ```
   var amount = Math.round(full_amount * share / 100.0); // Math.round(1.5) = 2, for BOTH A and B
   ```
   Both `A` and `B` receive `2` bytes each — `4` bytes total, while only `3` bytes (`full_amount`) were ever collected as headers commission from the payer unit.
4. These `4` bytes are inserted into `headers_commission_contributions` → aggregated into `headers_commission_outputs`, and later become spendable as real base-asset inputs (via `mc_outputs.calcEarnings`/`headers_commission` input type validated in `validation.js`), letting `A` and `B` (controlled by the same attacker) redeem 1 more byte than was actually paid into the system.

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

**File:** headers_commission.js (L176-216)
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
									if (!_.isEqual(arrValuesRAM.sort(), arrValues.sort())) {
										throwError("different arrValues, db: "+JSON.stringify(arrValues)+", ram: "+JSON.stringify(arrValuesRAM));
									}
								}

								conn.query("INSERT INTO headers_commission_contributions (unit, address, amount) VALUES "+arrValues.join(", "), function(){
									cb();
								});
							}
						);
```
