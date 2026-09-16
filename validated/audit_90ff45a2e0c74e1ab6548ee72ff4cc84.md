### Title
Rounding-up in headers-commission split among `earned_headers_commission_recipients` causes token supply inflation - (File: headers_commission.js)

### Summary
When a unit that wins headers commission designates multiple `earned_headers_commission_recipients` with percentage shares, the payout to each recipient is computed independently with `Math.round()`. Because `Math.round()` is applied per-recipient instead of distributing the remainder deterministically, the sum of the rounded shares can exceed the original `headers_commission` amount that was actually paid by the parent (payer) unit. Any unit author can freely set `earned_headers_commission_recipients` and their `%` shares when posting a unit, so this rounding surplus is directly reachable by an unprivileged unit poster and, if repeated at scale, mints extra spendable bytes that were never actually paid into the system — an analog of the Trail-of-Bits "rounding errors may cause the module to incur losses" finding, but here it inflates the payee side instead of shrinking the payer's debt.

### Finding Description
The headers-commission distribution logic splits a single `full_amount` (`headers_commission` won by a unit) across one or more recipient addresses using their configured share: [1](#0-0) 

and the equivalent MySQL/DB-aggregated path: [2](#0-1) 

as well as the raw SQL form used for the fast-path calculation: [3](#0-2) 

Each recipient's payout is `Math.round(full_amount * share / 100.0)`, computed independently per address. Standard rounding does not guarantee that `Σ Math.round(full_amount * share_i / 100) == full_amount`. With JavaScript's `Math.round` (round-half-up), it is trivial to construct shares/amounts where the sum of the rounded parts exceeds `full_amount` — every recipient can simultaneously round *up*.

The resulting values are inserted straight into `headers_commission_contributions` and subsequently aggregated into `headers_commission_outputs`, which are directly spendable outputs: [4](#0-3) 

There is no reconciliation step that checks `SUM(amount) == full_amount` and corrects the last recipient (as is standard practice to avoid rounding drift), so the surplus is a permanent, real increase in the total spendable headers-commission outputs versus what was actually paid by the payer unit (whose `headers_commission` deduction from its own balance is fixed and unaffected by how it is redistributed).

The same unguarded per-recipient rounding pattern is used for payload (witnessing) commission splits among multiple paid witnesses of a unit: [5](#0-4) [6](#0-5) 

both of which are also directly influenced by attacker-controlled data (`payload_commission` combined with the size of `unit_authors`/witness overlap that the attacker's unit produces).

### Impact Explanation
This is a supply-inflation bug: the sum of `headers_commission_outputs`/`witnessing_outputs` amounts that become spendable can exceed the amount that was actually debited from payer units as `headers_commission`/`payload_commission`. Because commission outputs are ordinary spendable balances once mature, an attacker who repeatedly engineers units with multiple `earned_headers_commission_recipients` (addresses under their own control) whose rounded shares round up can extract more bytes than were ever paid into the commission pool. Repeated at scale (as in the referenced report's "Exploit Scenario 2"), each individual rounding gain is small, but accumulated over many crafted units it results in a systemic, unauthorized net increase of the byte supply available to the attacker, at the expense of correctness of network-wide commission accounting.

### Likelihood Explanation
Setting `earned_headers_commission_recipients` with arbitrary shares (validated only to be well-formed / sum to 100 in `validation.js`) is a normal, permission-less unit field available to any unit author; no special role (witness, hub, OP) is required. Constructing a `headers_commission` value and a recipient-share split that rounds up (e.g., an odd `full_amount` split 50/50 between two attacker-controlled addresses: `Math.round(3*0.5)=2` for each of two recipients, total 4 > 3) is straightforward and fully within an ordinary user's control. The main friction is that headers commission amounts depend on the size in bytes of the parent unit and are not perfectly attacker-chosen, but an attacker can post many candidate units and simply keep the crafted units whose resulting `headers_commission` value happens to produce a favorable (rounds-up) split, repeating the process to accumulate systemic gain over time.

### Recommendation
- Do not round each recipient's share independently. Instead, round only `n-1` recipients and assign the remainder (`full_amount - Σ rounded_(n-1)`) to the last recipient, guaranteeing `Σ amounts == full_amount` exactly.
- Alternatively, always round in favor of the network/module rather than the recipient (i.e., floor all shares, and only pay out the exact deducted `full_amount`, discarding/burning any leftover remainder instead of allowing it to be exceeded).
- Apply the identical fix to the `paid_witnessing.js` per-witness commission split (`Math.round(objUnit.payload_commission / countPaidWitnesses[v.unit])`) and to the SQL-equivalent `ROUND()` expressions in `headers_commission.js`, to keep the RAM-path and DB-path consistent.
- Add an invariant check/test (mirroring the Trail-of-Bits recommendation for fuzz testing) asserting that the sum of amounts inserted into `headers_commission_outputs`/`witnessing_outputs` for a given payer/unit never exceeds the corresponding `headers_commission`/`payload_commission` value.

### Proof of Concept
1. Attacker crafts (or waits for) a headers-commission-winning child unit whose payer unit's `headers_commission` resolves to an odd value, e.g. `full_amount = 3`.
2. The winning child unit sets `earned_headers_commission_recipients` to two attacker-controlled addresses, each with `earned_headers_commission_share = 50`.
3. In `headers_commission.js`, for each address: `amount = Math.round(3 * 50 / 100.0) = Math.round(1.5) = 2`.
4. Total inserted into `headers_commission_contributions` for this payer unit = `2 + 2 = 4`, which is `1` unit greater than the actual `full_amount = 3` that was ever deducted from the payer.
5. This surplus flows into `headers_commission_outputs` and becomes spendable by the attacker's addresses.
6. Repeating steps 1–5 across many crafted units (each yielding a small surplus) allows the attacker to accumulate a net token-supply inflation over time, analogous to the referenced report's cumulative "many small roundings drain the module" exploit scenario.

### Citations

**File:** headers_commission.js (L49-51)
```javascript
					UNION ALL \n\
					SELECT punits.unit, earned_headers_commission_recipients.address, \n\
						ROUND(punits.headers_commission*earned_headers_commission_share/100.0) AS hc \n\
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

**File:** headers_commission.js (L196-206)
```javascript
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

**File:** headers_commission.js (L222-227)
```javascript
			conn.query(
				"INSERT INTO headers_commission_outputs (main_chain_index, address, amount) \n\
				SELECT main_chain_index, address, SUM(amount) FROM units CROSS JOIN headers_commission_contributions USING(unit) \n\
				WHERE main_chain_index>? \n\
				GROUP BY main_chain_index, address",
				[since_mc_index],
```

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
