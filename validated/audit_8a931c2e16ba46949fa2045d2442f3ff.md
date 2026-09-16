### Title
Rounding error in headers-commission distribution to multiple `earned_headers_commission_recipients` can inflate the byte supply - (File: `headers_commission.js`)

### Summary
`calcHeadersCommissions()` splits a winning unit's headers commission among multiple recipients defined by the unit's `earned_headers_commission_recipients` field, using `Math.round(full_amount * share / 100.0)` for each recipient. Because standard rounding (not floor/truncation) is applied independently to each recipient's share, the sum of the rounded per-recipient amounts can exceed the original `full_amount` when the commission is split across several small shares. This mirrors the Notional/Sherlock finding where independent, unchecked rounding during proportional distribution causes value to be gained or lost relative to the true total.

### Finding Description
Any unit author can set `earned_headers_commission_recipients` on their own unit (composed via `composer.js`, validated in `validation.js`, persisted in `writer.js`, and consumed later in `headers_commission.js`) to split earned headers commissions among several addresses by percentage share.

In `headers_commission.js`, once a unit is determined to be the winner of a headers commission for a payer unit, the amount is distributed to each recipient independently: [1](#0-0) 

and, in the SQL/mysql code path, the same rounding is done per-row rather than validated against the total: [2](#0-1) 

Each recipient's payout is computed as `round(full_amount * share / 100.0)` in isolation. Because JavaScript's `Math.round` (and MySQL's `ROUND`) round each fractional amount independently to the nearest integer, there is no guarantee that `Σ round(full_amount * share_i / 100)` equals `full_amount`. By crafting a unit with many recipients holding small percentage shares (e.g., splitting shares so that each individual amount's fractional part is ≥0.5), an attacker acting as a unit author can cause the sum of rounded payouts to exceed `full_amount`. These payouts are inserted into `headers_commission_contributions` and subsequently aggregated into `headers_commission_outputs`: [3](#0-2) 

These `headers_commission_outputs` rows are later spent as real, unbacked `type: "headers_commission"` inputs, meaning the excess from rounding becomes genuinely spendable currency that was never actually paid in as commission by any payer.

### Impact Explanation
If the aggregate rounding surplus across many split recipients is systematically positive, this results in real byte supply inflation: more currency becomes spendable from `headers_commission_outputs` than was actually collected as headers commission from fee-paying units. This violates the core invariant that money supply is fixed and can only move between addresses, not be created. Because the computation is deterministic and run identically by every full node, this would not directly cause a fork/disagreement, but it is a genuine, quietly-exploitable inflation bug reachable by any ordinary user who authors a unit with an `earned_headers_commission_recipients` list of their choosing.

### Likelihood Explanation
Reachability is low-privilege: any unit author can set `earned_headers_commission_recipients` on units they compose (this is a documented, user-facing feature, not privileged). The magnitude of the exploit per unit is small since headers commissions per unit are limited (bounded by the unit's declared headers-commission fee, typically on the order of a few hundred bytes), and the rounding surplus per split is at most `(n-1)/2` bytes for `n` recipients (bounded further by `MAX_MESSAGES_PER_UNIT`-like practical limits on how many recipients can be listed and by `constants` limits on recipient list size, which I did not fully verify in this session — see caveat below). Exploiting this profitably at scale would require repeatedly authoring winning units with crafted recipient splits over many main-chain indexes, which is possible but rate-limited by unit throughput and how "winning" the headers-commission race is determined (`getWinnerInfo`).

### Recommendation
- Compute per-recipient shares using integer arithmetic that guarantees the sum of distributed amounts never exceeds `full_amount` (e.g., use `Math.floor` for all but the last recipient and assign the remainder — dust — to the last recipient, sorted deterministically).
- Alternatively, validate at unit-validation time (`validation.js`) that, for the maximum possible `full_amount` (the unit's own `headers_commission`), the rounding of the declared shares cannot produce a sum different from `full_amount`, or reject configurations whose rounding is ambiguous.
- Apply the same remainder-allocation fix consistently in both the SQL (`ROUND(...)`) and in-memory (`Math.round(...)`) code paths to keep them equivalent, since the code currently cross-checks them via `_.isEqual` assuming they always match.

### Proof of Concept
1. Attacker authors a unit `U` with multiple authors is not required — a single-author unit can still declare `earned_headers_commission_recipients` splitting the commission among several *different* addresses controlled by the attacker (a valid feature use case documented near `composer.js` line 248-253).
2. Attacker crafts N recipient shares (summing to 100 as required by validation) such that each `full_amount * share_i / 100` has a fractional part ≥ 0.5, e.g. for `full_amount = 3` bytes and shares `[17, 17, 17, 17, 16, 16]` (sum=100): each of the four 17% shares yields `round(3*0.17)=round(0.51)=1`, and each 16% share yields `round(3*0.16)=round(0.48)=0`, total = 4, which is 1 more than `full_amount=3`.
3. Attacker gets this unit to repeatedly win the headers-commission race (`getWinnerInfo`) across many main-chain indices, accumulating the 1-byte-per-win surplus across `headers_commission_outputs`.
4. Attacker later spends these `headers_commission_outputs` as genuine `type: "headers_commission"` inputs, redeeming supply that was never actually paid in by any commission payer.

**Caveat:** I could not fully verify, within the available tool budget, the exact constraints `validation.js` places on the number of `earned_headers_commission_recipients` entries or the granularity/precision of `earned_headers_commission_share` values (e.g., whether shares must be integers, and whether there's a cap on recipient list length). These constraints affect the exact magnitude of exploitable surplus per unit but do not eliminate the rounding-surplus mechanism described above.

### Citations

**File:** headers_commission.js (L50-51)
```javascript
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
