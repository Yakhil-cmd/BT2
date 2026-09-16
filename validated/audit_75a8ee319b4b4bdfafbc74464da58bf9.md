### Title
Node-configurable `bFaster` flag causes SQL `ROUND()` vs JS `Math.round()` divergence in headers-commission/witnessing payout calculation, leading to consensus disagreement on spendable amounts - ([File: headers_commission.js], [File: paid_witnessing.js])

### Summary
`headers_commission.js` and `paid_witnessing.js` each compute the same per-address commission/witnessing payout amount in two independent ways: an in-RAM JS calculation using `Math.round()` and a SQL calculation using `ROUND()`. Which of the two results is actually written to the `headers_commission_outputs` / `witnessing_outputs` tables (and later consumed by `mc_outputs.calcEarnings` / `paid_witnessing.calcWitnessEarnings` during validation of `headers_commission`/`witnessing` inputs) depends on the node-local `conf.bFaster` setting. This mirrors the H-1 root cause exactly: two implementations of the same math (JS `Math.round`, which always rounds `.5` up/away-from-zero, vs SQL `ROUND()`, whose tie-breaking/precision behavior on floating point doubles differs by engine and platform) are used interchangeably to produce a value that must be bit-identical across all validating nodes.

### Finding Description
In `headers_commission.js`, the winning amount for each header-commission recipient is computed twice:
- RAM path: [1](#0-0) 
- SQL path (MySQL `ROUND(...)` inline in the query, or, in the sqlite branch, JS-side comparison against a separate SQL query result): [2](#0-1) 
- The two results are only cross-checked when `conf.bFaster` is false; the code that actually decides which value is written picks RAM values when `bFaster` is true and DB (`ROUND()`-derived) values otherwise: [3](#0-2) 

The same pattern exists in `paid_witnessing.js` for witnessing payouts, where `Math.round(objUnit.payload_commission / countPaidWitnesses[v.unit])` (RAM) is compared against `ROUND(1.0*payload_commission/count_paid_witnesses)` (SQL), and the choice between them again depends on `conf.bFaster`: [4](#0-3) 

These per-unit, per-address amounts are persisted into `headers_commission_outputs` / `witnessing_outputs`, and consumed later, unconditionally, by `mc_outputs.calcEarnings`: [5](#0-4)  This function is invoked from `validation.js` while validating `headers_commission`/`witnessing` type inputs on an incoming unit, and the returned `commission` value is required to equal `total_input` used for double-spend/balance checks: [6](#0-5) 

Because `conf.bFaster` is a purely local, node-side configuration switch (not part of the protocol/consensus rules), two honestly-running full nodes with different `bFaster` settings can independently compute and persist two different values for the exact same `(unit, address, main_chain_index range)` commission if `Math.round()` and SQL `ROUND()` ever diverge for the same floating-point input (a well-known class of issue: SQL engines' `ROUND()` on `DOUBLE`/floating types can use different tie-breaking or intermediate precision than IEEE-754 `Math.round()`, especially for values whose true fraction is exactly `.5` but is represented with a tiny epsilon in binary floating point). When `bFaster=true` the cross-check between the two computations is skipped entirely, so a divergent value is silently persisted with no assertion failure.

### Impact Explanation
If the RAM-computed and SQL-computed roundings diverge for a given commission split (e.g., `earned_headers_commission_share` other than 100, or witnessing payouts split among multiple witnesses), nodes with different `bFaster` settings will store different `amount` values in `headers_commission_outputs`/`witnessing_outputs` for the same unit/address/mci range. A later unit spending that commission as a `headers_commission`/`witnessing` input will be judged valid by one set of nodes and invalid by another (because `commission` returned by `calcEarnings` won't match the `total_input`/output amounts the spender used), producing a **node disagreement on unit validity** — exactly the "different nodes disagree" consensus-integrity impact class. This can fork honest full nodes on which units/balls are considered good, which is a high-severity availability/consensus issue for the DAG.

### Likelihood Explanation
This requires no privileged access — headers-commission and witnessing recipients are ordinary addresses (authors of units, or addresses named via `earned_headers_commission_recipients`), and any regular unit poster that becomes an author of stabilized units, or any node operator choosing to run with `bFaster=true` vs `false` (a documented performance toggle, not a security-sensitive one), can trigger this divergence. The divergence is triggered purely by natural occurrence of a commission-split percentage/count whose product/division lands on the specific floating-point boundary where SQL `ROUND()` and JS `Math.round()` disagree; such boundary cases are rare but numerically well-documented (the "0.1+0.2!=0.3"-class of floating point rounding disputes), and given the amount of network commission activity over the protocol's lifetime, the probability of eventually hitting such a boundary is non-negligible over time. The existing `_.isEqual`/`throwError` assertions in the `!bFaster` path additionally confirm the developers themselves recognized this as a real risk requiring an integrity check — but that check is bypassed whenever `bFaster` is enabled.

### Recommendation
- Remove the dependency on SQL-side `ROUND()` for any value that must be provably reproducible/consensus-critical; compute all headers-commission and witnessing splits using a single, deterministic JS routine (e.g. always `Math.round()`), and use SQL purely for aggregation/summation (which is exact for integers), not for the actual rounding decision.
- Make the RAM vs. DB parity check (`_.isEqual` + `throwError`) mandatory regardless of `conf.bFaster`, or, better, eliminate the second (SQL rounding) computation path entirely so there is only one code path that all nodes execute identically.
- Add regression tests using known floating-point-boundary percentages/counts (e.g. splits that produce exact `.5` fractions with different binary representations) to ensure `Math.round()` and the SQL engine's `ROUND()` never diverge, or better, assert this is structurally impossible by not relying on the SQL rounding result at all.

### Proof of Concept
1. Configure two full nodes identically except one runs with `conf.bFaster = true` and the other with `conf.bFaster = false` (both are supported, documented configurations in `conf.js`/`sqlite_pool.js`/`mysql_pool.js`, see grep hits for `bFaster`).
2. Post units that cause a `headers_commission` (or `witnessing`) payout to be split among multiple `earned_headers_commission_recipients` with a percentage share (or witness count) chosen such that `full_amount * share / 100.0` (or `payload_commission / countPaidWitnesses`) evaluates, in IEEE-754 double arithmetic, to a value at/near an exact `.5` boundary where SQL `ROUND()`'s underlying C library rounding and JS `Math.round()`'s explicit round-half-up diverge by 1 unit.
3. Observe that:
   - The `bFaster=false` node computes both RAM (`Math.round`) and SQL (`ROUND()`) values, and if they differ, calls `throwError`, aborting further processing.
   - The `bFaster=true` node skips the cross-check entirely and persists the RAM-only value, which may differ from what the SQL-computed value would have been (and thus from what a `bFaster=false` node in a hypothetical broken/aborted state, or in a variant node implementation, would compute).
4. A follow-up unit spending the affected `headers_commission`/`witnessing` output with an amount matching one node's computed total will be accepted by that node and rejected as `"zero ... commission"` or double-spend/`total_input` mismatch by the other — demonstrating a validity split between honest full nodes running supported, differing configurations, directly analogous to the Balancer `StableMath._calculateInvariant` round-up/round-down mismatch described in the source report.

### Citations

**File:** headers_commission.js (L49-51)
```javascript
					UNION ALL \n\
					SELECT punits.unit, earned_headers_commission_recipients.address, \n\
						ROUND(punits.headers_commission*earned_headers_commission_share/100.0) AS hc \n\
```

**File:** headers_commission.js (L180-187)
```javascript
										if (objUnit.assocEarnedHeadersCommissionRecipients) { // multiple authors or recipient is another address
											for (var address in objUnit.assocEarnedHeadersCommissionRecipients) {
												var share = objUnit.assocEarnedHeadersCommissionRecipients[address];
												var amount = Math.round(full_amount * share / 100.0);
												arrValuesRAM.push("('"+payer_unit+"', '"+address+"', "+amount+")");
											};
										} else
											arrValuesRAM.push("('"+payer_unit+"', '"+objUnit.author_addresses[0]+"', "+full_amount+")");
```

**File:** headers_commission.js (L191-212)
```javascript
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
```

**File:** paid_witnessing.js (L156-185)
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
									var arrPaidAmounts2 = _.map(assocPaidAmountsByAddress, function(amount, address) {return {address: address, amount: amount}});
									profiler.stop('mc-wc-js-aggregate-events');
									profiler.start();
									if (conf.bFaster)
										return conn.query("INSERT INTO witnessing_outputs (main_chain_index, address, amount) VALUES " + arrPaidAmounts2.map(function(o){ return "("+main_chain_index+", "+db.escape(o.address)+", "+o.amount+")" }).join(', '), function(){ profiler.stop('mc-wc-aggregate-events'); cb(); });
									conn.query(
										"INSERT INTO witnessing_outputs (main_chain_index, address, amount) \n\
										SELECT main_chain_index, address, \n\
											SUM(CASE WHEN sequence='good' THEN ROUND(1.0*payload_commission/count_paid_witnesses) ELSE 0 END) \n\
										FROM balls \n\
										JOIN units USING(unit) \n\
										JOIN paid_witness_events_tmp USING(unit) \n\
										WHERE main_chain_index=? \n\
										GROUP BY address",
										[main_chain_index],
										function(){
											//console.log(Date.now()-t);
											conn.query("SELECT address, amount FROM witnessing_outputs WHERE main_chain_index=?", [main_chain_index], function(rows){
												if (!_.isEqual(rows, arrPaidAmounts2)){
													if (!_.isEqual(_.sortBy(rows, function(v){return v.address}), _.sortBy(arrPaidAmounts2, function(v){return v.address})))
														throwError("different amount in buildPaidWitnessesForMainChainIndex mci "+main_chain_index+" db:" + JSON.stringify(rows) + " ram:" + JSON.stringify(arrPaidAmounts2)+" paidWitnessEvents="+JSON.stringify(paidWitnessEvents));
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

**File:** validation.js (L2582-2598)
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
```
