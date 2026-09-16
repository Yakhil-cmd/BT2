## Title
Headers commission permanently unclaimable when a unit's stable interval has no eligible ("good") children - (File: `headers_commission.js`)

### Summary
`headers_commission.calcHeadersCommissions()` distributes the `headers_commission` fee paid by every "payer" unit to whichever descendant unit (child on the same or next MCI) "wins" the fee. This is directly analogous to the Sherlock M-4 bug: a value (`finalTVL` in the Y2K report, here the pool of eligible winning children) that is expected to always be non-zero is allowed to be zero, and when it is, the funds tied to that period (the payer unit's `headers_commission`) are never credited to anyone and become permanently unspendable — there is no fallback/treasury path.

### Finding Description
For every stable "payer" unit, the code looks for children units (units whose `parent_units` include the payer, with the same or next `main_chain_index`) that are `sequence='good'` to determine who "wins" the headers commission of that payer unit: [1](#0-0) 

If none of the candidate children have `sequence='good'` (i.e., all descendant units in that slot ended up `final-bad`, e.g., due to a resolved double-spend), the code explicitly skips creating any entry for that payer unit:

```
var arrCandidateChildren = arrSameMciChildren.concat(arrNextMciChildren);
if (arrCandidateChildren.length === 0)
    return; // all eligible children are final-bad, nobody gets the hc
```

Because `assocChildrenInfosRAM[parent.unit]` (and its SQL-side counterpart, which is built from the equivalent `JOIN` conditions requiring `+chunits.sequence='good'`) is never populated for this payer unit, that payer's `headers_commission` is never inserted into `headers_commission_contributions`, and consequently never flows into `headers_commission_outputs`: [2](#0-1) [3](#0-2) 

The `headers_commission` field itself was already deducted from the payer's balance when the unit was composed (it is a mandatory network fee, similar to how the Y2K vault's `finalTVL` is fixed once the epoch ends): [4](#0-3) 

Unlike a normal payer unit, whose fee is always won by exactly one descendant, a payer unit whose entire "next-slot" neighborhood turns out to be `final-bad` loses this fee outright: there is no code path anywhere in `headers_commission.js`, `main_chain.js`, or the commission-input validation logic in `validation.js` that redirects this amount to the payer itself, to witnesses, or to any other recoverable destination. The amount simply never appears in `headers_commission_outputs`, so it can never be referenced by a `headers_commission` input (validated in `validatePaymentInputsAndOutputs`): [5](#0-4) 

This mirrors the Y2K report precisely: the "TVL" analog here is "count of good candidate children competing for the fee." When that count is zero (the equivalent of a nullified epoch with 0 TVL), the emission tied to it (`headers_commission`) is stuck forever, with no mechanism to reclaim it.

### Impact Explanation
This results in a silent, permanent, unrecoverable loss of network fee funds (bytes) belonging to the payer unit's author. While each individual occurrence is bounded by a single unit's `headers_commission` size (typically small), it is a systemic protocol-level fund-freezing bug: any ordinary unit poster whose unit ends up in a topology where all of its next-slot descendants are rejected as `final-bad` (a legitimate, reachable outcome of normal double-spend resolution among any two conflicting units built on top of it) permanently loses that fee with no way for anyone — not the payer, not witnesses, not any address — to claim it. Because `max_spendable_mci` still advances past this MCI (the `assocWonAmounts`/`arrWinnerUnits` empty check just returns without erroring), the network permanently "forgets" this slice of the money supply is unclaimed, i.e. it is burned unintentionally rather than by design.

### Likelihood Explanation
Any unprivileged unit poster can end up on the losing side of this scenario simply by having their unit's immediate descendants (in the following 0-or-1 MCI window) all be resolved as non-serial (`final-bad`) during ordinary double-spend resolution — a routine occurrence in a DAG where conflicting spends are common (e.g., wallets retrying after a spend attempt is superseded by another chain). No malicious hub, node, or peer collusion is required; it can happen purely from normal network activity and light-wallet retry behavior building conflicting units on the same parent.

### Recommendation
Add an explicit fallback when `arrCandidateChildren.length === 0` (JS path) / when the SQL join for a payer unit yields no `good` children (MySQL path): instead of silently dropping the payer's `headers_commission`, credit it back to the payer unit's own author(s) (or to a well-defined default recipient), consistent with how the Sherlook fix redirected unclaimable epoch emissions back to the treasury rather than letting them become permanently stuck. This closes the gap symmetrically for both the MySQL query path and the SQLite/in-memory (`assocChildrenInfosRAM`) path in `headers_commission.js`.

### Proof of Concept
1. Unit `P` is created and becomes stable with `headers_commission = X` charged to its author.
2. Two units, `C1` and `C2`, are both built directly on top of `P` at the same or next MCI, forming a double-spend conflict elsewhere in the DAG.
3. The conflict resolves such that both `C1` and `C2` end up with `sequence != 'good'` (`final-bad`) — for instance because a third, better-witnessed unit `C3` (not a child of `P`) wins the double-spend and neither `C1` nor `C2` remains valid, while `P` still stabilizes as `good`.
4. When `calcHeadersCommissions()` runs for `P`'s MCI, `arrCandidateChildren` (JS path) is empty / the MySQL `JOIN ... AND +chunits.sequence='good'` returns no rows for `P`, so no row is ever inserted into `headers_commission_contributions` or `headers_commission_outputs` for `P`.
5. `max_spendable_mci` advances past `P`'s MCI regardless (`headers_commission.js:239-244`), so this MCI can never be retried.
6. `X` bytes of `P`'s `headers_commission` are now permanently unspendable — no `headers_commission` input referencing this MCI can ever be validated as non-zero (`validation.js:2593-2596`, `mc_outputs.calcEarnings`), because no output for it was ever created.

### Citations

**File:** headers_commission.js (L101-114)
```javascript
								var filter_func = function(child){
									return (child.sequence === 'good' && child.parent_units && child.parent_units.indexOf(parent.unit) > -1);
								};
								var arrSameMciChildren = storage.assocStableUnitsByMci[parent.main_chain_index].filter(filter_func);
								var arrNextMciChildren = storage.assocStableUnitsByMci[parent.main_chain_index+1].filter(filter_func);
								var arrCandidateChildren = arrSameMciChildren.concat(arrNextMciChildren);
								if (arrCandidateChildren.length === 0)
									return; // all eligible children are final-bad, nobody gets the hc
								var children = arrCandidateChildren.map(function(child){
									return {child_unit: child.unit, next_mc_unit: next_mc_unit};
								});
							//	var children = _.map(_.pickBy(storage.assocStableUnits, function(v, k){return (v.main_chain_index - props.main_chain_index == 1 || v.main_chain_index - props.main_chain_index == 0) && v.parent_units.indexOf(props.unit) > -1 && v.sequence === 'good';}), function(props, unit){return {child_unit: unit, next_mc_unit: next_mc_unit}});
								assocChildrenInfosRAM[parent.unit] = {headers_commission: parent.headers_commission, children: children};
							}
```

**File:** headers_commission.js (L144-156)
```javascript
						var assocWonAmounts = {}; // amounts won, indexed by child unit who won the hc, and payer unit
						for (var payer_unit in assocChildrenInfos){
							var headers_commission = assocChildrenInfos[payer_unit].headers_commission;
							var winnerChildInfo = getWinnerInfo(assocChildrenInfos[payer_unit].children);
							var child_unit = winnerChildInfo.child_unit;
							if (!assocWonAmounts[child_unit])
								assocWonAmounts[child_unit] = {};
							assocWonAmounts[child_unit][payer_unit] = headers_commission;
						}
						//console.log(assocWonAmounts);
						var arrWinnerUnits = Object.keys(assocWonAmounts);
						if (arrWinnerUnits.length === 0)
							return cb();
```

**File:** headers_commission.js (L221-245)
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
		function(cb){
			conn.query("SELECT MAX(main_chain_index) AS max_spendable_mci FROM headers_commission_outputs", function(rows){
				max_spendable_mci = rows[0].max_spendable_mci;
				cb();
			});
		}
	], onDone);
```

**File:** composer.js (L472-472)
```javascript
			objUnit.headers_commission = objectLength.getHeadersSize(objUnit);
```

**File:** validation.js (L2529-2543)
```javascript
				case "headers_commission":
				case "witnessing":
					if (objValidationState.bAA)
						return cb(type+" in AA");
					if (type === "headers_commission"){
						if (bHaveWitnessings)
							return cb("all headers commissions must come before witnessings");
						bHaveHeadersComissions = true;
					}
					else
						bHaveWitnessings = true;
					if (objAsset)
						return cb("only base asset can have "+type);
					if (hasFieldsExcept(input, ["type", "from_main_chain_index", "to_main_chain_index", "address"]))
						return cb("unknown fields in witnessing input");
```
