### Title
Off-by-one boundary mismatch (`>` vs `>=`) in `witnessedLevelMustNotRetreatFromAllParentsUpgradeMci` gating between `graph.js` and `main_chain.js` can cause the fast stability-search path to diverge from the reference path at the exact upgrade MCI - (File: `main_chain.js`, `graph.js`)

### Summary
This is the same bug class reported in the YieldMath `log_2` finding: two implementations of what should be the *same* rule use inconsistent boundary operators (`>` vs `>=`) around a single threshold constant. In `ocore`, the threshold `constants.witnessedLevelMustNotRetreatFromAllParentsUpgradeMci` gates whether the "witnessed level must not retreat" rule applies to graph-inclusion/stability computations. `graph.js` gates it with strict `>`, while `main_chain.js`'s fast best-children collector gates the analogous check with `>=`, producing different behavior for units exactly at the upgrade MCI.

### Finding Description
`graph.js:determineIfIncluded` applies the witnessed-level-retreat exclusion rule using a strict `>` comparison against the upgrade MCI, in two places (the aggregate short-circuit check and the per-row ancestor-walk check): [1](#0-0) [2](#0-1) 

Both read: `... && objEarlierUnitProps.main_chain_index > constants.witnessedLevelMustNotRetreatFromAllParentsUpgradeMci`.

In contrast, `main_chain.js:goDownAndCollectBestChildrenFast` — the fast-path implementation used inside `determineIfStableInLaterUnits` to build the "best children" set walked down from the best parent when computing `min_mc_wl` for stability — applies the analogous check with `>=`: [3](#0-2) 

Specifically line 999: `row.witnessed_level > max_later_witnessed_level && first_unstable_mc_index >= constants.witnessedLevelMustNotRetreatFromAllParentsUpgradeMci`.

At `main_chain_index === witnessedLevelMustNotRetreatFromAllParentsUpgradeMci` exactly, `graph.js`'s condition evaluates to `false` (rule not yet enforced for that unit), while `main_chain.js`'s condition evaluates to `true` (rule already enforced). This is precisely the class of bug flagged in the external report: the same conceptual rule implemented twice with inconsistent boundary operators around an identical constant.

The fast path result feeds `min_mc_wl` via `findMinMcWitnessedLevel` and `collectBestChildren`, which directly determines the outcome of `determineIfStableInLaterUnits`: [4](#0-3) 

Notably, the self-consistency check that compares the fast path (`goDownAndCollectBestChildrenFast`/`collectBestChildren`) against the reference/old path (`goDownAndCollectBestChildrenOld`, which itself relies on `graph.determineIfIncludedOrEqual`) is only executed when `!conf.bFaster`: [5](#0-4) 

When `conf.bFaster` is `true`, `collectBestChildren` (fast path only) is used directly with no cross-check against the `graph.js`-based reference implementation, so the boundary discrepancy is never caught by the `throwError` safety net at line 1121.

### Impact Explanation
`determineIfStableInLaterUnits` is core consensus logic that decides whether a unit (and its main-chain-index) becomes marked stable, which is the basis for finalizing payments, AA triggers, and double-spend resolution across the DAG. A boundary mismatch that changes which units are treated as "tips" during the best-children walk, for units at exactly the upgrade MCI, can change the computed `min_mc_wl` and therefore the stability verdict for that unit. Since nodes running with `conf.bFaster=true` skip the cross-check against the reference algorithm, they could reach a stability conclusion for the boundary MCI that differs from the (correct) reference/graph.js-consistent algorithm, causing disagreement between nodes on whether a given unit/mci is stable — falling under the accepted impact "node disagreement on validity or stability."

### Likelihood Explanation
Likelihood is limited to a single specific main_chain_index value equal to the upgrade constant `witnessedLevelMustNotRetreatFromAllParentsUpgradeMci`, and only manifests when a unit at that exact index has children whose witnessed level lies strictly between `max_later_witnessed_level` exclusive bounds relevant to the two differing conditions, and only when `conf.bFaster` is enabled (skipping the cross-check). This narrows real-world triggering to a specific historical/boundary MCI and specific graph shapes, making it a low-frequency but structurally real consensus-divergence risk rather than an attacker-controlled arbitrary trigger.

### Recommendation
Audit every use of `witnessedLevelMustNotRetreatFromAllParentsUpgradeMci` (and analogous upgrade-MCI constants gating consensus-relevant comparisons) and standardize the boundary operator (`>` vs `>=`) to match the originally intended semantics used when the upgrade activated. Specifically, align `main_chain.js:999`'s `first_unstable_mc_index >= constants.witnessedLevelMustNotRetreatFromAllParentsUpgradeMci` with `graph.js`'s `main_chain_index > constants.witnessedLevelMustNotRetreatFromAllParentsUpgradeMci` (or vice versa, whichever matches the deployed/expected chain behavior), and ensure the `throwError` consistency check between `collectBestChildren` and `goDownAndCollectBestChildrenOld` is always executed (not gated behind `conf.bFaster`) so that any future operator mismatch is caught before nodes diverge in production.

### Proof of Concept
1. Consider a unit `U` with `main_chain_index === constants.witnessedLevelMustNotRetreatFromAllParentsUpgradeMci` exactly, having a best child with `witnessed_level` strictly greater than `max_later_witnessed_level` but not violating the graph.js ancestor-inclusion rule (since `graph.js`'s `>` check does not trigger at this exact MCI).
2. Running `determineIfStableInLaterUnits` on `U` with `conf.bFaster=true` causes `goDownAndCollectBestChildrenFast` (main_chain.js:990-1002) to classify that child as a "tip" (stopping the walk early) because its `>=` boundary condition is satisfied at this MCI, while the reference algorithm based on `graph.js:determineIfIncludedOrEqual` (as used by `goDownAndCollectBestChildrenOld`) would not stop there, since its `>` condition is not yet satisfied.
3. This produces a different `arrBestChildren`/`min_mc_wl` between the fast and reference algorithms for that specific boundary unit, and because the equality check between the two paths is skipped when `conf.bFaster` is true (main_chain.js:1107-1111), the divergent (fast-path) stability verdict is accepted without detection, risking a differing stability conclusion from a node still using the slow/graph.js path.

### Citations

**File:** graph.js (L158-161)
```javascript
		var max_later_wl = Math.max.apply(
			null, arrLaterUnitProps.map(function(objLaterUnitProps){ return objLaterUnitProps.witnessed_level; }));
		if (max_later_wl < objEarlierUnitProps.witnessed_level && objEarlierUnitProps.main_chain_index > constants.witnessedLevelMustNotRetreatFromAllParentsUpgradeMci)
			return handleResult(false);
```

**File:** graph.js (L222-225)
```javascript
					if (objUnitProps.latest_included_mc_index < objEarlierUnitProps.latest_included_mc_index)
						continue;
					if (objUnitProps.witnessed_level < objEarlierUnitProps.witnessed_level && objEarlierUnitProps.main_chain_index > constants.witnessedLevelMustNotRetreatFromAllParentsUpgradeMci)
						continue;
```

**File:** main_chain.js (L990-1002)
```javascript
							async.eachSeries(
								rows, 
								function(row, cb2){
									arrBestChildren.push(row.unit);
									if (arrLaterUnits.indexOf(row.unit) >= 0)
										cb2();
									else if (
										row.is_free === 1
										|| row.level >= max_later_level
										|| row.witnessed_level > max_later_witnessed_level && first_unstable_mc_index >= constants.witnessedLevelMustNotRetreatFromAllParentsUpgradeMci
										|| row.latest_included_mc_index > max_later_limci
										|| row.is_on_main_chain && row.main_chain_index > max_later_limci
									){
```

**File:** main_chain.js (L1103-1126)
```javascript
									if (arrFilteredAltBranchRootUnits.length === 0)
										return handleBestChildrenList([]);
									var arrInitialBestChildren = _.clone(arrBestChildren);
									var start_time = Date.now();
									if (conf.bFaster)
										return collectBestChildren(arrFilteredAltBranchRootUnits, function(){
											console.log("collectBestChildren took "+(Date.now()-start_time)+"ms");
											cb();
										});
									goDownAndCollectBestChildrenOld(arrFilteredAltBranchRootUnits, function(){
										console.log("goDownAndCollectBestChildrenOld took "+(Date.now()-start_time)+"ms");
										var arrBestChildren1 = _.clone(arrBestChildren.sort());
										arrBestChildren = arrInitialBestChildren;
										start_time = Date.now();
										collectBestChildren(arrFilteredAltBranchRootUnits, function(){
											console.log("collectBestChildren took "+(Date.now()-start_time)+"ms");
											arrBestChildren.sort();
											if (!_.isEqual(arrBestChildren, arrBestChildren1)){
												throwError("different best children, old "+arrBestChildren1.join(', ')+'; new '+arrBestChildren.join(', ')+', later '+arrLaterUnits.join(', ')+', earlier '+earlier_unit+", global db? = "+(conn === db));
												arrBestChildren = arrBestChildren1;
											}
											cb();
										});
									});
```

**File:** main_chain.js (L1138-1147)
```javascript
				findMinMcWitnessedLevel(function(min_mc_wl){
					//console.log("min mc wl", min_mc_wl);
					if (min_mc_wl === null) // couldn't collect even 7 witnesses
						return handleResult(false);
					determineIfHasAltBranches(function(bHasAltBranches){
						if (!bHasAltBranches){
							console.log("determineIfStableInLaterUnits no alt took "+(Date.now()-start_time)+"ms");
							if (min_mc_wl >= first_unstable_mc_level) 
								return handleResult(true);
							return handleResult(false);
```
