### Title
Unbounded growth of `storage.assocBestChildren[parent_unit]` from repeated single-parent unit posting causes DoS of main-chain stability advancement - (File: writer.js, main_chain.js)

### Summary
Any unprivileged unit poster can keep adding new units that all choose the same still‑unstable unit as their sole parent (and hence as their `best_parent_unit`). Every time such a unit is written, its properties are pushed into the in‑memory array `storage.assocBestChildren[best_parent_unit]` with no upper bound on the array's size. This array is later iterated in full — synchronously, in Node's single event loop — on *every* subsequent unit that is added to the DAG, as part of `advanceMcStability`/`determineIfStableInLaterUnits`, which is unavoidable machinery required to confirm any new unit on the network. The unbounded growth is functionally analogous to the `partyBPendingQuotes` unbounded-array iteration reported in the original Symmetrical finding: an attacker-controlled, ever-growing per-key list that a core state-transition function is later forced to fully traverse.

### Finding Description
When a new unit is written, `writer.saveJoint` records it in `storage.assocUnstableUnits` and additionally appends it to `storage.assocBestChildren[my_best_parent_unit]`, unconditionally and without any length cap: [1](#0-0) 

`my_best_parent_unit` is deterministically computed from the parent set the author of the new unit chooses to reference (`objValidationState.best_parent_unit`). If the author repeatedly submits new units whose `parent_units` array contains only a single still‑unstable tip `X` (a perfectly valid and common unit shape), then `X` trivially becomes the `best_parent_unit` for every one of these new units, and `storage.assocBestChildren[X]` keeps growing by one entry per posted unit, with no limit enforced anywhere in this path.

This array is not merely bookkeeping — it is read and iterated in full on the hot path used to determine and advance main-chain stability, which every full node must run for every new unit added to the DAG:

- `readBestChildrenProps` returns the *entire* in-memory list for any set of still-unstable units: [2](#0-1) 

- This is consumed inside `createListOfBestChildrenIncludedByLaterUnits` → `goDownAndCollectBestChildrenFast`, which performs `async.eachSeries` over every element of the returned array on each invocation: [3](#0-2) 

- These routines are invoked from `updateStableMcFlag`, which is executed every time `advanceMcStability` runs, i.e., on every new unit written to the ledger: [4](#0-3) [5](#0-4) 

Unlike other per-unit structures in the protocol (e.g., messages per unit, authors per unit, parents per unit), which are bounded by explicit `constants.MAX_*` checks enforced in `validation.js`, there is no corresponding cap on the number of children (best-child references) that a single unstable unit may accumulate before it stabilizes. An attacker who keeps a chosen tip `X` "alive" (unstable) by continuously feeding it new descendants elsewhere in the DAG, while repeatedly posting cheap single-parent units on top of `X`, can inflate `assocBestChildren[X]` arbitrarily during the window before `X` stabilizes.

### Impact Explanation
Because `assocBestChildren[X]` is fully materialized and iterated (via `readBestChildrenProps`/`goDownAndCollectBestChildrenFast`/`createListOfBestChildren`) inside the synchronous, single-threaded stability-advancement logic that every node must execute for *every* new unit it processes, an attacker-inflated array increases the CPU cost of `advanceMcStability` for all subsequent units network-wide, not just for units authored by the attacker. As the array grows without bound, the per-unit cost of confirming *any* unit increases, degrading main-chain stability advancement and, in the worst case, causing the node to stall processing new units — i.e., "a network unable to confirm new units," one of the accepted high/critical impact classes for this scan.

### Likelihood Explanation
The attack requires only the ability to post ordinary units — no special privileges, witness status, or AA authorship — using a valid, cheap DAG shape (single-parent units referencing the same tip). This is easily reachable by any unprivileged unit poster and requires no coordination with other network participants, making the likelihood high given a motivated attacker willing to pay minimal per-unit fees to grow the array.

### Recommendation
Introduce an explicit cap analogous to other DAG anti-spam limits (e.g. `constants.MAX_PARENTS_PER_UNIT`), such as `MAX_BEST_CHILDREN_PER_UNIT`, and reject/deprioritize new units whose computed `best_parent_unit` already has an excessive number of recorded best children in `storage.assocBestChildren`, or otherwise bound/paginate the traversal performed in `goDownAndCollectBestChildrenFast`/`createListOfBestChildren` so that the cost of stability advancement cannot scale unboundedly with attacker-controlled fan-out from a single stale tip.

### Proof of Concept
1. Identify or create a currently free, unstable unit `X` in the DAG (any ordinary unit works as a tip).
2. Attacker repeatedly composes and posts new units `U1, U2, …, Un`, each with `parent_units: [X]` only (single-parent unit, minimal payload/fee), while ensuring `X` itself does not stabilize during this window (e.g., by controlling the tip growth elsewhere or exploiting normal network timing before the 12-witness stabilization threshold is met on this branch).
3. Each `Ui` is processed by `writer.saveJoint`, computing `best_parent_unit = X` and pushing `Ui`'s properties into `storage.assocBestChildren[X]` per the code at `writer.js:598-601`, with no cap.
4. As `n` grows large (bounded only by attacker's willingness to pay per-unit fees), every subsequent call to `updateStableMcFlag`/`determineIfStableInLaterUnits` for *any* unrelated unit elsewhere on the DAG triggers `readBestChildrenProps`/`goDownAndCollectBestChildrenFast`, which fully iterates `storage.assocBestChildren[X]` (`main_chain.js:704-712`, `981-1017`), incurring O(n) cost per call.
5. Repeating this against multiple stale tips in parallel compounds the per-unit stability-check cost across the whole node, degrading or stalling confirmation of new units network-wide.

### Citations

**File:** writer.js (L596-602)
```javascript
			else
				storage.assocUnstableUnits[objUnit.unit] = objNewUnitProps;
			if (!bGenesis && storage.assocUnstableUnits[my_best_parent_unit]) {
				if (!storage.assocBestChildren[my_best_parent_unit])
					storage.assocBestChildren[my_best_parent_unit] = [];
				storage.assocBestChildren[my_best_parent_unit].push(objNewUnitProps);
			}
```

**File:** main_chain.js (L512-520)
```javascript
					if (first_unstable_mc_index > constants.lastBallStableInParentsUpgradeMci) {
						const arrFreeUnits = getFreeUnits();
						console.log(`will call determineIfStableInLaterUnits`, first_unstable_mc_unit, arrFreeUnits)
						determineIfStableInLaterUnits(conn, first_unstable_mc_unit, arrFreeUnits, function (bStable) {
							console.log(first_unstable_mc_unit + ' stable in free units ' + arrFreeUnits.join(', ') + ' ? ' + bStable);
							bStable ? advanceLastStableMcUnitAndTryNext() : finish();
						});
						return;
					}
```

**File:** main_chain.js (L552-569)
```javascript
								}
								createListOfBestChildren(conn, arrAltBranchRootUnits, function(arrAltBestChildren){
									determineMaxAltLevel(
										conn, first_unstable_mc_index, first_unstable_mc_level, arrAltBestChildren, arrWitnesses,
										function(max_alt_level){
											if (min_mc_wl > max_alt_level)
												return advanceLastStableMcUnitAndTryNext();
											console.log('--- with branches - unstable');
											if (getFreeUnits().length <= 1) // single free unit
												return finish();
											console.log('--- will try tip parent '+tip_unit);
											determineIfStableInLaterUnits(conn, first_unstable_mc_unit, [tip_unit], function (bStable) {
												console.log('---- tip only: '+bStable);
												bStable ? advanceLastStableMcUnitAndTryNext() : finish();
											});
										}
									);
								});
```

**File:** main_chain.js (L704-712)
```javascript
function readBestChildrenProps(conn, arrUnits, handleResult){
	if (arrUnits.every(function(unit){ return !!storage.assocUnstableUnits[unit]; })){
		var arrProps = [];
		arrUnits.forEach(function(unit){
			if (storage.assocBestChildren[unit])
				arrProps = arrProps.concat(storage.assocBestChildren[unit]);
		});
		return handleResult(arrProps);
	}
```

**File:** main_chain.js (L981-1017)
```javascript
					function goDownAndCollectBestChildrenFast(arrStartUnits, cb){
						readBestChildrenProps(conn, arrStartUnits, function(rows){
							if (rows.length === 0){
								arrStartUnits.forEach(function(start_unit){
									arrTips.push(start_unit);
								});
								return cb();
							}
							var count = arrBestChildren.length;
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
										arrTips.push(row.unit);
										arrNotIncludedTips.push(row.unit);
										cb2();
									}
									else {
										if (count % 100 === 0)
											return setImmediate(goDownAndCollectBestChildrenFast, [row.unit], cb2);
										goDownAndCollectBestChildrenFast([row.unit], cb2);
									}
								},
								function () {
									(count % 100 === 0) ? setImmediate(cb) : cb();
								}
							);
						});
```
