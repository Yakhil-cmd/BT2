### Title
Denial of service via unbounded array scans in DAG stability/inclusion determination (goUp/goDown traversal and best-children collection) - (File: main_chain.js, graph.js)

### Finding Description
The reported bug class is a linear-scan-based add/remove operation on an array whose size grows with attacker-supplied, unprivileged input, so that each removal/lookup costs O(n) and the cost of repeated operations becomes O(n²), eventually exhausting gas/time.

`ocore` has an analogous pattern in the main-chain stability and unit-inclusion determination code, which is executed by every node whenever it processes new units (i.e., triggered by any unprivileged unit poster). In `graph.js`, `determineIfIncluded()`'s inner `goUp`/`goDown` helpers repeatedly grow `arrKnownUnits` via `concat` and then filter new candidate units against it with `_.difference`/`indexOf`, an O(n) operation performed once per BFS/DFS layer: [1](#0-0) 

In `main_chain.js`, `createListOfBestChildrenIncludedByLaterUnits()` builds `arrBestChildren`, `arrTips`, `arrNotIncludedTips` and `arrRemovedBestChildren` arrays and repeatedly performs `indexOf` scans against them inside `async.eachSeries` loops (`findBestChildrenNotIncludedInLaterUnits`, `goDownAndCollectBestChildrenFast`, `goUp`), then concatenates removed items back with `arrRemovedBestChildren.concat(...)` and iterates again: [2](#0-1) [3](#0-2) 

These arrays are populated based on the number of units in unstable/alternative branches of the DAG below the last stable point — a quantity directly controllable by any unprivileged party simply by posting many valid units that create long, wide, or heavily-branched unstable sub-DAGs before the branch is abandoned or excluded.

### Impact Explanation
Because every node must run this exact traversal to determine unit stability/inclusion (part of consensus-critical processing on the main chain), an attacker who cheaply floods many low-value units into one or more alternative/unstable branches can inflate the arrays scanned by `indexOf`/`concat` in these functions. As in the NFT report, repeated O(n) lookups performed once per newly discovered unit turn into O(n²) total work. This can make main-chain stability determination take substantially longer for every node, potentially stalling progress of main chain stability advancement and thus the network's ability to confirm new units in a timely manner — matching the accepted "network unable to confirm new units" impact category.

### Likelihood Explanation
Likelihood is limited by the cost of producing enough units to materially degrade performance (each unit requires proof-of-work-free but fee-bearing broadcast, and witnessing/parent selection rules constrain branch growth), and modern conf.bFaster paths (`goDownAndCollectBestChildrenFast`) already yield periodically via `setImmediate` to avoid blocking the event loop, which mitigates a hard DoS. Still, the underlying algorithmic complexity remains O(n) per lookup on attacker-influenceable array sizes rather than O(1), so it is a genuine, non-trivial degradation vector reachable by any unprivileged unit poster, without needing any special privilege, hub/peer position, or leaked key.

### Recommendation
Replace `indexOf`/`concat`/`_.difference` based membership checks on `arrKnownUnits`, `arrBestChildren`, `arrTips`, `arrNotIncludedTips`, and `arrRemovedBestChildren` with hash-map/set-based membership tracking (e.g., a plain object or `Set` keyed by unit hash) so that membership checks and dedup/removal are O(1) instead of O(n). This mirrors the general fix recommended in the referenced report: use an alternative data structure so add/lookup/remove operate in O(1) rather than O(n).

### Proof of Concept
Not directly reproducible without a live multi-node testnet, but conceptually:
1. An attacker crafts many valid units forming a wide/deep alternative (non-best) branch off the current unstable DAG, all authored by cheaply generated addresses.
2. As nodes attempt to determine stability of legitimate units via `determineIfStableInLaterUnits` → `createListOfBestChildrenIncludedByLaterUnits`, and via `graph.determineIfIncluded`'s `goUp`/`goDown`, the arrays `arrKnownUnits`, `arrBestChildren`, etc. grow proportionally to the number of attacker units.
3. Each subsequent `indexOf`/`_.difference` call scans the entire accumulated array, so total work across the traversal grows quadratically with the number of attacker-injected units, degrading main-chain stability processing time for every full node.

### Citations

**File:** graph.js (L175-231)
```javascript
		var arrKnownUnits = [];
		
		function goUp(arrStartUnits){
		//	console.log('determine goUp', earlier_unit, arrLaterUnits/*, arrStartUnits*/);
			arrKnownUnits = arrKnownUnits.concat(arrStartUnits);
			var arrDbStartUnits = [];
			var arrParents = [];
			arrStartUnits.forEach(function(unit){
				var props = storage.assocUnstableUnits[unit] || storage.assocStableUnits[unit];
				if (!props || !props.parent_units){
					arrDbStartUnits.push(unit);
					return;
				}
				props.parent_units.forEach(function(parent_unit){
					var objParent = storage.assocUnstableUnits[parent_unit] || storage.assocStableUnits[parent_unit];
					if (!objParent){
						if (arrDbStartUnits.indexOf(unit) === -1)
							arrDbStartUnits.push(unit);
						return;
					}
					/*objParent = _.cloneDeep(objParent);
					for (var key in objParent)
						if (['unit', 'level', 'latest_included_mc_index', 'main_chain_index', 'is_on_main_chain'].indexOf(key) === -1)
							delete objParent[key];*/
					arrParents.push(objParent);
				});
			});
			if (arrDbStartUnits.length > 0){
				console.log('failed to find all parents in memory, will query the db, earlier '+earlier_unit+', later '+arrLaterUnits+', not found '+arrDbStartUnits);
				arrParents = [];
			}
			
			function handleParents(rows){
			//	var sort_fun = function(row){ return row.unit; };
			//	if (arrParents.length > 0 && !_.isEqual(_.sortBy(rows, sort_fun), _.sortBy(arrParents, sort_fun)))
			//		throw Error("different parents");
				var arrNewStartUnits = [];
				for (var i=0; i<rows.length; i++){
					var objUnitProps = rows[i];
					if (objUnitProps.unit === earlier_unit)
						return handleResult(true);
					if (objUnitProps.main_chain_index !== null && objUnitProps.main_chain_index <= objEarlierUnitProps.latest_included_mc_index)
						continue;
					if (objUnitProps.main_chain_index !== null && objEarlierUnitProps.main_chain_index !== null && objUnitProps.main_chain_index < objEarlierUnitProps.main_chain_index)
						continue;
					if (objUnitProps.main_chain_index !== null && objEarlierUnitProps.main_chain_index === null)
						continue;
					if (objUnitProps.latest_included_mc_index < objEarlierUnitProps.latest_included_mc_index)
						continue;
					if (objUnitProps.witnessed_level < objEarlierUnitProps.witnessed_level && objEarlierUnitProps.main_chain_index > constants.witnessedLevelMustNotRetreatFromAllParentsUpgradeMci)
						continue;
					if (objUnitProps.is_on_main_chain === 0 && objUnitProps.level > objEarlierUnitProps.level)
						arrNewStartUnits.push(objUnitProps.unit);
				}
				arrNewStartUnits = _.uniq(arrNewStartUnits);
				arrNewStartUnits = _.difference(arrNewStartUnits, arrKnownUnits);
				(arrNewStartUnits.length > 0) ? goUp(arrNewStartUnits) : handleResult(false);
```

**File:** main_chain.js (L981-1018)
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
					}
```

**File:** main_chain.js (L1020-1075)
```javascript
					function findBestChildrenNotIncludedInLaterUnits(arrUnits, cb){
						var arrUnitsToRemove = [];
						async.eachSeries(
							arrUnits, 
							function(unit, cb2){
								if (arrRemovedBestChildren.indexOf(unit) >= 0)
									return cb2();
								if (arrNotIncludedTips.indexOf(unit) >= 0){
									arrUnitsToRemove.push(unit);
									return cb2();
								}
								graph.determineIfIncludedOrEqual(conn, unit, arrLaterUnits, function(bIncluded){
									if (!bIncluded)
										arrUnitsToRemove.push(unit);
									cb2();
								});
							},
							function(){
								if (arrUnitsToRemove.length === 0)
									return cb();
								arrRemovedBestChildren = arrRemovedBestChildren.concat(arrUnitsToRemove);
								goUp(arrUnitsToRemove, cb);
							}
						);
					}
					
					function goUp(arrCurrentTips, cb){
						var arrUnits = [];
						async.eachSeries(
							arrCurrentTips,
							function(unit, cb2){
								storage.readStaticUnitProps(conn, unit, function(props){
									if (arrUnits.indexOf(props.best_parent_unit) === -1)
										arrUnits.push(props.best_parent_unit);
									cb2();
								});
							},
							function(){
								findBestChildrenNotIncludedInLaterUnits(arrUnits, cb);
							}
						);
					}
					
					function collectBestChildren(arrFilteredAltBranchRootUnits, cb){
						goDownAndCollectBestChildrenFast(arrFilteredAltBranchRootUnits, function(){
							if (arrTips.length === 0)
								return cb();
							var start_time = Date.now();
							findBestChildrenNotIncludedInLaterUnits(arrTips, function(){
								console.log("findBestChildrenNotIncludedInLaterUnits took "+(Date.now()-start_time)+"ms");
								arrBestChildren = _.difference(arrBestChildren, arrRemovedBestChildren);
								cb();
							});
						});
					}

```
