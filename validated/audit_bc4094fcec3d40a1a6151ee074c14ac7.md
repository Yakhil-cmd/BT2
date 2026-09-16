### Title
Unbounded alt-branch traversal in stability determination allows Denial of Service via unit-validation resource exhaustion - (File: main_chain.js)

### Summary
Every unit whose `last_ball_unit` is not yet locally known to be stable triggers a recursive, DB-heavy walk of all non-main-chain ("alt") branches descending from the last-ball candidate in order to decide stability. This traversal has no bound on the number of alt-branch units it must visit, and it executes while holding the global `handleJoint` mutex, so an attacker who cheaply grows the number of unresolved alt branches can make this computation arbitrarily expensive for every honest node validating subsequent units — closely mirroring the Synapse advisory's root cause (an auth-chain/cover-index computation with unbounded cost triggerable by crafted, attacker-controlled DAG structure).

### Finding Description
`validateParents()` calls `main_chain.determineIfStableInLaterUnitsAndUpdateStableMcFlag()` whenever the last ball referenced by a newly posted unit is not yet stable in the local view: [1](#0-0) 

That function in turn calls `determineIfStableInLaterUnits()`, which — when the earlier unit has any alternative (non-main-chain) branch — invokes `createListOfBestChildrenIncludedByLaterUnits()` to enumerate every "best child" reachable from each alt-branch root: [2](#0-1) 

The enumeration itself (`goDownAndCollectBestChildrenOld` / `goDownAndCollectBestChildrenFast`) walks the DAG downward from every alt-branch root, recursively re-querying `best_parent_unit` children and executing a `graph.determineIfIncludedOrEqual` check for tips not yet resolvable, with no upper bound on the number of units visited, and the "old" verification path additionally re-runs the entire traversal twice per call to cross-check results: [3](#0-2) [4](#0-3) 

Crucially, when a unit is found stable via this path, the code advances the stability point while holding a serializing `handleJoint` mutex lock, meaning all concurrent unit processing on the node is blocked until the (unbounded) computation and subsequent per-MCI stabilization loop complete: [5](#0-4) 

There is no cap analogous to `MAX_PARENTS_PER_UNIT` or `MAX_PARENT_DEPTH` on the number of alt-branch units that can accumulate before being resolved by the main chain; anti-spam limits in `constants.js` bound per-unit shape (authors, parents, messages) but not the total number of parallel alt-branch units an attacker can post over time: [6](#0-5) 

An unprivileged unit poster can therefore continuously post syntactically valid units that create/extend many parallel alt branches (units that pick parents other than the current main-chain tip while still satisfying witness/parent validation rules). Each additional alt-branch unit increases the DB rows and recursive levels that every future node validating a new unit (whose last ball selection touches that region of the DAG) must traverse in `createListOfBestChildrenIncludedByLaterUnits`, without any hard ceiling — directly analogous to Synapse's "weakness in how the auth chain cover index is calculated" that let a malicious room member induce high CPU and excessive DB usage.

### Impact Explanation
Because the traversal is invoked synchronously during ordinary unit validation (`validateParents`) and the "stabilize" path serializes all unit handling behind the `handleJoint` mutex, sustained growth of unresolved alt branches degrades validation throughput network-wide: nodes spend increasing CPU/DB I/O per incoming unit just to answer "is the last ball stable", and other units queue behind the mutex. In the worst case this can slow or stall a node's ability to validate and confirm new units — a network-availability impact analogous to the referenced CWE-770 (uncontrolled resource consumption) issue, without requiring any special privilege, hub role, or network-level attack — a single crafted sequence of units suffices.

### Likelihood Explanation
Any address can author and broadcast units; producing alt-branch units only requires enough payment/headers commission to make units valid (no special asset or committee membership needed), so the barrier to grow the number of alt branches is the ordinary anti-spam fee cost, not a structural limit. Because the discovery/expansion cost of `createListOfBestChildrenIncludedByLaterUnits` scales with the (attacker-controlled) size of the alt-branch subgraph, the likelihood of an attacker economically able to spam units achieving a meaningful CPU/DB burden is moderate-to-high, particularly since the routine also runs the traversal twice for verification (`goDownAndCollectBestChildrenOld` plus `collectBestChildren`) in the fast-storage code path.

### Recommendation
- Bound the alt-branch traversal (e.g., cap the number of units/levels visited by `createListOfBestChildrenIncludedByLaterUnits`, similar to `MAX_PARENTS_PER_UNIT`/`MAX_PARENT_DEPTH`), and fail closed (treat as "not yet stable", not throw/hang) when the cap is exceeded.
- Avoid performing the duplicate old/new traversal (`goDownAndCollectBestChildrenOld` followed by `collectBestChildren`) in production; keep it only under an explicit debug/consistency-check flag.
- Track and rate-limit the number of outstanding alt-branch units per author/address so a single actor cannot cheaply inflate the alt-branch subgraph that every node must traverse.
- Release the `handleJoint` mutex (or otherwise avoid serializing unrelated unit validation) while running the alt-branch stability search, so a slow computation for one region of the DAG does not block all unit processing.

### Proof of Concept
1. An attacker-controlled address (or several colluding addresses) repeatedly composes and broadcasts units that intentionally avoid extending the current main-chain tip, instead building on older free units so as to create many parallel, non-main-chain ("alt") branches that all remain valid and are eventually referenced as parents by legitimate units.
2. As free units accumulate, an honest unit's `last_ball_unit` (chosen by normal parent-selection logic) is not yet known stable locally, so `validateParents()` invokes `main_chain.determineIfStableInLaterUnitsAndUpdateStableMcFlag()` (validation.js:803).
3. `determineIfStableInLaterUnits()` detects alt branches and calls `createListOfBestChildrenIncludedByLaterUnits()`, which must walk the entire attacker-grown alt-branch subgraph (main_chain.js:944-979, 1106-1126) before returning a stability verdict.
4. Because this computation runs under the `handleJoint` lock during stability advancement (main_chain.js:1206-1236), each additional round of alt-branch units the attacker posts increases the CPU/DB cost paid by every node validating subsequent units, degrading the network's ability to timely confirm new units — reproducing the DoS pattern described in GHSA-3h7q-rfh9-xm4v.

### Citations

**File:** validation.js (L802-810)
```javascript
						// Last ball is not stable yet in our view. Check if it is stable in view of the parents
						main_chain.determineIfStableInLaterUnitsAndUpdateStableMcFlag(conn, last_ball_unit, objUnit.parent_units, objLastBallUnitProps.is_stable, function(bStable, bAdvancedLastStableMci){
							/*if (!bStable && objLastBallUnitProps.is_stable === 1){
								var eventBus = require('./event_bus.js');
								eventBus.emit('nonfatal_error', "last ball is stable, but not stable in parents, unit "+objUnit.unit, new Error());
								return checkNoSameAddressInDifferentParents();
							}
							else */if (!bStable)
								return callback(objUnit.unit+": last ball unit "+last_ball_unit+" is not stable in view of your parents "+objUnit.parent_units);
```

**File:** main_chain.js (L944-979)
```javascript
				// also includes arrAltBranchRootUnits
				function createListOfBestChildrenIncludedByLaterUnits(arrAltBranchRootUnits, handleBestChildrenList){
					if (arrAltBranchRootUnits.length === 0)
						return handleBestChildrenList([]);
					var arrBestChildren = [];
					var arrTips = [];
					var arrNotIncludedTips = [];
					var arrRemovedBestChildren = [];

					function goDownAndCollectBestChildrenOld(arrStartUnits, cb){
						conn.query("SELECT unit, is_free, main_chain_index FROM units WHERE best_parent_unit IN(?)", [arrStartUnits], function(rows){
							if (rows.length === 0)
								return cb();
							async.eachSeries(
								rows, 
								function(row, cb2){
									
									function addUnit(){
										arrBestChildren.push(row.unit);
										if (row.is_free === 1 || arrLaterUnits.indexOf(row.unit) >= 0)
											cb2();
										else
											goDownAndCollectBestChildrenOld([row.unit], cb2);
									}
									
									if (row.main_chain_index !== null && row.main_chain_index <= max_later_limci)
										addUnit();
									else
										graph.determineIfIncludedOrEqual(conn, row.unit, arrLaterUnits, function(bIncluded){
											bIncluded ? addUnit() : cb2();
										});
								},
								cb
							);
						});
					}
```

**File:** main_chain.js (L1106-1126)
```javascript
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

**File:** main_chain.js (L1201-1236)
```javascript
		breadcrumbs.add('stable in parents, will wait for handleJoint lock');
		handleResult(bStable, true);

		// result callback already called, we stay here to move the stability point forward.
		// To avoid deadlocks, we always first obtain a "handleJoint" lock, then a db connection
		const bOpListCanChange = hasUnstableOpVoteCount();
		mutex.lock(["handleJoint"], function(unlock){
			breadcrumbs.add('stable in parents, got handleJoint lock');
			storage.readLastStableMcIndex(db, function(last_stable_mci){
				/*if (last_stable_mci >= constants.v4UpgradeMci && !(constants.bTestnet && last_stable_mci === 3547801)) {
					// we don't advance the stability point in v4 as that would necessitate executing triggers and updating actual tps fees. We return a transient error and expect that the stability point will move thanks to other units before the earlier_unit is retransmitted.
					await conn.query("COMMIT");
					conn.release();
					unlock();
					return console.log(`${earlier_unit} not stable in db but stable in later units ${arrLaterUnits.join(', ')} in v4`);
				//	throwError(`${earlier_unit} not stable in db but stable in later units ${arrLaterUnits.join(', ')} in v4`);
				}*/
				storage.readUnitProps(db, earlier_unit, async function(objEarlierUnitProps){
					if (!objEarlierUnitProps.is_on_main_chain)
						throw Error("earlier unit is no longer on main chain");
					var new_last_stable_mci = objEarlierUnitProps.main_chain_index;
					if (new_last_stable_mci <= last_stable_mci || objEarlierUnitProps.is_stable)
						return unlock("the stability point moved while we were waiting for the lock, last_stable_mci="+last_stable_mci+", new_last_stable_mci="+new_last_stable_mci);
					for (let mci = last_stable_mci + 1; mci <= new_last_stable_mci; mci++) {
						if (bOpListCanChange && mci >= constants.v4UpgradeMci) {
							// check stability before every step using the best parent's OP list (the standard rule for advancing stability). The initial stability of the earlier_unit was determined using the OP list of the last stable unit
							const conn = await db.takeConnectionFromPool();
							const [{ unit }] = await conn.query("SELECT unit FROM units WHERE main_chain_index=? AND is_on_main_chain=1", [mci]);
							const bMciStable = await determineIfStableInLaterUnits(conn, unit, arrLaterUnits);
							conn.release();
							if (!bMciStable) break;
						}
						await stabilizeMci(mci);
					}
					unlock();
				});
```

**File:** constants.js (L42-59)
```javascript
// anti-spam limits
exports.MAX_AUTHORS_PER_UNIT = 16;
exports.MAX_PARENTS_PER_UNIT = 16;
exports.MAX_MESSAGES_PER_UNIT = 128;
exports.MAX_SPEND_PROOFS_PER_MESSAGE = 128;
exports.MAX_INPUTS_PER_PAYMENT_MESSAGE = 128;
exports.MAX_OUTPUTS_PER_PAYMENT_MESSAGE = 128;
exports.MAX_CHOICES_PER_POLL = 128;
exports.MAX_CHOICE_LENGTH = 64;
exports.MAX_DENOMINATIONS_PER_ASSET_DEFINITION = 64;
exports.MAX_ATTESTORS_PER_ASSET = 64;
exports.MAX_DATA_FEED_NAME_LENGTH = 64;
exports.MAX_DATA_FEED_VALUE_LENGTH = 64;
exports.MAX_DATA_FEEDS_PER_MESSAGE = 1024;
exports.MAX_AUTHENTIFIER_LENGTH = 4096;
exports.MAX_CAP = 9e15;
exports.MAX_COMPLEXITY = process.env.MAX_COMPLEXITY || 100;
exports.MAX_UNIT_LENGTH = process.env.MAX_UNIT_LENGTH || 5e6;
```
