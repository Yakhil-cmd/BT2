### Title
Adversary can degrade DAG stabilization by flooding the network with tiny units, inflating the in-memory `assocUnstableUnits` map that is fully iterated on every stabilization step - (File: main_chain.js, storage.js)

### Summary
The `_accruePremiumAndExpireProtections` bug class in the report is a case of an unbounded, attacker-inflatable loop over "all active items" that executes on a normal, frequently-triggered code path, letting a low-cost flood of tiny objects blow up the cost of every subsequent call until the call runs out of gas/time. In ocore, the analogous unbounded structure is `storage.assocUnstableUnits`, an in-memory map of every currently-unstable unit in the DAG, which is rebuilt on startup by `initUnstableUnits` [1](#0-0)  and is iterated in full inside `markMcIndexStable` and `updateLatestIncludedMcIndex`, both of which run as part of `advanceMcStability`, i.e. on (or shortly after) every new unit that is added to the DAG [2](#0-1) [3](#0-2) .

### Finding Description
`markMcIndexStable` iterates `for (var unit in storage.assocUnstableUnits)` to find all units at the given `main_chain_index` and mark them stable [4](#0-3) . `updateLatestIncludedMcIndex` performs an equivalent full scan of the same map before recomputing LIMCIs [5](#0-4) . Both functions are called from `advanceMcStability`, which fires for every unit added to the DAG (via `writer.js`), so the cost of these loops is paid repeatedly, once per incoming unit, for as long as the units referenced by the map remain unstable.

`assocUnstableUnits` size is driven purely by how many units in the DAG have not yet reached the 7/12-witness majority stability rule. A poster who is not a witness can create an arbitrarily large number of minimal-size, minimal-fee units (e.g. single-input/single-output "tiny" transfers) chained or parallel-parented so that they linger in the unstable set for longer (e.g., by not being included promptly by witness-authored units, or by creating many parallel non-witness branches that need to be walked/merged before majority witnessing is achieved). Because the loop is a plain JS `for...in` over the whole map on the hot "new unit received" path, this is structurally identical to the reported `_accruePremiumAndExpireProtections` issue: an attacker with only the ability to post ordinary units (no special privilege) can inflate a global "active set" that every future confirmation-critical operation must fully scan.

This differs from a pure network/p2p flood: the cost is not just bandwidth/storage but a specific, unbounded synchronous JS loop that runs on the node's core consensus/stabilization code path for every future unit, independent of whether that unit is otherwise unrelated to the attacker's units.

### Impact Explanation
As `assocUnstableUnits` grows, every subsequent unit written to the DAG pays an O(n) (or worse, since `updateLatestIncludedMcIndex` also does per-unit DB updates keyed off entries found in the loop, see `main_chain.js:390-441`) cost before it can be confirmed/stabilized. If sustained, this slows down or stalls MC advancement for the whole node, i.e., the network becomes unable to confirm new units in a timely manner — directly matching the "network unable to confirm new units" impact class. Because stabilization/consensus code is shared by all full nodes, a sufficiently large flood can degrade throughput network-wide, not just for the attacker's own transactions.

### Likelihood Explanation
Likelihood is moderate: creating many small units costs headers/payload commissions and (post-v4) `tps_fee`, so the attack is not free, but the report's underlying bug class — "no cap on the number of items that can be pushed into an always-fully-scanned collection" — is present verbatim in `assocUnstableUnits` handling. No special role (witness, hub, light vendor) is required; any ordinary unit poster can grow the unstable set. The severity is capped by the economic cost of tps fees and by witnesses' rate of stabilizing the MC, which is why I rate this Medium rather than High/Critical, consistent with the original report's own Medium rating for the same bug class.

### Recommendation
Bound or batch the work done per stabilization step instead of scanning the full `assocUnstableUnits` map synchronously in `markMcIndexStable`/`updateLatestIncludedMcIndex`. Options include: indexing unstable units by `main_chain_index` (already partially done via `assocStableUnitsByMci`, but the initial mci-matching scan in `markMcIndexStable` at `main_chain.js:1296-1303` is still a full linear scan) so lookups are O(1)/O(k) instead of O(n) over the entire unstable set; and/or processing the LIMCI recalculation in `updateLatestIncludedMcIndex` in bounded chunks with `setImmediate` yields (similar to the `count % 100 === 0` chunking already used in `goDownAndCollectBestChildrenFast`, `main_chain.js:1008-1014`) to avoid blocking the event loop for extended periods when the unstable set is abnormally large.

### Proof of Concept
Not verified with a runnable PoC. The reachable path is: (1) an unprivileged node posts a large number of minimal-fee, minimal-size units that reference existing free tips as parents, keeping them structurally "unstable" (not yet witnessed by majority) for an extended period; (2) `initUnstableUnits`/normal joint processing inserts all of them into `storage.assocUnstableUnits`; (3) every subsequently received unit triggers `advanceMcStability` → `updateStableMcFlag`/`markMcIndexStable`/`updateLatestIncludedMcIndex`, each of which fully iterates `storage.assocUnstableUnits` (`main_chain.js:372-378`, `main_chain.js:1296-1303`), so the per-unit processing cost scales with the number of units the attacker managed to keep unstable. I was not able to execute this against a live/test node in this session to measure actual timing degradation, so the severity estimate is based on code-path analysis only, not empirical benchmarking.

### Citations

**File:** storage.js (L2300-2334)
```javascript
function initUnstableUnits(conn, onDone){
	if (!onDone)
		return new Promise(resolve => initUnstableUnits(conn, resolve));
	conn = conn || db;
	conn.query(
		"SELECT unit, level, latest_included_mc_index, main_chain_index, is_on_main_chain, is_free, is_stable, witnessed_level, headers_commission, payload_commission, sequence, timestamp, GROUP_CONCAT(address) AS author_addresses, COALESCE(witness_list_unit, unit) AS witness_list_unit, best_parent_unit, last_ball_unit, tps_fee, max_aa_responses, count_aa_responses, count_primary_aa_triggers, is_aa_response, version \n\
			FROM units \n\
			JOIN unit_authors USING(unit) \n\
			WHERE is_stable=0 \n\
			GROUP BY +unit \n\
			ORDER BY +level",
		function(rows){
		//	assocUnstableUnits = {};
			rows.forEach(function(row){
				var best_parent_unit = row.best_parent_unit;
			//	delete row.best_parent_unit;
				row.count_primary_aa_triggers = row.count_primary_aa_triggers || 0;
				row.bAA = !!row.is_aa_response;
				delete row.is_aa_response;
				row.tps_fee = row.tps_fee || 0;
				if (parseFloat(row.version) >= constants.fVersion4)
					delete row.witness_list_unit;
				delete row.version;
				row.author_addresses = row.author_addresses.split(',');
				assocUnstableUnits[row.unit] = row;
				if (assocUnstableUnits[best_parent_unit]){
					if (!assocBestChildren[best_parent_unit])
						assocBestChildren[best_parent_unit] = [];
					assocBestChildren[best_parent_unit].push(row);
				}
			});
			console.log('initUnstableUnits 1 done');
			if (Object.keys(assocUnstableUnits).length === 0)
				return onDone ? onDone() : null;
			initParenthoodAndHeadersComissionShareForUnits(conn, assocUnstableUnits, onDone);
```

**File:** main_chain.js (L366-378)
```javascript
		console.log("updateLatestIncludedMcIndex "+last_main_chain_index);
		if (!conf.bFaster)
			profiler.start();
		var assocChangedUnits = {};
		var assocLimcisByUnit = {};
		var assocDbLimcisByUnit = {};
		for (var unit in storage.assocUnstableUnits){
			var o = storage.assocUnstableUnits[unit];
			if (o.main_chain_index > last_main_chain_index || o.main_chain_index === null){
				o.latest_included_mc_index = null;
				assocChangedUnits[unit] = o;
			}
		}
```

**File:** main_chain.js (L1288-1307)
```javascript
function markMcIndexStable(conn, batch, mci, onDone){
	if (!onDone)
		return new Promise(resolve => markMcIndexStable(conn, batch, mci, resolve));
	profiler.start();
	let count_aa_triggers;
	var arrStabilizedUnits = [];
	if (mci > 0)
		storage.assocStableUnitsByMci[mci] = [];
	for (var unit in storage.assocUnstableUnits){
		var o = storage.assocUnstableUnits[unit];
		if (o.main_chain_index === mci && o.is_stable === 0){
			o.is_stable = 1;
			storage.assocStableUnits[unit] = o;
			storage.assocStableUnitsByMci[mci].push(o);
			arrStabilizedUnits.push(unit);
		}
	}
	arrStabilizedUnits.forEach(function(unit){
		delete storage.assocUnstableUnits[unit];
	});
```
