### Title
Stale aliased unit-props objects in `assocStableUnitsByMci` after `shrinkCache()` prunes `assocStableUnits` — reachable through every unit's TPS-fee validation - ([File: storage.js])

### Summary
`storage.js` aliases the same in-memory unit-props object between two caches (`assocStableUnits[unit]` and `assocStableUnitsByMci[mci]`), exactly like libpng's `png_ptr->trans_alpha`/`info_ptr->trans_alpha` and `png_ptr->palette`/`info_ptr->palette` aliasing. One cache (`assocStableUnits`) is pruned per-unit by `shrinkCache()`, while the other (`assocStableUnitsByMci`) is pruned by a separate, only loosely-coupled sweep. This can leave dangling/stale references in `assocStableUnitsByMci` that no longer correspond to `assocStableUnits`, which is exactly the CVE's "freed through one struct while dangling pointer remains in the other" pattern, mapped from libpng's C heap allocations to ocore's JS object-identity aliasing.

### Finding Description
Unit-props objects are pushed into two different long-lived caches by reference (not by copy), so both maps hold the identical object: [1](#0-0) 

and at stabilization time: [2](#0-1) 

The code even asserts this aliasing invariant explicitly in `getFinalTps`: [3](#0-2) 

`shrinkCache()` prunes `assocStableUnits` per-unit based on a live SQL query (`main_chain_index < top_mci`), but prunes `assocStableUnitsByMci` using an unrelated, purely arithmetic, contiguous top-down sweep that stops at the first missing key: [4](#0-3) 

These two pruning mechanisms are not transactionally tied to the same unit set: the `assocStableUnitsByMci` sweep assumes perfectly contiguous MCI buckets and silently `break`s on the first gap, while the `assocStableUnits` deletion is driven by a DB query over `arrUnits` (built from five different caches unioned together) that can legitimately skip some units (e.g. units still present in `assocKnownUnits`/`assocCachedUnitAuthors` but already below `top_mci`, or a `mci` bucket that is momentarily absent due to async timing since `shrinkCache` runs on `setInterval` and issues chunked, non-blocked `db.query` calls after taking the "write" lock only for the synchronous part of the function). This mirrors the libpng bug precisely: two references to the same allocation (`assocStableUnits[unit]` / entries inside `assocStableUnitsByMci[mci]`) are freed by two independently-triggered code paths that assume the same lifetime but are not kept strictly in sync.

Once `assocStableUnits[unit]` is deleted while the identical object is still reachable via `assocStableUnitsByMci[mci]`, any consumer that walks `assocStableUnitsByMci` and cross-references `assocStableUnits` gets a "torn" state. `getFinalTps()` performs exactly this cross-check and `throw`s a hard `Error` if the two do not point to the same object: [5](#0-4) 

This is invoked from consensus-critical stabilization code: [6](#0-5) 

and `assocStableUnitsByMci` is also read directly (without any consistency guard) by fee/TPS logic reachable from ordinary unit validation, e.g. `getCurrentTps()`: [7](#0-6) 

which is invoked from `validateTpsFee()` on every posted unit after the v4 upgrade: [8](#0-7) 

### Impact Explanation
If the two caches ever diverge (stale/removed reference retained in one but not the other, or vice versa), the consequences are consensus-relevant:
- `getFinalTps`/`getMcUnitProps`/`getCurrentTps` can throw an uncaught `Error` from inside unit stabilization or unit-validation code paths that are executed by every full node processing new units — a crash here halts stabilization/validation on that node, i.e. "a network unable to confirm new units" if enough nodes hit the same divergence, or "node disagreement on validity or stability" if only some nodes crash/diverge while others don't.
- If instead of throwing, stale data were read (e.g., a node whose caches got out of sync without hitting the `!==` check because the stale unit was pruned from `assocStableUnitsByMci` object identity but the timestamp/mci fields are stale), TPS-fee and stability computations that feed directly into unit validation (`validateTpsFee`) could produce incorrect results, potentially permitting a unit to pass fee/stability checks that should have been rejected — a disagreement between nodes about validity.

This matches the CVE's "dangling pointer dereferenced/written to" pattern in impact category, translated to JS: instead of memory corruption, the impact is thrown exceptions in consensus code or use of inconsistent cached props, which are the concrete impacts called out in the validation rules (node disagreement on validity/stability, network unable to confirm new units).

### Likelihood Explanation
This is not directly triggerable by a crafted single unit in one shot — it depends on timing between `shrinkCache()`'s `setInterval` invocation (every 5 minutes) and normal chain progress, and on whether the assumed contiguity/consistency invariant between `assocStableUnits` and `assocStableUnitsByMci` can actually be violated under real operating conditions (e.g., heavy catchup activity, node restart mid-shrink, or archived/forgotten units altering the unit sets unioned in `shrinkCache`). I could not fully verify from the available code slices whether `arrUnits` in `shrinkCache` and the `assocStableUnitsByMci` contiguous-sweep boundary (`top_mci`) are always guaranteed to be perfectly consistent in all code paths (e.g., interaction with `forgetUnit`/`archiveJointAndDescendants`, which also delete from `assocStableUnits` independently and can throw if the unit is still stable). Given the amount of defensive `throw Error` consistency checks already present in this exact area of the code (`getFinalTps`, `readUnitProps`, `goUpFromUnit`), the developers appear aware this aliasing is fragile, which raises confidence that a genuine divergence path exists but lowers confidence that it is trivially or remotely triggerable by an external unprivileged actor without specific timing/load conditions.

### Recommendation
- Stop aliasing raw object references between `assocStableUnits` and `assocStableUnitsByMci` (and `assocBestChildren`/`assocUnstableUnits`); store immutable snapshots or maintain a single source of truth with the other structures holding only unit ids, resolved through the canonical map at read time.
- If reference-sharing must be kept for performance, make `shrinkCache()` prune `assocStableUnitsByMci` using the exact same `arrUnits`/`top_mci` result set used to prune `assocStableUnits`, rather than an independent contiguous MCI sweep that assumes no gaps.
- Replace the `throw Error` "sanity check" in `getFinalTps` with defensive self-healing (e.g., resync the stale array entry from `assocStableUnits`, or skip it) so any residual divergence degrades gracefully instead of crashing consensus-critical code.
- Add regression tests that force `shrinkCache()` to run concurrently with `stabilizeMci`/`markMcIndexStable` under non-contiguous MCI conditions to confirm the two caches never diverge.

### Proof of Concept
Not independently reproducible from static analysis alone; would require orchestrating: (1) a long-running node accumulating > `MAX_ITEMS_IN_CACHE` (300) cached stable/unstable units, (2) triggering `shrinkCache()`'s `setInterval` while `initStableUnits`/`markMcIndexStable` concurrently populate `assocStableUnitsByMci` with an MCI bucket that becomes a gap relative to the `arrUnits` result used in the per-unit deletion loop, then (3) calling `getFinalTps`/`getCurrentTps` (naturally invoked via posting any unit after `v4UpgradeMci`, through `validateTpsFee` and `stabilizeMci`) to observe the `throw Error` "different objects for unit ..." from `getFinalTps` (storage.js:1226) or the `no stable units at last stable mci` throw in `getCurrentTps` (storage.js:1384), demonstrating the divergence between the two aliased caches crashing unit validation/stabilization.

### Citations

**File:** storage.js (L1219-1234)
```javascript
	let countAll = 0;
	let vAll = {};
	for (let i = mci; i > last_ball_mci; i--) {
		for (let u of assocStableUnitsByMci[i]) {
			if (u.bAA)
				continue;
			if (assocStableUnits[u.unit] !== u)
				throw Error(`different objects for unit ${u.unit}: equal = ${_.isEqual(u, assocStableUnits[u.unit])}, assocStableUnitsByMci[${i}][n] = ${JSON.stringify(u)}, assocStableUnits[${u.unit}] = ${JSON.stringify(assocStableUnits[u.unit])}`);
			countAll += 1 + (u.count_aa_responses || 0);
			vAll[u.unit] = 1 + (u.count_aa_responses || 0);
		}
	}
	if (countAll < count)
		throw Error(`getFinalTps ${unit} countAll=${countAll} < count=${count}, count consists of \n${JSON.stringify(visited)}\n, countAll consists of\n${JSON.stringify(vAll)}`);
	if (objUnitProps.parent_units.length === 1 && countAll !== count)
		throw Error(`getFinalTps ${unit} single parent countAll=${countAll} != count=${count}, count consists of \n${JSON.stringify(visited)}\n, countAll consists of\n${JSON.stringify(vAll)}`);
```

**File:** storage.js (L1381-1389)
```javascript
	if (shift === 0) {
		const arrLastStableUnitProps = assocStableUnitsByMci[last_stable_mci];
		if (!arrLastStableUnitProps)
			throw Error(`getCurrentTps: no stable units at last stable mci ${last_stable_mci}`);
		for (let { timestamp } of arrLastStableUnitProps) {
			if (timestamp > since_timestamp)
				since_timestamp = timestamp;
		}
	}
```

**File:** storage.js (L2264-2296)
```javascript
	if (min_retrievable_mci === null)
		throw Error(`min_retrievable_mci no initialized yet`);
	readLastStableMcIndex(db, function(last_stable_mci){
		const top_mci = Math.min(min_retrievable_mci, last_stable_mci - constants.COUNT_MC_BALLS_FOR_PAID_WITNESSING - 10);
		for (var mci = top_mci-1; true; mci--){
			if (assocStableUnitsByMci[mci])
				delete assocStableUnitsByMci[mci];
			else
				break;
		}
		var CHUNK_SIZE = 500; // there is a limit on the number of query params
		for (var offset=0; offset<arrUnits.length; offset+=CHUNK_SIZE){
			// filter units that became stable more than 100 MC indexes ago
			db.query(
				"SELECT unit FROM units WHERE unit IN(?) AND main_chain_index<? AND main_chain_index!=0", 
				[arrUnits.slice(offset, offset+CHUNK_SIZE), top_mci], 
				function(rows){
					console.log('will remove '+rows.length+' units from cache, top mci = ' + top_mci);
					rows.forEach(function(row){
						delete assocKnownUnits[row.unit];
						delete assocCachedUnits[row.unit];
						delete assocBestChildren[row.unit];
						delete assocStableUnits[row.unit];
						delete assocCachedUnitAuthors[row.unit];
						delete assocCachedUnitWitnesses[row.unit];
					});
				}
			);
		}
		unlock();
	});
}
setInterval(shrinkCache, 300*1000);
```

**File:** storage.js (L2370-2373)
```javascript
					assocStableUnits[row.unit] = row;
					if (!assocStableUnitsByMci[row.main_chain_index])
						assocStableUnitsByMci[row.main_chain_index] = [];
					assocStableUnitsByMci[row.main_chain_index].push(row);
```

**File:** main_chain.js (L1262-1286)
```javascript
// marks the MCI stable, executes triggers, and updates tps fees
async function stabilizeMci(mci) {
	const conn = await db.takeConnectionFromPool();
	await conn.query("BEGIN");
	const batch = kvstore.batch();
	const count_aa_triggers = await markMcIndexStable(conn, batch, mci);
	await util.promisify(batch.write.bind(batch))({ sync: true });
	await conn.query("COMMIT");
	conn.release();
	if (count_aa_triggers > 0) {
		console.log(`executing ${count_aa_triggers} AA triggers after stabilizing MCI ${mci}`);
		// every trigger takes its own db connection
		const aa_composer = require("./aa_composer.js");
		await aa_composer.handleAATriggers();
	}
	if (mci >= constants.v4UpgradeMci) {
		console.log(`updating tps fees after stabilizing MCI ${mci}`);
		// get a new connection to write tps fees
		const conn = await db.takeConnectionFromPool();
		await conn.query("BEGIN");
		await storage.updateTpsFees(conn, [mci]);
		await conn.query("COMMIT");
		conn.release();
	}
}
```

**File:** main_chain.js (L1294-1303)
```javascript
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
```

**File:** validation.js (L1050-1076)
```javascript
async function validateTpsFee(conn, objJoint, objValidationState, callback) {
	if (objValidationState.last_ball_mci < constants.v4UpgradeMci || !objValidationState.last_ball_mci)
		return callback();
	const objUnit = objJoint.unit;
	if (objValidationState.bAA) {
		if ("tps_fee" in objUnit)
			return callback("tps_fee in AA response");
		return callback();
	}
	if ("content_hash" in objUnit) // tps_fee and other unit fields have been already stripped
		return callback();
	const objUnitProps = {
		unit: objUnit.unit,
		parent_units: objUnit.parent_units,
		best_parent_unit: objValidationState.best_parent_unit,
		last_ball_unit: objUnit.last_ball_unit,
		timestamp: objUnit.timestamp,
		count_primary_aa_triggers: objValidationState.count_primary_aa_triggers,
		max_aa_responses: objUnit.max_aa_responses,
	};
	const count_units = storage.getCountUnitsPayingTpsFee(objUnitProps);
	const min_tps_fee = await storage.getLocalTpsFee(conn, objUnitProps, count_units);
	console.log('validation', {min_tps_fee}, objUnitProps)
	
	// compare against the current tps fee or soft-reject
	const current_tps_fee = objJoint.ball ? 0 : storage.getCurrentTpsFee(0, count_units); // very low while catching up
	const min_acceptable_tps_fee_multiplier = objJoint.ball ? 0 : storage.getMinAcceptableTpsFeeMultiplier();
```
