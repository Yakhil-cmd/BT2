### Title
Stale in-memory unit-cache references used after intervening async DB/cache mutations during MC stabilization — potential node divergence on unit validity - ([File: main_chain.js])

### Summary
The Linux advisory describes a bug class where a reference obtained while iterating a shared collection is used again after the enclosing critical section that guaranteed its validity has ended — a stale-reference/TOCTOU pattern. `ocore` is single-threaded but uses callback/async interleaving with a custom advisory-lock library (`mutex.js`) rather than true mutual exclusion of in-memory caches, so the same *class* of bug — dereferencing a cached object after other async code has had a chance to mutate or delete it — can occur across `storage.assocUnstableUnits` / `assocStableUnits`.

### Finding Description
`main_chain.js`'s `propagateFinalBad()` reads a set of spending units from the DB and then, in the callback, unconditionally dereferences the in-memory caches populated earlier: [1](#0-0) 

```
rows.forEach(function (row) {
    var unit = row.unit;
    if (row.main_chain_index === mci) {
        if (storage.assocStableUnits[unit].sequence !== 'final-bad') {
            storage.assocStableUnits[unit].sequence = 'final-bad';
            ...
        }
    }
    else {
        storage.assocUnstableUnits[unit].sequence = 'final-bad';
        delete storage.assocUnstableMessages[unit];
    }
});
```

This is invoked from `markMcIndexStable()` [2](#0-1) , which itself does an initial synchronous `for...in storage.assocUnstableUnits` pass, then issues several `conn.query` async calls (`UPDATE units...`, `SELECT * FROM units WHERE main_chain_index=... sequence!='good'`, `SELECT DISTINCT inputs.unit...`) before finally touching the caches again in `propagateFinalBad`. Between the initial synchronous snapshot and these later cache accesses, the Node event loop can run other queued callbacks (e.g. `storage.forgetUnit()` / `archiving.generateQueriesToArchiveJoint()` invoked from `joint_storage.js`'s `purgeUncoveredNonserialJoints` [3](#0-2) , or `storage.resetMemory()` triggered on a write rollback in `writer.js` [4](#0-3) ), which can delete or reset entries in `assocUnstableUnits`/`assocStableUnits`/`assocUnstableMessages` via `forgetUnit()` [5](#0-4) .

Unlike `readUnitProps()`, which explicitly re-checks and reconciles cache vs. DB state after an async gap (see the comment "the unit could become stable after the check above...") [6](#0-5) , `propagateFinalBad` performs **no existence or consistency check** before mutating `storage.assocUnstableUnits[unit].sequence` / `storage.assocStableUnits[unit].sequence`. If the referenced cache entry was deleted or replaced in the interim (analogous to using a stale RCU-protected pointer after the read-side critical section ended), this either throws (`Cannot read properties of undefined`), silently no-ops the final-bad propagation, or corrupts a live object shared with other in-flight computations (e.g. `assocBestChildren`, `readUnitProps` consistency checks), producing divergent validity/finality state between nodes that process the interleaving differently.

### Impact Explanation
If two nodes process the interleaving of "stabilize MCI → propagate final-bad to descendants" and "purge/archive/forget an uncovered non-serial unit" in different orders (which is plausible because `markMcIndexStable` does not hold the `["write"]` mutex across its full duration while `purgeUncoveredNonserialJointsUnderLock` requires both `purge_uncovered` and `handleJoint`), one node may crash (uncaught exception on `.sequence` of `undefined`, halting a node's ability to process new units and confirm the DAG) while another proceeds normally, or may silently fail to mark a spending unit `final-bad`, leaving inconsistent `sequence`/`is_unique` state between the DB and in-memory cache used for further validation — a node-disagreement-on-validity condition. This matches the required impact class ("node disagreement on validity or stability" / "network unable to confirm new units").

### Likelihood Explanation
Reaching `propagateFinalBad` requires only that an attacker post a unit that becomes non-serial/`final-bad` at some MCI (an ordinary double-spend attempt by any unprivileged unit poster triggers `handleNonserialUnits`/`propagateFinalBad`), which is a routine, cheap, and always-available code path — no special privilege is required. However, exploiting the race requires the concurrent purge/archive/reset path to interleave at exactly the right callback boundary, which depends on timing/queue state that is hard to guarantee deterministically from a single crafted unit. I was not able to fully trace whether `markMcIndexStable`'s caller always holds the `handleJoint` lock for its entire duration (this would need to be confirmed by tracing every caller of `stabilizeMci`/`advanceMcStability`/`updateMainChain` and every acquirer of `handleJoint`/`write` to rule out interleaving); this uncertainty lowers confidence from High to Medium.

### Recommendation
- Re-validate the presence of `storage.assocUnstableUnits[unit]` / `storage.assocStableUnits[unit]` immediately before mutating them in `propagateFinalBad`, falling back to a DB re-read (as `readUnitProps` already does) if the cache entry is missing or already forgotten, rather than assuming the previously-fetched row snapshot is still valid.
- Ensure `markMcIndexStable`/`propagateFinalBad` execute fully under the `["write"]` (and/or `["handleJoint"]`) mutex so that no other code path can call `forgetUnit`/`resetMemory` while cached unit objects are being read and mutated across multiple asynchronous `conn.query` boundaries.
- Add the same kind of defensive `_.isEqual` cache/DB consistency assertion already used elsewhere in `storage.js` (e.g. in `readUnitProps`) to `propagateFinalBad` and similar cache-touching callbacks in `main_chain.js`, so a stale reference triggers a loud, diagnosable error rather than either silent corruption or an unhandled crash mid-transaction.

### Proof of Concept
Not directly reproducible without live timing control over Node's callback queue; the following describes the conceptual trigger sequence:
1. An unprivileged unit poster crafts two conflicting (double-spend) units so that one becomes `temp-bad`/`final-bad` for a given input at MCI `m`, causing `markMcIndexStable(mci=m)` to invoke `handleNonserialUnits` → `propagateFinalBad`.
2. Concurrently (interleaved via the async callback queue while `markMcIndexStable`'s multiple `conn.query` calls are pending, and while the `["write"]`/`["handleJoint"]` mutex is not held across the full sequence), trigger `purgeUncoveredNonserialJointsUnderLock()` [7](#0-6)  (naturally scheduled) or a write-rollback path in `writer.js` that calls `storage.resetMemory()` [4](#0-3) , causing `storage.forgetUnit()` to delete the entry for one of the spending units from `assocUnstableUnits`.
3. When `propagateFinalBad`'s `rows.forEach` callback executes, `storage.assocUnstableUnits[unit]` is `undefined` for the forgotten unit, and `storage.assocUnstableUnits[unit].sequence = 'final-bad'` throws, or (if instead re-populated with a different object due to a cache reset) silently mutates the wrong/new object, producing state that diverges from the DB's `sequence` column and from other nodes.

### Citations

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

**File:** main_chain.js (L1394-1407)
```javascript
				var arrNewBadUnitsOnSameMci = [];
				rows.forEach(function (row) {
					var unit = row.unit;
					if (row.main_chain_index === mci) { // on the same MCI that we've just stabilized
						if (storage.assocStableUnits[unit].sequence !== 'final-bad') {
							storage.assocStableUnits[unit].sequence = 'final-bad';
							arrNewBadUnitsOnSameMci.push(unit);
						}
					}
					else { // on a future MCI
						storage.assocUnstableUnits[unit].sequence = 'final-bad';
						delete storage.assocUnstableMessages[unit];
					}
				});
```

**File:** joint_storage.js (L219-228)
```javascript
function purgeUncoveredNonserialJointsUnderLock(){
	mutex.lockOrSkip(["purge_uncovered"], function(unlock){
		mutex.lock(["handleJoint"], function(unlock_hj){
			purgeUncoveredNonserialJoints(false, function(){
				unlock_hj();
				unlock();
			});
		});
	});
}
```

**File:** joint_storage.js (L252-277)
```javascript
			mutex.lock(["write"], function(unlock) {
				db.takeConnectionFromPool(function (conn) {
					async.eachSeries(
						rows,
						function (row, cb) {
							breadcrumbs.add("--------------- archiving uncovered unit " + row.unit);
							storage.readJoint(conn, row.unit, {
								ifNotFound: function () {
									throw Error("nonserial unit not found?");
								},
								ifFound: function (objJoint) {
									var arrQueries = [];
									conn.addQuery(arrQueries, "BEGIN");
									archiving.generateQueriesToArchiveJoint(conn, objJoint, 'uncovered', arrQueries, function(){
										conn.addQuery(arrQueries, "COMMIT");
										// sql goes first, deletion from kv is the last step
										async.series(arrQueries, function(){
											kvstore.del('j\n'+row.unit, function(){
												breadcrumbs.add("------- done archiving "+row.unit);
												var parent_units = storage.assocUnstableUnits[row.unit].parent_units;
												storage.forgetUnit(row.unit);
												storage.fixIsFreeAfterForgettingUnit(parent_units);
												cb();
											});
										});
									});
```

**File:** writer.js (L708-713)
```javascript
								if (err) {
									var headers_commission = require("./headers_commission.js");
									headers_commission.resetMaxSpendableMci();
									delete storage.assocUnstableMessages[objUnit.unit];
									await storage.resetMemory(conn);
								}
```

**File:** storage.js (L1526-1551)
```javascript
			if (props.is_stable) {
				console.log('caching stable unit', unit, 'already cached =', !!assocStableUnits[unit]);
				// the unit could become stable after the check above and be added to assocStableUnits
				if (assocStableUnits[unit]) {
					let props2 = _.cloneDeep(assocStableUnits[unit]);
					delete props2.parent_units;
					if (!_.isEqual(props2, props))
						throw Error(`different props: assocStableUnits[unit]=${JSON.stringify(props2)}, props=${JSON.stringify(props)}`);
					return handleProps(assocStableUnits[unit]);
				}
				if (props.sequence === 'good') // we don't cache final-bads as they can be voided later
					assocStableUnits[unit] = props;
				// we don't add it to assocStableUnitsByMci as all we need there is already there
			}
			else{
				if (!assocUnstableUnits[unit])
					throw Error("no unstable props of "+unit);
				var props2 = _.cloneDeep(assocUnstableUnits[unit]);
				delete props2.parent_units;
				delete props2.assocEarnedHeadersCommissionRecipients;
			//	delete props2.bAA;
				if (!_.isEqual(props, props2)) {
					debugger;
					throw Error("different props of "+unit+", mem: "+JSON.stringify(props2)+", db: "+JSON.stringify(props)+", stack "+stack);
				}
			}
```

**File:** storage.js (L2209-2232)
```javascript
function forgetUnit(unit){
	console.log('forgetting unit '+unit);
	if (!conf.bLight){
		console.log('parents', assocUnstableUnits[unit].parent_units);
		assocUnstableUnits[unit].parent_units.forEach(function(parent_unit){
			console.log('parent '+parent_unit+' best children', JSON.stringify(assocBestChildren[parent_unit]));
			if (assocBestChildren[parent_unit] && assocBestChildren[parent_unit].indexOf(assocUnstableUnits[unit]) >= 0){
				console.log('before pull', assocBestChildren[parent_unit]);
				_.pull(assocBestChildren[parent_unit], assocUnstableUnits[unit]);
				console.log('after pull', assocBestChildren[parent_unit]);
			}
		});
	}
	delete assocKnownUnits[unit];
	delete assocCachedUnits[unit];
	delete assocCachedUnitAuthors[unit];
	delete assocCachedUnitWitnesses[unit];
	delete assocUnstableUnits[unit];
	if (!conf.bLight && assocStableUnits[unit])
		throw Error("trying to forget stable unit "+unit);
	delete assocStableUnits[unit];
	delete assocUnstableMessages[unit];
	delete assocBestChildren[unit];
}
```
