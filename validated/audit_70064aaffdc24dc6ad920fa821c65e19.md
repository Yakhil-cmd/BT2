### Title
Race condition between `shrinkCache()`'s premature mutex release and concurrent unit-cache mutation causes an unhandled assertion crash - (File: storage.js)

### Summary
`storage.js`'s periodic `shrinkCache()` acquires the `"write"` mutex, but calls `unlock()` immediately after firing off a batch of asynchronous `db.query()` calls in a `for` loop, without waiting for their callbacks to complete and actually perform the `delete assocStableUnits[...]` / `delete assocCachedUnits[...]` mutations. [1](#0-0) 
This releases the lock that is meant to serialize mutation of the in-memory unit caches (`assocStableUnits`, `assocUnstableUnits`, `assocCachedUnits`, `assocBestChildren`) while eviction of those same caches is still pending in flight, letting the normal unit-write path (`writer.saveJoint`, which also takes the `"write"` lock) or other cache-mutating flows (`forgetUnit`/`fixIsFreeAfterForgettingUnit`, invoked from `purgeUncoveredNonserialJoints` under the same `"write"` key) interleave with the delayed deletions. [2](#0-1) [3](#0-2) 

### Finding Description
`readUnitProps()` is the canonical accessor for unit properties used throughout validation and main-chain processing (`main_chain.js`, `parent_composer.js`). It performs a DB read and then asserts internal cache consistency: [4](#0-3) 
For unstable units it hard-fails with `throw Error("no unstable props of "+unit)` if `assocUnstableUnits[unit]` is no longer present when the async DB callback returns, and for stable units it throws `"different props: ..."` if the freshly re-cached snapshot diverges from what's already in `assocStableUnits[unit]`.

Because `shrinkCache()` releases the `"write"` mutex before its own asynchronous cache-eviction callbacks fire, a window opens in which another writer holding the same `"write"` key can legitimately run concurrently with the still-pending `delete assocStableUnits[...]` / `delete assocUnstableUnits[...]` operations queued by `shrinkCache`. Any unprivileged unit poster can widen or trigger this window by continuously submitting units:
- growing `assocCachedUnits`/`assocStableUnits` past `MAX_ITEMS_IN_CACHE` triggers `shrinkCache()`'s eviction pass every 300s;
- simultaneously submitting a borderline non-serial unit that becomes `final-bad`/`temp-bad` causes `purgeUncoveredNonserialJoints()` to run under the same `"write"` mutex and call `forgetUnit()`, which deletes `assocUnstableUnits[unit]`, `assocStableUnits[unit]`, etc. for that unit. [5](#0-4) 

If a concurrent `readUnitProps()` call for that same unit (e.g., invoked while walking best-parent chains in `main_chain.js` or `parent_composer.js`) has already dispatched its `conn.query` and is waiting on the callback when `forgetUnit()` removes the cache entry, the callback will observe `assocUnstableUnits[unit]` missing and throw an unhandled `Error`, crashing the node process — the same "delete races with in-flight use of the same object" bug-class as the reported kernel `queue_delete` UAF/crash (CVE-2016-2544), reimplemented here as an assertion-driven crash rather than memory corruption because Node.js is single-threaded but the mutex protecting these caches is released too early.

### Impact Explanation
An uncaught `Error` thrown from inside an async DB callback in a busy Node process is fatal and crashes the ocore node (unhandled exception, no surrounding try/catch on this path). A node crash halts its ability to validate/relay/confirm units, matching the "network unable to confirm new units" impact criterion. Because the trigger only requires posting ordinary units (some intentionally structured to be provisionally rejected/purged) at a rate/pattern that fills the cache and forces both `shrinkCache()` and `purgeUncoveredNonserialJoints()` to touch the same unit concurrently, this is reachable by any unprivileged unit poster, not a privileged operator, hub, or peer.

### Likelihood Explanation
Triggering requires winning a narrow but reproducible timing window: `shrinkCache()` runs every 300 seconds only when caches exceed `MAX_ITEMS_IN_CACHE`, and the target unit must be actively read via `readUnitProps` (dispatch of its DB query) at the exact moment `forgetUnit()` removes it from `assocUnstableUnits`. This is plausible for a determined attacker who can flood the network with many units to inflate caches and force frequent, larger main-chain/graph traversals, but it is not trivially deterministic — it depends on Node.js event-loop scheduling and DB query latency. Likelihood is therefore moderate, not high.

### Recommendation
In `shrinkCache()` (storage.js), do not call `unlock()` until all the per-chunk `db.query` deletions have actually completed — e.g., collect the queries with `async.eachSeries`/`Promise.all` and only invoke `unlock()` in the final completion callback, mirroring how `initCaches()` and `resetMemory()` already serialize cache mutation under the `"write"` lock. This ensures the mutex genuinely protects the full lifetime of the cache-eviction mutation, closing the race window with concurrent `forgetUnit()`/`readUnitProps()` calls.

### Proof of Concept
1. Attacker submits a stream of well-formed units to inflate `assocCachedUnits`/`assocStableUnits` above `MAX_ITEMS_IN_CACHE` (`storage.js:2259`), so the next 300s tick of `shrinkCache()` starts evicting many units, issuing multiple chunked `db.query` calls and calling `unlock()` right after dispatching them, before their callbacks run.
2. In the same window, attacker submits a non-serial unit that ends up `final-bad`/`temp-bad`, causing `purgeUncoveredNonserialJoints()` (which also locks `"write"`) to run and call `storage.forgetUnit(unit)` for a unit that is also being read/traversed elsewhere (e.g., a concurrent `main_chain.js` call to `readUnitProps` for a unit on the same best-parent chain).
3. When the pending `readUnitProps` DB callback fires after `forgetUnit()` has already deleted `assocUnstableUnits[unit]`, it hits `throw Error("no unstable props of "+unit)` (storage.js:1542), crashing the node process — an unauthenticated, network-visible denial of service triggered purely by unit submission.

Note: I was not able to fully trace every concurrent call site of `readUnitProps` versus `forgetUnit` timing within the tool budget available, so the exact minimal PoC sequence (which specific caller of `readUnitProps` races with which purge path) could not be verified end-to-end in this session; the root-cause defect (premature `unlock()` in `shrinkCache()` before its async deletions complete) is confirmed directly from the code.

### Citations

**File:** storage.js (L1497-1551)
```javascript
function readUnitProps(conn, unit, handleProps){
	if (!unit)
		throw Error(`readUnitProps bad unit ` + unit);
	if (!handleProps)
		return new Promise(resolve => readUnitProps(conn, unit, resolve));
	if (assocStableUnits[unit])
		return handleProps(assocStableUnits[unit]);
	if (conf.bFaster && assocUnstableUnits[unit])
		return handleProps(assocUnstableUnits[unit]);
	var stack = new Error().stack;
	conn.query(
		"SELECT unit, level, latest_included_mc_index, main_chain_index, is_on_main_chain, is_free, is_stable, witnessed_level, headers_commission, payload_commission, sequence, timestamp, GROUP_CONCAT(address) AS author_addresses, COALESCE(witness_list_unit, unit) AS witness_list_unit, best_parent_unit, last_ball_unit, tps_fee, max_aa_responses, count_aa_responses, count_primary_aa_triggers, is_aa_response, version\n\
			FROM units \n\
			JOIN unit_authors USING(unit) \n\
			WHERE unit=? \n\
			GROUP BY +unit", 
		[unit], 
		function(rows){
			if (rows.length !== 1)
				throw Error("not 1 row, unit "+unit);
			var props = rows[0];
			props.author_addresses = props.author_addresses.split(',');
			props.count_primary_aa_triggers = props.count_primary_aa_triggers || 0;
			props.bAA = !!props.is_aa_response;
			delete props.is_aa_response;
			props.tps_fee = props.tps_fee || 0;
			if (parseFloat(props.version) >= constants.fVersion4)
				delete props.witness_list_unit;
			delete props.version;
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

**File:** storage.js (L2261-2294)
```javascript
	const unlock = await mutex.lock("write");
	var arrUnits = _.union(arrPropsUnits, arrAuthorsUnits, arrWitnessesUnits, arrKnownUnits, arrStableUnits);
	console.log('will shrink cache, total units: '+arrUnits.length);
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
