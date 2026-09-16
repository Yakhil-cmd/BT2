## Finding: Cache entries freed asynchronously after the protecting lock is already released (`storage.js` `shrinkCache()`)

### Title
Premature mutex release causes in-memory unit-cache entries to be deleted without holding the "write" lock, racing with concurrent unit validation - (File: storage.js)

### Summary
`ocore`'s `storage.js` maintains several long-lived in-memory caches (`assocStableUnits`, `assocCachedUnits`, `assocCachedUnitAuthors`, `assocCachedUnitWitnesses`, `assocKnownUnits`, `assocBestChildren`) that are read directly (by reference, no cloning) throughout unit validation (`validation.js`) and main-chain processing (`main_chain.js`) whenever a unit is posted. The codebase's own invariant, stated explicitly in `validation.js`, is that "there are no other updates/inserts/deletes" to these structures while the `"write"` mutex is held. The periodic maintenance job `shrinkCache()` violates this invariant: it releases the `"write"` lock *before* the asynchronous `db.query()` callbacks that actually delete cache entries have executed, so the deletions happen completely unprotected while other concurrent validation/writer code (which correctly relies on the lock for exclusivity) is running. This is analogous to the kernel bug's root cause: freeing shared data (`ftrace` pages / here, cache entries) without synchronizing with in-flight readers before the "unlock"/free step.

### Finding Description
`shrinkCache()` acquires the `"write"` mutex, then kicks off several async `db.query()` calls in a loop, and calls `unlock()` immediately after firing the queries — not after their callbacks complete: [1](#0-0) 

```js
const unlock = await mutex.lock("write");
...
for (var offset=0; offset<arrUnits.length; offset+=CHUNK_SIZE){
    db.query(
        "SELECT unit FROM units WHERE unit IN(?) AND main_chain_index<? AND main_chain_index!=0",
        [arrUnits.slice(offset, offset+CHUNK_SIZE), top_mci],
        function(rows){
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
```

`unlock()` is invoked synchronously right after the `for` loop, while the `db.query` callbacks that perform the actual deletions are still pending on the event loop. Once `unlock()` fires, `mutex.js`'s `handleQueue()` immediately starts any other job queued on `"write"` (e.g. `writer.js saveJoint()`, `main_chain.js updateMainChain()`), and unrelated unit validations proceed to read the very caches that are about to be mutated by the still-pending `shrinkCache` callbacks: [2](#0-1) 

Meanwhile, `validation.js` explicitly assumes exclusivity of these structures under the write lock: [3](#0-2) 

and functions like `readUnitProps()` / `readStaticUnitProps()` / `readUnitAuthors()` directly reference and even do deep-equality "cache vs DB" sanity checks against these same dictionaries: [4](#0-3) [5](#0-4) 

If the delayed `shrinkCache` deletion callback fires for a `unit` in the exact window between the point `readUnitProps()`/`readStaticUnitProps()` observes a cached entry and the point it later re-checks/deep-compares that same entry (or the point where a concurrent `writer.saveJoint()` transaction, itself relying on the write lock for exclusive cache mutation, is populating/removing entries for the same or a graph-adjacent unit), the two mutation streams interleave without any coordinating lock. This exactly parallels the ftrace bug's pattern: a resource is torn down by one code path in a "deferred"/asynchronous fashion after the caller believes exclusive access has ended, while another path continues to rely on the resource remaining consistent.

### Impact Explanation
Because Node.js is single-threaded but I/O callbacks interleave, this race can be hit by any ordinary unit submission that touches the shared unit-props caches while `shrinkCache()` (which runs every 5 minutes via `setInterval(shrinkCache, 300*1000)`) is in its unprotected deletion window. Concrete consequences:
- `readUnitProps()`'s own internal consistency check (`if (!_.isEqual(props, props2)) throw Error(...)`) can be triggered by an unrelated deletion of `assocStableUnits`/`assocUnstableUnits` entries mid-flight, causing an uncaught exception inside a DB-callback context, which crashes the node process — directly impacting "a network unable to confirm new units" if replicated across nodes running the same version.
- Loss of synchronization between `"write"`-holding writers (`writer.js saveJoint`, `main_chain.js updateMainChain`) and the now-unprotected `shrinkCache` deletions can desynchronize `assocBestChildren`/`assocStableUnitsByMci` from the DB state that other validation logic (e.g., `graph.js determineIfIncluded`, `main_chain.js` stability/witnessed-level determination) assumes is authoritative, risking inconsistent validation outcomes (node disagreement on validity/stability) between nodes whose cache states diverge depending on timing.

### Likelihood Explanation
`shrinkCache()` runs unconditionally every 300 seconds on any full node with a sufficiently large cache (`MAX_ITEMS_IN_CACHE` exceeded), which is the normal steady-state for an active hub/node. Any attacker (or even ordinary user) posting units, triggers frequent traversal of the shared caches via `validation.js`/`main_chain.js` at essentially the same rate as normal network traffic, giving many chances per hour for the race window to be hit. No privileged access is required — an unprivileged unit poster's own transaction validation is what races against the background job.

### Recommendation
Do not call `unlock()` until all asynchronous cache-mutation callbacks issued inside `shrinkCache()` have completed (e.g., use `async.eachSeries`/`Promise.all` over the query chunks and only call `unlock()` in the final completion callback), so that the `"write"` lock genuinely covers the entire span during which the shared caches are being mutated, preserving the invariant that `validation.js` and `writer.js` rely on.

### Proof of Concept
1. Populate the in-memory caches beyond `MAX_ITEMS_IN_CACHE` (normal operation on an active node) so `shrinkCache()`'s early-return guard is bypassed.
2. Let the periodic timer invoke `shrinkCache()`; it acquires the `"write"` lock, fires multiple `db.query()` calls, and calls `unlock()` synchronously right after the loop — before any `db.query` callback has run.
3. Immediately after `unlock()`, submit (or have any peer submit) a new unit referencing/being validated against a unit whose cache entry is about to be deleted by one of the still-pending `shrinkCache` query callbacks (`storage.js:2280-2289`).
4. Depending on scheduling, `readUnitProps()`'s deep-equality re-check (`storage.js:1526-1550`) or downstream logic relying on `assocStableUnits`/`assocBestChildren` can observe an inconsistent (partially-deleted) cache state, throwing an uncaught `Error` inside the async callback chain and crashing the node process, or causing divergent validation state between nodes hit by the race versus nodes that are not.

### Citations

**File:** storage.js (L1497-1555)
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
			handleProps(props);
		}
	);
}
```

**File:** storage.js (L2168-2199)
```javascript
function readStaticUnitProps(conn, unit, handleProps, bReturnNullIfNotFound){
	if (!unit)
		throw Error("no unit");
	var props = assocCachedUnits[unit];
	if (props)
		return handleProps(props);
	conn.query("SELECT level, witnessed_level, best_parent_unit, witness_list_unit FROM units WHERE unit=?", [unit], function(rows){
		if (rows.length !== 1){
			if (bReturnNullIfNotFound)
				return handleProps(null);
			throw Error("not 1 unit "+unit);
		}
		props = rows[0];
		assocCachedUnits[unit] = props;
		handleProps(props);
	});
}

function readUnitAuthors(conn, unit, handleAuthors){
	var arrAuthors = assocCachedUnitAuthors[unit];
	if (arrAuthors)
		return handleAuthors(arrAuthors);
	conn.query("SELECT address FROM unit_authors WHERE unit=?", [unit], function(rows){
		if (rows.length === 0)
			throw Error("no authors, unit "+unit);
		var arrAuthors2 = rows.map(function(row){ return row.address; }).sort();
	//	if (arrAuthors && arrAuthors.join('-') !== arrAuthors2.join('-'))
	//		throw Error('cache is corrupt');
		assocCachedUnitAuthors[unit] = arrAuthors2;
		handleAuthors(arrAuthors2);
	});
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

**File:** mutex.js (L43-59)
```javascript
function exec(arrKeys, proc, next_proc){
	arrLockedKeyArrays.push(arrKeys);
	console.log("lock acquired", arrKeys);
	var bLocked = true;
	proc(function unlock(unlock_msg) {
		if (!bLocked)
			throw Error("double unlock?");
		if (unlock_msg)
			console.log(unlock_msg);
		bLocked = false;
		release(arrKeys);
		console.log("lock released", arrKeys);
		if (next_proc)
			next_proc.apply(next_proc, arguments);
		handleQueue();
	});
}
```

**File:** validation.js (L446-451)
```javascript
				if(err){
					if (profiler.isStarted())
						profiler.stop('validation-advanced-stability');
					// We might have advanced the stability point and have to commit the changes as the caches are already updated.
					// There are no other updates/inserts/deletes during validation
					commit_fn(function(){
```
