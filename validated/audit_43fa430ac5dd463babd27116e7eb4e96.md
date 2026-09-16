## Title
Race condition in `shrinkCache()` releases the `write` mutex before its own pending cache-purge queries complete, allowing a NULL/`undefined` dereference on shared unit caches - (File: `storage.js`)

### Summary
`storage.js`'s periodic `shrinkCache()` takes the global `"write"` mutex, fires a batch of async `db.query()` calls that will later delete entries from the shared in-memory caches (`assocKnownUnits`, `assocCachedUnits`, `assocBestChildren`, `assocStableUnits`, `assocCachedUnitAuthors`, `assocCachedUnitWitnesses`), but calls `unlock()` immediately after *scheduling* those queries instead of after they complete: [1](#0-0) . This mirrors the CVE-2024-24855 pattern (an "unregister" path racing a "rescan" path over a record that is freed/nulled mid-flight, causing a NULL-pointer dereference), except here it is the JS in-memory unit-property cache that gets nulled out from under other, correctly-locked writer code.

### Finding Description
`shrinkCache()`:
```js
const unlock = await mutex.lock("write");
...
readLastStableMcIndex(db, function(last_stable_mci){
    ...
    for (var offset=0; offset<arrUnits.length; offset+=CHUNK_SIZE){
        db.query(..., function(rows){
            rows.forEach(function(row){
                delete assocKnownUnits[row.unit];
                delete assocCachedUnits[row.unit];
                delete assocBestChildren[row.unit];
                delete assocStableUnits[row.unit];
                delete assocCachedUnitAuthors[row.unit];
                delete assocCachedUnitWitnesses[row.unit];
            });
        });
    }
    unlock();   // <-- released before the db.query callbacks above have fired
});
``` [2](#0-1) 

`unlock()` is invoked synchronously right after the `for` loop that only *schedules* the `db.query` calls; it does not wait for their callbacks. This releases the `"write"` mutex while multiple cache-delete operations are still pending on the event loop.

Every other writer that mutates the exact same caches takes the same `"write"` lock and assumes exclusive access while it holds it, e.g. `main_chain.js`'s `markMcIndexStable()`/`propagateFinalBad()` writes directly into `storage.assocStableUnits[unit].sequence` and `storage.assocUnstableUnits[unit]` [3](#0-2) , and `forgetUnit()` unconditionally dereferences `assocUnstableUnits[unit].parent_units` [4](#0-3) .

Because `shrinkCache()`'s `unlock()` fires before its own deferred deletes run, a second writer (e.g. unit-save/stabilization triggered by an ordinary unit post) can acquire the `"write"` lock and legitimately mutate/re-populate `assocStableUnits`/`assocUnstableUnits` for a unit while shrinkCache's stale, already-scheduled `db.query` callback for that very unit is still in flight. When that callback finally executes, it blindly `delete`s the entry regardless of what the concurrently-run writer just did with it. Any later code path (including code running under the very next `"write"`-lock holder, or code that assumes `assocStableUnits[unit]`/`assocUnstableUnits[unit]` is still populated once cached) that then dereferences a property on the now-missing object throws `TypeError: Cannot read properties of undefined`, which is an unhandled/thrown error in this codebase (`throw Error(...)` patterns are used pervasively around these same caches, e.g. `main_chain.js:104`, `storage.js:1542`), crashing the node process.

### Impact Explanation
An uncaught exception from dereferencing a deleted cache entry crashes the Node.js process outright (no domain/try-catch recovery around these hot paths). Because `"write"` is the same global lock guarding unit-save/stabilization for every incoming unit, a crash here stops the node from validating/saving any further units, i.e., "a network unable to confirm new units" if this hits enough full/witness nodes running the periodic `shrinkCache()` (`setInterval(shrinkCache, 300*1000)` [5](#0-4) ) concurrently with normal unit traffic.

### Likelihood Explanation
`shrinkCache()` only does meaningful work once caches exceed `MAX_ITEMS_IN_CACHE`, which naturally happens on active full nodes over time, and it is invoked automatically every 300 seconds without any external trigger needed. An attacker only needs to keep the network busy (posting ordinary units, which any unprivileged actor can do) to increase the number of units being stabilized/cached during the window in which `shrinkCache()`'s deferred deletes are still pending after its early `unlock()`, raising the probability of the interleaving needed to hit the dangling-reference deref.

### Recommendation
Move `unlock()` in `shrinkCache()` so it is only called after all scheduled `db.query` chunk callbacks have completed (e.g., via `async.each`/`Promise.all` over the chunk queries, calling `unlock()` in the final completion callback), so the `"write"` lock is genuinely held for the whole duration that the shared caches are being mutated.

### Proof of Concept
1. Run a full node long enough (or synthetically lower `MAX_ITEMS_IN_CACHE`) so `shrinkCache()`'s `if` guard is satisfied and its cache-shrink path executes.
2. While `shrinkCache()`'s `db.query` calls for chunked `arrUnits` are in flight (after its early `unlock()`), have another actor post/broadcast a new unit that causes `main_chain.js`'s `markMcIndexStable()`/`propagateFinalBad()` or `storage.forgetUnit()` to run, mutating/removing/adding entries for the same units in `assocStableUnits`/`assocUnstableUnits` under the (now separately re-acquired) `"write"` lock.
3. When the earlier `shrinkCache()` `db.query` callback fires and deletes `assocStableUnits[unit]`/`assocUnstableUnits[unit]` for a unit that the interleaved writer just touched or is about to touch, any subsequent access such as `storage.assocStableUnits[row.unit].sequence = 'good'` (main_chain.js) or `assocUnstableUnits[unit].parent_units` (storage.js `forgetUnit`) throws on `undefined`, crashing the node process.

### Citations

**File:** storage.js (L2209-2226)
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
```

**File:** storage.js (L2250-2294)
```javascript
async function shrinkCache(){
	if (Object.keys(assocCachedAssetInfos).length > MAX_ITEMS_IN_CACHE)
		assocCachedAssetInfos = {};
	console.log(Object.keys(assocUnstableUnits).length+" unstable units");
	var arrKnownUnits = Object.keys(assocKnownUnits);
	var arrPropsUnits = Object.keys(assocCachedUnits);
	var arrStableUnits = Object.keys(assocStableUnits);
	var arrAuthorsUnits = Object.keys(assocCachedUnitAuthors);
	var arrWitnessesUnits = Object.keys(assocCachedUnitWitnesses);
	if (arrPropsUnits.length < MAX_ITEMS_IN_CACHE && arrAuthorsUnits.length < MAX_ITEMS_IN_CACHE && arrWitnessesUnits.length < MAX_ITEMS_IN_CACHE && arrKnownUnits.length < MAX_ITEMS_IN_CACHE && arrStableUnits.length < MAX_ITEMS_IN_CACHE)
		return console.log('cache is small, will not shrink');
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

**File:** storage.js (L2296-2296)
```javascript
setInterval(shrinkCache, 300*1000);
```

**File:** main_chain.js (L1337-1359)
```javascript
							conn.query("UPDATE units SET sequence=? WHERE unit=?", [sequence, row.unit], function(){
								if (sequence === 'good')
									conn.query("UPDATE inputs SET is_unique=1 WHERE unit=?", [row.unit], function(){
										storage.assocStableUnits[row.unit].sequence = 'good';
										cb();
									});
								else{
									arrFinalBadUnits.push(row.unit);
									// treat this unit as a non-existent competitor from now on
									conn.query("UPDATE inputs SET is_unique=NULL WHERE unit=?", [row.unit], function(){
										setContentHash(row.unit, cb);
									});
								}
							});
						});
					},
					function(){
						//if (rows.length > 0)
						//    throw "stop";
						// next op
						arrFinalBadUnits.forEach(function(unit){
							storage.assocStableUnits[unit].sequence = 'final-bad';
						});
```
