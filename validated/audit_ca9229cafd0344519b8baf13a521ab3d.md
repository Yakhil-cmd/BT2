### Title
Unsynchronized async cache eviction in `shrinkCache` can race with unit validation/stability caches - ([File: storage.js])

### Summary
The Chrome CVE describes a use-after-free where an object is freed by the garbage collector while another part of the program still holds and dereferences a stale pointer to it. The closest reachable analog in `ocore` is `shrinkCache()` in `storage.js`, which releases the process-wide write mutex before its asynchronous cache-eviction queries actually complete, allowing concurrently-running validation code to read/write in-memory unit caches (`assocKnownUnits`, `assocCachedUnits`, `assocStableUnits`, `assocCachedUnitAuthors`, `assocCachedUnitWitnesses`, `assocBestChildren`) while they are being mutated out from under it.

### Finding Description
`shrinkCache()` takes the global `"write"` mutex, then for each 500-unit chunk issues `db.query(...)` calls whose callbacks perform `delete assocKnownUnits[row.unit]`, `delete assocCachedUnits[row.unit]`, etc. Critically, these `db.query` calls inside the `for` loop are fired without being awaited/sequenced, and `unlock()` is invoked immediately after the loop, not inside the final query's callback: [1](#0-0) 

Because `unlock()` runs synchronously right after issuing the async `db.query` calls, the mutex is released while cache-clearing callbacks are still pending. This means the mutex offers no real protection window for the underlying delete operations: other units in the process (validation triggered from `network.js`'s `handleJoint`, `readStaticUnitProps`, `readUnitAuthors`, `isKnownUnit`) can proceed to read `assocCachedUnits[unit]` / `assocCachedUnitAuthors[unit]` at the exact moment a `delete` fires for that same key, and rely on stale references to properties objects (`props`) that were already spliced out of the cache map, or repopulate the cache with new state that then gets clobbered by the delayed delete from an older, already-superseded chunk.

This is conceptually analogous to a UAF: a cached object handed out by `readStaticUnitProps` (via `handleProps(props)`) is a bare object reference stored only by cache key; once `shrinkCache`'s pending delete callback fires, the reference is severed from the cache map (freed) while validation logic executing concurrently may still be holding and reasoning about it, or may re-fetch expecting consistent state and get a corrupted view (e.g., resurrected via a fresh `conn.query` and then deleted a moment later by the stale `shrinkCache` callback), producing state divergence between nodes evaluating the same unit's stability/parent chain.

### Impact Explanation
If two nodes experience different timing of `shrinkCache` racing with concurrent validation, they can end up with divergent in-memory unit caches (`assocCachedUnits`, `assocStableUnits`, `assocBestChildren`) feeding stability determination (`determineIfStableInLaterUnitsAndUpdateStableMcFlag`) and parent-selection logic (`determineBestParent`, `buildListOfMcUnitsWithPotentiallyDifferentWitnesslists`). Divergent caches for `witness_list_unit`, `best_parent_unit`, or stable-unit membership can cause a node to disagree with the rest of the network on unit validity/stability, which the scan rules explicitly recognize as impactful (node disagreement on validity or stability).

### Likelihood Explanation
`shrinkCache` runs automatically every 5 minutes (`setInterval(shrinkCache, 300*1000)`), so the race window recurs continuously without requiring privileged access. Triggering concurrent unit posting/validation during that window (an unprivileged unit poster can always broadcast units) is sufficient to line up the timing; this only requires normal usage plus cache size exceeding `MAX_ITEMS_IN_CACHE`. Exploiting the exact corruption deterministically is timing-dependent and requires a large cache and precise interleaving, so likelihood is real but not trivial.

### Recommendation
Refactor `shrinkCache()` so that `unlock()` is called only after all chunked `db.query` deletions have completed (e.g., via `async.eachSeries`/`Promise.all` awaited before unlocking), ensuring the write mutex genuinely serializes cache eviction against concurrent cache reads/writes performed during unit validation.

### Proof of Concept
1. Grow `assocCachedUnits`/`assocKnownUnits` past `MAX_ITEMS_IN_CACHE` by posting many units so `shrinkCache` performs real work on its next 5-minute tick.
2. At the moment `shrinkCache` is between issuing its `db.query` chunk calls and their callbacks completing, post a new unit that triggers `validateParents`/`buildListOfMcUnitsWithPotentiallyDifferentWitnesslists`, which calls `readStaticUnitProps(conn, unit, ...)` for a unit currently queued for deletion in `shrinkCache`.
3. Because `unlock()` in `shrinkCache` was already called (line 2293) before the deletion callbacks (lines 2280-2291) ran, the concurrent validation path is not blocked by the mutex and can observe the cache in an inconsistent state — either reading a props object right before it's deleted, or repopulating `assocCachedUnits[unit]` via `conn.query` (storage.js lines 2174-2183) just before the stale `shrinkCache` callback deletes the freshly repopulated entry, silently dropping cached state and forcing inconsistent subsequent DB re-reads across concurrently validating code paths. [2](#0-1)

### Citations

**File:** storage.js (L2250-2296)
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
}
setInterval(shrinkCache, 300*1000);
```
