Found a concrete analog: `network.js`'s `light/get_definition` handler poisons a persistent, unbounded in-process cache (`definitions[params]`) with an **unconfirmed** AA definition, and that stale entry is served to every future light client until the process restarts — the same "destination/content cache never invalidated across the object's real lifecycle, served stale after a restart-adjacent condition" bug class as CVE-2023-33198's chat-channel cache.

### Title
Full node's `light/get_definition` cache permanently poisons served AA definitions with unconfirmed/mutable data - (File: network.js)

### Summary
The hub/full-node handler for `light/get_definition` caches whatever definition it resolves — including **unconfirmed** AA definitions pulled straight out of the in-flight `assocUnstableMessages` — in a process-lifetime, unbounded `definitions` object keyed only by address/chash, with no invalidation, no distinction between "stable/final" and "unstable/still-changeable" data, and no re-check against the eventually-finalized definition. [1](#0-0) 

### Finding Description
`readDefinitionByAddress`/`readDefinitionAtMci` only ever look at **stable, sequence='good'** rows [2](#0-1) , but the `light/get_definition` request handler falls back to `storage.getUnconfirmedAADefinition(params)` when no stable definition exists yet [3](#0-2) . `getUnconfirmedAADefinition` walks the in-memory `assocUnstableMessages`/`assocUnstableUnits` map and returns the `definition` payload of the first still-unstable `definition` message it finds for that address [4](#0-3) . This data is provisional: a `sequence='good'` unstable unit can still turn out to be non-serial (double-spend) or otherwise get rolled back/forgotten via `revertResponsesInCaches`/`forgetUnit` [5](#0-4) , or a different, competing `definition` message for the very same address chash could stabilize instead.

Despite this, the handler unconditionally writes the result into the never-expiring, never-invalidated `definitions[params]` cache: `if (arrDefinition) // save in cache definitions[params] = arrDefinition;` [6](#0-5) . On every subsequent `light/get_definition` request for that address, the handler short-circuits straight to the stale cached value without ever re-querying storage: `if (definitions[params]) return sendResponse(ws, tag, definitions[params]);` [7](#0-6) . There is no `setInterval` purge, no TTL, and no hook into `forgetUnit`/`revertResponsesInCaches`/`resetMemory` to clear this cache when the underlying unstable unit is forgotten or superseded — unlike other in-memory caches in `storage.js` that are explicitly purged on unit forgetting [5](#0-4)  or shrunk periodically [8](#0-7) .

This is directly analogous to the TGS chat-channel cache bug: a mutable/provisional piece of routing/definition data gets cached indefinitely and continues to be served as if it were authoritative even after the underlying source of truth has changed (here: rollback of a non-serial unit, or a competing AA-defined AA whose address chash collides via `getUnconfirmedAADefinitionsPostedByAAs`/`insertAADefinitions` composing a different final definition).

### Impact Explanation
Any unprivileged peer that posts (or gets another unprivileged peer to post) an AA-defining unit can seed this cache with a definition for a given address before it's finalized. If that unit is subsequently invalidated as non-serial/rolled back, or superseded by a conflicting definition for the same chash-derived address, every light client (wallet) that already queried `light/get_definition` for that address on that specific full node continues to receive the old, no-longer-correct definition for the remaining lifetime of the node process. Light wallets rely on this definition to validate the AA's logic/conditions locally (e.g., to decide whether a payment condition/oscript is satisfiable, or to compose transactions). A wallet acting on a stale definition can be misled about spending/authorization conditions of an address it trusted the node's answer for, producing node/wallet disagreement on validity — matching the "node disagreement on validity" impact class.

### Likelihood Explanation
Reaching this requires only posting ordinary units (an AA definition message) — no privileged role, no malicious peer/hub trust needed, and no special network position. The race window (post an AA definition, have it observed by `light/get_definition` while unstable, then have it double-spent/rolled back or overtaken by a competing definition) is realistic given ordinary non-serial/rollback handling already present in the codebase (`revertResponsesInCaches`, `forgetUnit`, `checkForDoublespends`). The impact is confined to nodes serving light clients (`bServeAsHub`/full nodes answering `light/*`), which is the normal operating mode of most publicly reachable ocore nodes.

### Recommendation
- Never persist `getUnconfirmedAADefinition` results into the long-lived `definitions[params]` cache; only cache definitions once they are confirmed stable (i.e., results from the DB `SELECT ... FROM definitions / aa_addresses` branch), matching the guarantee `readDefinitionByAddress` already provides for stable data.
- If unconfirmed definitions must be served, mark the response as unstable/tentative (similar to `light/get_definition_for_address`'s `is_stable` flag) and do not cache it, or cache it with a short TTL and hook eviction into `forgetUnit`/`revertResponsesInCaches`/unit stabilization.
- Add cache invalidation tied to unit rollback/forgetting so stale unstable data can never outlive its source unit.

### Proof of Concept
1. A light-serving full node is running with `conf.bServeAsHub` or otherwise reachable via `light/get_definition`.
2. Attacker posts unit `U1` containing a `definition` message for AA address `A` with definition `D1`, in a way that it can plausibly be non-serial (e.g., conflicting with another unit spending the same input, so it may later be excluded).
3. A light client queries `light/get_definition` for address `A` before `U1` stabilizes; `getUnconfirmedAADefinition('A')` returns `D1`, and the handler caches `definitions['A'] = D1` [3](#0-2) .
4. `U1` is later determined non-serial / rolled back (`revertResponsesInCaches` / `forgetUnit`) [5](#0-4) , or a competing unit with a different definition for the same address stabilizes instead.
5. Any light client (the same or a different one) subsequently querying `light/get_definition` for `A` on this node still receives the stale `D1` from the cache hit path [7](#0-6) , indefinitely, with no way to detect the staleness, until the node process restarts.

### Citations

**File:** network.js (L3825-3840)
```javascript
		case 'light/get_definition':
			if (!params)
				return sendErrorResponse(ws, tag, "no params in light/get_definition");
			if (!ValidationUtils.isValidAddress(params))
				return sendErrorResponse(ws, tag, "address not valid");
			if (definitions[params])
				return sendResponse(ws, tag, definitions[params]);
			db.query("SELECT definition FROM definitions WHERE definition_chash=? UNION SELECT definition FROM aa_addresses WHERE address=? LIMIT 1", [params, params], function(rows){
				var arrDefinition = rows[0]
					? JSON.parse(rows[0].definition)
					: storage.getUnconfirmedAADefinition(params);
				if (arrDefinition) // save in cache
					definitions[params] = arrDefinition;
				sendResponse(ws, tag, arrDefinition);
			});
			break;
```

**File:** storage.js (L772-788)
```javascript
function readDefinitionByAddress(conn, address, max_mci, callbacks){
	readDefinitionChashByAddress(conn, address, max_mci, function(definition_chash){
		readDefinitionAtMci(conn, definition_chash, max_mci, callbacks);
	});
}

// max_mci must be stable
function readDefinitionAtMci(conn, definition_chash, max_mci, callbacks){
	var sql = "SELECT definition FROM definitions CROSS JOIN unit_authors USING(definition_chash) CROSS JOIN units USING(unit) \n\
		WHERE definition_chash=? AND is_stable=1 AND sequence='good' AND main_chain_index<=?";
	var params = [definition_chash, max_mci];
	conn.query(sql, params, function(rows){
		if (rows.length === 0)
			return callbacks.ifDefinitionNotFound(definition_chash);
		callbacks.ifFound(JSON.parse(rows[0].definition));
	});
}
```

**File:** storage.js (L862-880)
```javascript
function getUnconfirmedAADefinition(address) {
	for (var unit in assocUnstableMessages) {
		var objUnit = assocUnstableUnits[unit] || assocStableUnits[unit]; // just stabilized
		if (!objUnit)
			throw Error("unstable unit " + unit + " not in assoc");
		if (objUnit.sequence !== 'good')
			continue;
		var messages = assocUnstableMessages[unit];
		for (var i = 0; i < messages.length; i++) {
			var message = messages[i];
			if (message.app !== 'definition')
				continue;
			var payload = message.payload;
			if (payload.address === address)
				return payload.definition;
		}
	}
	return null;
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
