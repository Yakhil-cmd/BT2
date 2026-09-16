### Title
Unbounded, never-invalidated in-memory cache of unconfirmed AA definitions served to light clients as authoritative - ([File: network.js])

### Summary
`network.js` maintains a plain in-memory object `definitions` (used at the `light/get_definition` request handler) that permanently caches an address's definition — including *unconfirmed* AA definitions returned by `storage.getUnconfirmedAADefinition()` — with no TTL, no size bound, and no invalidation hook when the underlying unit that produced the definition is later voided, displaced by a conflicting unit, or otherwise fails to finalize. Any single unit posted to the DAG that contains a `definition` message can seed this cache; once cached, the (potentially never-finalized) value is served to every future light client that queries `light/get_definition` for that address, functioning as an analog of a poisoned resolver cache: bad/never-final data is trusted and redistributed indefinitely to downstream clients.

### Finding Description
`storage.getUnconfirmedAADefinition(address)` (`storage.js:862-880`) scans `assocUnstableMessages` for any unstable unit whose in-memory `sequence` is currently `'good'` and returns the `definition` payload of a `definition`-app message matching the requested address:

```js
function getUnconfirmedAADefinition(address) {
	for (var unit in assocUnstableMessages) {
		var objUnit = assocUnstableUnits[unit] || assocStableUnits[unit];
		...
		if (objUnit.sequence !== 'good') continue;
		var messages = assocUnstableMessages[unit];
		for (var i = 0; i < messages.length; i++) {
			var message = messages[i];
			if (message.app !== 'definition') continue;
			var payload = message.payload;
			if (payload.address === address) return payload.definition;
		}
	}
	return null;
}
``` [1](#0-0) 

This is explicitly a *point-in-time, unstable* signal — the unit's `sequence` field can still flip from `'good'` to `'temp-bad'`/`'final-bad'` later as the DAG resolves conflicts (see `writer.js` marking conflicting units `'temp-bad'` in additional queries), or the unit could simply never stabilize and be archived/voided. [2](#0-1) 

The full-node `light/get_definition` handler consumes this unconfirmed value and stores it in a persistent, unbounded module-level cache with no expiry and no invalidation callback:

```js
case 'light/get_definition':
    ...
    if (definitions[params])
        return sendResponse(ws, tag, definitions[params]);
    db.query("SELECT definition FROM definitions ... UNION SELECT definition FROM aa_addresses ...", [params, params], function(rows){
        var arrDefinition = rows[0]
            ? JSON.parse(rows[0].definition)
            : storage.getUnconfirmedAADefinition(params);
        if (arrDefinition) // save in cache
            definitions[params] = arrDefinition;
        sendResponse(ws, tag, arrDefinition);
    });
    break;
``` [3](#0-2) 

Note the DB query only returns rows for definitions that are already finalized (`definitions`/`aa_addresses` tables); the fallback to `storage.getUnconfirmedAADefinition` is precisely the unconfirmed/unstable path, and its result is unconditionally written into `definitions[params]` forever, with no code path anywhere in `network.js` ever deleting or refreshing an entry once set (`grep` for `delete definitions` / re-assignment finds none).

The same unconfirmed-definition fallback is also used to answer other light-protocol AA-related requests that a wallet relies on to decide how to treat a destination address, e.g. `light/new_aa_to_watch` and `light/get_aa_state_vars`:

```js
storage.readAADefinition(db, body.aa, null, function (arrDefinition) {
    if (!arrDefinition) {
        arrDefinition = storage.getUnconfirmedAADefinition(body.aa);
        if (!arrDefinition) return sendError(ws, "not an AA: " + body.aa);
    }
    ...
});
``` [4](#0-3) [5](#0-4) 

Because the `definition` app message itself is hash-bound to its own address (`payload.address !== objectHash.getChash160(payload.definition)` is rejected in `validation.js`), an attacker cannot forge a *different* definition for a victim's address — but that is not the relevant analog to the BIND cache-poisoning bug class. The analogous flaw is that **temporary/never-finalized data is treated as authoritative and cached without expiry or revalidation**, exactly like a resolver that caches a response before validating that it will remain the final, authoritative answer. A single unit poster can create a `definition` message for a fresh address while the message's own unit is still unstable (`sequence === 'good'` only transiently); a hub that serves `light/get_definition`/`light/new_aa_to_watch`/`light/get_aa_state_vars` before that unit stabilizes will permanently cache and redistribute the “address X is an AA with definition D” answer to every light client that ever asks, even if the defining unit subsequently becomes non-serial/`final-bad` (e.g., because its author double-spent the same input in a competing branch) and is voided/archived (`archiving.js`, `storage.forgetUnit`). [6](#0-5) 

### Impact Explanation
Light wallets that rely on the hub's answer to decide how to interact with an address (composing a payment expecting AA processing, calling `light/dry_run_aa`, or registering a watch via `light/new_aa_to_watch`) can be permanently misled about whether an address is (or will remain) a valid AA. If the defining unit never finalizes as `good`, the address never actually becomes an AA on the authoritative DAG, yet the hub keeps answering "yes, it's an AA with definition D" to every light client indefinitely. A light wallet acting on this stale/incorrect answer can send funds to that address expecting autonomous-agent handling (refunds, state transitions) that will never occur, resulting in AA fund loss/freezing for the sender, and creates a persistent disagreement between what light clients believe about the DAG's finalized state and what full nodes ultimately settle on — i.e., a form of validity/finalization disagreement analogous to the cache poisoning root cause in the CVE (stale/incorrect cached records driving clients to wrong conclusions about where to send data).

### Likelihood Explanation
The only prerequisite is posting a single ordinary unit containing a `definition`-app message for a fresh address while the unit is momentarily unstable with `sequence='good'`, and having any hub that serves light clients receive a `light/get_definition`, `light/new_aa_to_watch`, or `light/get_aa_state_vars` request for that address during that unstable window (a normal, permissionless, unprivileged action — no special hub/peer trust required to *create* the state, only ordinary light-protocol usage to *trigger* the caching). Given hubs answer light requests as soon as a unit is locally known/validated and the cache is never invalidated afterward, this is straightforward for anyone controlling both the definition-posting unit and a light-client-facing request (or simply timing normal light traffic) to trigger.

### Recommendation
- Do not populate the persistent `definitions` cache in `network.js` from `storage.getUnconfirmedAADefinition()` results; only cache definitions that are backed by a `main_chain_index`-stable, `sequence='good'` row from the `definitions`/`aa_addresses` tables.
- If unconfirmed AA definitions must be exposed to light clients at all (e.g., for `light/get_aa_state_vars`/`light/new_aa_to_watch`), tag the response as unconfirmed and re-validate/expire it once the underlying unit's finality is known (hook into `writer.js`'s stabilization/voiding paths and `storage.forgetUnit`/archiving to purge stale cache entries for the same address).
- Add a TTL or size bound to the `definitions` map, and explicitly invalidate any cached unconfirmed-definition entry when the corresponding unit's sequence changes away from `'good'` or when the unit is archived/voided.

### Proof of Concept
1. Compose and broadcast unit U1 from address A containing a `definition` message defining a fresh address X as an AA (`payload.address = X = getChash160(payload.definition)`), spending an input of A.
2. Before U1 stabilizes, broadcast a conflicting unit U2 from A that double-spends the same input via a different DAG branch, engineered so U1 ultimately becomes non-serial (`sequence` flips to `'temp-bad'`/`'final-bad'`) once the fork resolves.
3. While U1 is still `sequence='good'` (the normal window before resolution), send a `light/get_definition` (or `light/new_aa_to_watch` / `light/get_aa_state_vars`) request for address X to a hub that has received U1. The hub calls `storage.getUnconfirmedAADefinition(X)`, finds U1's message, and caches it in `definitions[X]` (`network.js:3830-3838`).
4. After U2 wins and U1 is voided/archived, repeat the `light/get_definition` request for X from any light client. The hub returns the cached (now-stale, never-finalized) definition from step 3 without re-querying the DB, because `definitions[X]` is checked and returned first (`network.js:3830-3831`) and is never invalidated.

### Citations

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

**File:** writer.js (L58-72)
```javascript
		// additional queries generated by the validator, used only when received a doublespend
		for (var i=0; i<objValidationState.arrAdditionalQueries.length; i++){
			var objAdditionalQuery = objValidationState.arrAdditionalQueries[i];
			conn.addQuery(arrQueries, objAdditionalQuery.sql, objAdditionalQuery.params);
			breadcrumbs.add('====== additional query '+JSON.stringify(objAdditionalQuery));
			if (objAdditionalQuery.sql.match(/temp-bad/)){
				var arrUnstableConflictingUnits = objAdditionalQuery.params[0];
				breadcrumbs.add('====== conflicting units in additional queries '+arrUnstableConflictingUnits.join(', '));
				arrUnstableConflictingUnits.forEach(function(conflicting_unit){
					var objConflictingUnitProps = storage.assocUnstableUnits[conflicting_unit];
					if (!objConflictingUnitProps)
						return breadcrumbs.add("====== conflicting unit "+conflicting_unit+" not found in unstable cache"); // already removed as uncovered
					if (objConflictingUnitProps.sequence === 'good')
						objConflictingUnitProps.sequence = 'temp-bad';
				});
```

**File:** network.js (L3194-3199)
```javascript
			storage.readAADefinition(db, body.aa, null, function (arrDefinition) {
				if (!arrDefinition) {
					arrDefinition = storage.getUnconfirmedAADefinition(body.aa);
					if (!arrDefinition)
						return sendError(ws, "not an AA: " + body.aa);
				}
```

**File:** network.js (L3825-3839)
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
```

**File:** network.js (L3986-3991)
```javascript
			storage.readAADefinition(db, params.address, null, function (arrDefinition) {
				if (!arrDefinition) {
					arrDefinition = storage.getUnconfirmedAADefinition(params.address);
					if (!arrDefinition)
						return sendErrorResponse(ws, tag, "not an AA");
				}
```
