### Title
Unhandled TypeError crashes the node when re-checking a repeated primary AA trigger unit not present in `assocStableUnits` cache - (File: aa_composer.js)

### Summary
`handleTrigger()` in `aa_composer.js` dereferences `storage.assocStableUnits[trigger.unit].count_aa_responses` without first checking that the cache entry exists, unlike every other lookup of `assocStableUnits` in the codebase (`storage.js`, `main_chain.js`), which always guard with `if (!objUnitProps) throw Error(...)` or an existence check before dereferencing. If the entry is absent, this crashes the process with an unguarded `TypeError: Cannot read properties of undefined`.

### Finding Description [1](#0-0) 

```js
// skip this check for dry-run which uses genesis unit as trigger unit
if (trigger.unit !== constants.GENESIS_UNIT && !trigger_opts.bAir && storage.assocStableUnits[trigger.unit].count_aa_responses && mci >= constants.pemCurvesFixMci)
    return bounce('a second primary trigger from the same unit is not allowed');
```

This check is designed to prevent a unit from re-triggering a primary AA response after resuming (e.g. after catch-up or restart). It is reached for every non-dry-run, non-secondary trigger execution, i.e. for every unit that includes a `payment` message to an AA address, sent by any regular user. Unlike this line, all comparable lookups elsewhere in the codebase guard the lookup, e.g.: [2](#0-1) 
```js
const objLastBallUnitProps = assocStableUnits[objMcUnitProps.last_ball_unit];
if (!objLastBallUnitProps)
    throw Error(`no last ball of MC unit ${objMcUnitProps.unit} found in cache`);
```

`assocStableUnits` is an in-memory cache that is actively pruned by `shrinkCache()` (runs every 5 minutes) and by `forgetUnit()`/`archiveJointAndDescendants()`, and is also rebuilt from a bounded MCI window on startup (`initStableUnits` only loads units with `main_chain_index >= top_mci`): [3](#0-2) [4](#0-3) 

`handleAATriggers()` processes rows straight from the `aa_triggers` DB table (which can retain entries across process restarts if the AA batch commit sequence is interrupted, as it is only deleted after the trigger finishes executing) and joins to `units`/`aa_addresses`, not to the in-memory `assocStableUnits` cache: [5](#0-4) 

If a queued/backlog trigger unit is old enough to have been pruned/evicted from `assocStableUnits` (via `shrinkCache`) or was never reloaded into the cache after a restart (because it falls outside the bounded `top_mci` window loaded by `initStableUnits`), `storage.assocStableUnits[trigger.unit]` is `undefined`, and dereferencing `.count_aa_responses` on it throws a raw `TypeError` instead of a handled `Error`.

### Impact Explanation
Because `handleAATriggers`/`handleTrigger` run outside any try/catch that converts exceptions into an `Error()`-style rejection, this exception propagates as an uncaught exception. `network.js` installs a global `uncaughtException` handler that deliberately re-throws to crash the process "to avoid ending up in an inconsistent state": [6](#0-5) 

A process crash here occurs while holding the `'aa_triggers'` mutex and mid-transaction (`conn.query("BEGIN")` was issued in `handlePrimaryAATrigger` but never committed), and it happens for *every* full node processing this same trigger backlog upon reconnect/restart — this is exactly the class of bug the referenced report warns about: a panic during state processing (`assocStableUnits` cache state) that "can occur from reading the state of a contract," and which "can persist across process lifetimes (spin-up, crash, spin-up, crash...)" because the offending `aa_triggers` row is never deleted (the `DELETE FROM aa_triggers` only runs after `handleTrigger` completes successfully). This can render the affected node (and any other full node that independently reaches the same cache-eviction state, since `shrinkCache`/`initStableUnits` are deterministic per uptime/restart pattern) unable to process new units, satisfying the "network unable to confirm new units" impact bar.

### Likelihood Explanation
The likelihood is difficult to fully pin down without deeper analysis of exact ordering guarantees between `markMcIndexStable` → `handleAATriggers` → `shrinkCache`/restart timing, so I flag this as a real code smell/root-cause bug (missing guard, inconsistent with every other similar cache access in the file) rather than a fully proven, reliably-triggerable exploit path from a single attacker action in one transaction. Triggering it plausibly requires the AA-trigger backlog to remain unprocessed across a cache-eviction boundary (a long node outage/restart combined with normal AA usage), which is a scenario not fully under the control of a single unprivileged unit poster but is reachable via ordinary AA payment usage without needing a malicious peer, node, or hub.

### Recommendation
Add an explicit existence check before dereferencing, mirroring the pattern used everywhere else in `storage.js`/`main_chain.js`:
```js
if (trigger.unit !== constants.GENESIS_UNIT && !trigger_opts.bAir && mci >= constants.pemCurvesFixMci) {
    const objTriggerUnitProps = storage.assocStableUnits[trigger.unit];
    if (objTriggerUnitProps && objTriggerUnitProps.count_aa_responses)
        return bounce('a second primary trigger from the same unit is not allowed');
    if (!objTriggerUnitProps) {
        // fall back to a DB read of count_aa_responses instead of assuming 0 or crashing
    }
}
```
More generally, replace the panic-as-error-handling pattern in `aa_composer.js`/`writer.js` (numerous `throw Error(...)` calls reached during normal trigger/unit processing) with `Result`-style callbacks/logged errors at the top level, per the referenced finding's recommendation, so that a single inconsistent cache entry cannot crash the entire daemon.

### Proof of Concept
Not independently reproduced within the scope of this review; the analysis is based on static code-path tracing: `aa_composer.js:1861` unconditionally indexes `storage.assocStableUnits[trigger.unit]`, and `storage.js` demonstrates that entries are routinely absent from this cache (pruned in `shrinkCache`, bounded on load in `initStableUnits`), each of those call sites explicitly guard against `undefined` before use — this call site does not. A concrete PoC would require constructing a backlog `aa_triggers` row whose unit falls outside the `top_mci` window used by `initStableUnits`/`shrinkCache` at the time `handleAATriggers` re-processes it, which was not verified end-to-end due to index/tool limitations on tracing exact MCI-window arithmetic across `main_chain.js`.

### Citations

**File:** aa_composer.js (L59-89)
```javascript
function handleAATriggers(onDone) {
	if (!onDone)
		return new Promise(resolve => handleAATriggers(resolve));
	mutex.lock(['aa_triggers'], function (unlock) {
		db.query(
			"SELECT aa_triggers.mci, aa_triggers.unit, address, definition \n\
			FROM aa_triggers \n\
			CROSS JOIN units USING(unit) \n\
			CROSS JOIN aa_addresses USING(address) \n\
			ORDER BY aa_triggers.mci, level, aa_triggers.unit, address",
			function (rows) {
				var arrPostedUnits = [];
				async.eachSeries(
					rows,
					function (row, cb) {
						console.log('handleAATriggers', row.unit, row.mci, row.address);
						var arrDefinition = JSON.parse(row.definition);
						handlePrimaryAATrigger(row.mci, row.unit, row.address, arrDefinition, arrPostedUnits, cb);
					},
					function () {
						arrPostedUnits.forEach(function (objUnit) {
							eventBus.emit('new_aa_unit', objUnit);
						});
						unlock();
						onDone();
					}
				);
			}
		);
	});
}
```

**File:** aa_composer.js (L1860-1862)
```javascript
			// skip this check for dry-run which uses genesis unit as trigger unit
			if (trigger.unit !== constants.GENESIS_UNIT && !trigger_opts.bAir && storage.assocStableUnits[trigger.unit].count_aa_responses && mci >= constants.pemCurvesFixMci)
				return bounce('a second primary trigger from the same unit is not allowed');
```

**File:** storage.js (L1181-1183)
```javascript
	const objLastBallUnitProps = assocStableUnits[objMcUnitProps.last_ball_unit];
	if (!objLastBallUnitProps)
		throw Error(`no last ball of MC unit ${objMcUnitProps.unit} found in cache`);
```

**File:** storage.js (L2250-2293)
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
```

**File:** storage.js (L2339-2380)
```javascript
function initStableUnits(conn, onDone){
	if (!onDone)
		return new Promise(resolve => initStableUnits(conn, resolve));
	if (min_retrievable_mci === null)
		throw Error(`min_retrievable_mci no initialized yet`);
	var conn = conn || db;
	readLastStableMcIndex(conn, async function (_last_stable_mci) {
		last_stable_mci = _last_stable_mci;
		let top_mci = Math.min(min_retrievable_mci, last_stable_mci - constants.COUNT_MC_BALLS_FOR_PAID_WITNESSING - 10);
		const last_tps_fees_mci = await getLastTpsFeesMci(conn);
		if (last_tps_fees_mci < last_stable_mci) {
			const last_ball_mci_of_last_tps_fees_mci = last_tps_fees_mci ? await findLastBallMciOfMci(conn, last_tps_fees_mci) : 0;
			top_mci = Math.min(top_mci, last_ball_mci_of_last_tps_fees_mci)
		}
		conn.query(
			"SELECT unit, level, latest_included_mc_index, main_chain_index, is_on_main_chain, is_free, is_stable, witnessed_level, headers_commission, payload_commission, sequence, timestamp, GROUP_CONCAT(address) AS author_addresses, COALESCE(witness_list_unit, unit) AS witness_list_unit, best_parent_unit, last_ball_unit, tps_fee, max_aa_responses, count_aa_responses, count_primary_aa_triggers, is_aa_response, version \n\
			FROM units \n\
			JOIN unit_authors USING(unit) \n\
			WHERE is_stable=1 AND main_chain_index>=? \n\
			GROUP BY +unit \n\
			ORDER BY +level", [top_mci],
			function(rows){
				rows.forEach(function(row){
					row.count_primary_aa_triggers = row.count_primary_aa_triggers || 0;
					row.bAA = !!row.is_aa_response;
					delete row.is_aa_response;
					row.tps_fee = row.tps_fee || 0;
					if (parseFloat(row.version) >= constants.fVersion4)
						delete row.witness_list_unit;
					delete row.version;
					row.author_addresses = row.author_addresses.split(',');
					assocStableUnits[row.unit] = row;
					if (!assocStableUnitsByMci[row.main_chain_index])
						assocStableUnitsByMci[row.main_chain_index] = [];
					assocStableUnitsByMci[row.main_chain_index].push(row);
				});
				console.log('initStableUnits 1 done');
				if (Object.keys(assocStableUnits).length === 0)
					return onDone ? onDone() : null;
				initParenthoodAndHeadersComissionShareForUnits(conn, assocStableUnits, onDone);
			}
		);
```

**File:** network.js (L4530-4543)
```javascript
process.on('uncaughtException', (err) => {
	console.log('Uncaught exception:', err);
	console.error('Uncaught exception:', err);
	if (!conf.bLight) {
		let hosts = [...Object.keys(messagesInWork), ...Object.keys(requestsInWork)];
		if (currentJointHost)
			hosts.push(currentJointHost);
		console.log('Clients with pending requests/messages at the time of uncaught exception:', hosts);
		const fs = require('fs');
		const app_data_dir = require('./desktop_app.js').getAppDataDir();
		fs.writeFileSync(`${app_data_dir}/uncaught_exception_clients.txt`, hosts.concat(Object.keys(assocBlockedPeers)).join('\n'), 'utf8');
	}
	throw err; // crash the process to avoid ending up in an inconsistent state
});
```
