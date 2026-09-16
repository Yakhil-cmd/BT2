### Title
Unprivileged light-client `light/dry_run_aa` request triggers an unlocked, wholesale in-memory cache reset (`storage.resetMemory`) that races with concurrent unit validation/writing — analog of Xen `EVTCHNOP_reset` race (CVE-2020-25599) - ([File: network.js])

### Summary
`network.js`'s `light/dry_run_aa` handler lets any connected peer (including unprivileged light clients) request a dry-run of an AA trigger. When `constants.COUNT_WITNESSES === 1`, the handler unconditionally calls `storage.resetMemory()` inside a *separate*, unlocked DB transaction, wiping and rebuilding the core in-memory unit/stability caches (`assocUnstableUnits`, `assocStableUnits`, `assocBestChildren`, `assocStableUnitsByMci`, `min_retrievable_mci`) that every other validation and write path relies on. [1](#0-0) 

### Finding Description
`resetMemory()` deletes and repopulates the global caches that back `readUnitProps`, `readStaticUnitProps`, main-chain stability computations, and AA trigger execution: [2](#0-1) [3](#0-2) 

Every other writer to these structures — normal unit validation/saving (`validation.validate` → `writer.saveJoint`), AA trigger execution (`aa_composer.handlePrimaryAATrigger`/`handleTrigger`), and cache shrinking (`storage.shrinkCache`) — is serialized either by per-author-address mutex locks (`mutex.lock(arrAuthorAddresses, ...)` in `validation.js`) or by the dedicated `"write"`/`"aa_triggers"` mutex keys: [4](#0-3) [5](#0-4) [6](#0-5) 

The `light/dry_run_aa` reset path takes none of these locks — it goes straight through `db.executeInTransaction`, which only opens its own DB transaction, with no mutex acquisition at all: [7](#0-6) 

This is structurally identical to the Xen `evtchn_reset()` bug class: a guest-controlled (here, peer-controlled) "reset" operation that clears/rebuilds shared internal state without coordinating with concurrently running operations that assume that state's stability. `readUnitProps` itself contains hard invariant checks (`throw Error("different props...")`, `throw Error("no unstable props of ...")`) that assume the cache reflects a single consistent view during a validation pass: [8](#0-7) 

If a unit validation/write (holding `arrAuthorAddresses` or `"write"` locks) is in flight while `resetMemory()` concurrently deletes and rebuilds `assocUnstableUnits`/`assocStableUnits` from a different connection/transaction, the in-progress validation can observe a mix of stale in-memory objects and freshly rebuilt ones (or momentarily-empty maps), tripping these invariant checks (`throw Error`) or silently reading inconsistent state (e.g., `is_free`, `is_stable`, `witnessed_level`, `best_parent_unit`) used to determine main-chain stability and sequence (`good`/`temp-bad`/`final-bad`). `aa_composer.handlePrimaryAATrigger` explicitly assumes `storage.assocStableUnits[unit]` exists and throws if it does not: [9](#0-8) 
— exactly the sort of assumption a concurrent, unlocked reset can violate.

### Impact Explanation
On any deployment where `constants.COUNT_WITNESSES === 1` (single-witness/private networks, which are a supported and documented ocore configuration, not merely a test artifact), an unprivileged light-wallet peer can repeatedly send `light/dry_run_aa` requests to a full node. Each request races an unlocked full cache rebuild against ordinary unit validation, AA trigger processing, and stabilization. Depending on timing this can:
- Crash the node process via one of the `throw Error(...)` invariant checks in `readUnitProps`/`handlePrimaryAATrigger`, causing denial of service for the whole network segment served by that node.
- Corrupt the in-memory view of stability/sequence, causing the node to disagree with peers on unit validity/stability (nodes running the same version could diverge if the race window differs), which maps to the "node disagreement on validity or stability" impact class.

### Likelihood Explanation
Likelihood is data/timing dependent (requires overlap between the reset transaction and an in-flight validation/AA-trigger transaction), and only applies when `COUNT_WITNESSES === 1`. On such single-witness deployments, an attacker only needs to send `light/dry_run_aa` requests at high frequency while normal traffic (new units, AA triggers) is being processed — trivially reachable by any peer since `light/dry_run_aa` requires no special privilege, no valid signature, and no prior state.

### Recommendation
Guard the `storage.resetMemory()` call in the `light/dry_run_aa` handler with the same `"write"` mutex key used elsewhere (`mutex.lock(["write"], ...)`), so the reset cannot overlap with concurrent validation/writing/AA-trigger processing. Alternatively, avoid the global memory reset entirely for dry-runs by scoping the temporary "rebuilt MC" state to a private/local structure that doesn't touch the shared `assocUnstableUnits`/`assocStableUnits` caches used by concurrent unit processing.

### Proof of Concept
1. Run an ocore full node configured with `constants.COUNT_WITNESSES === 1`.
2. As an unprivileged peer, open a websocket connection and continuously send `light/dry_run_aa` requests referencing any valid AA address (no signing required):
   ```json
   {"command":"light/dry_run_aa","params":{"address":"<AA_ADDRESS>","trigger":{"address":"<ANY_ADDRESS>","outputs":{"base":10000}}}}
   ```
3. Simultaneously, from a separate connection, broadcast ordinary payment units / AA-triggering units at a normal rate.
4. Observe that `storage.resetMemory()` (triggered on every dry-run reply, unconditionally per request under `COUNT_WITNESSES===1`) executes in an unlocked transaction concurrently with the mutex-protected validation/write path; with sufficient request rate the invariant checks in `storage.readUnitProps` (`throw Error("different props...")`) or `aa_composer.handlePrimaryAATrigger` (`throw Error("...unit ${unit} not found in cache")`) will trigger, crashing the node process — confirming the race.

### Citations

**File:** network.js (L3951-3956)
```javascript
					aa_composer.dryRunPrimaryAATrigger(params.trigger, params.address, arrDefinition, function (arrResponses) {
						if (constants.COUNT_WITNESSES === 1) { // the temp unit might have rebuilt the MC
							db.executeInTransaction(function (conn, onDone) {
								storage.resetMemory(conn, onDone);
							});
						}
```

**File:** storage.js (L1502-1551)
```javascript
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

**File:** storage.js (L2261-2261)
```javascript
	const unlock = await mutex.lock("write");
```

**File:** storage.js (L2500-2519)
```javascript
function resetUnstableUnits(conn, onDone){
	Object.keys(assocBestChildren).forEach(function(unit){
		delete assocBestChildren[unit];
	});
	Object.keys(assocUnstableUnits).forEach(function(unit){
		delete assocUnstableUnits[unit];
	});
	initUnstableUnits(conn, onDone);
}

function resetStableUnits(conn, onDone){
	console.log('resetStableUnits');
	Object.keys(assocStableUnits).forEach(function(unit){
		delete assocStableUnits[unit];
	});
	Object.keys(assocStableUnitsByMci).forEach(function(mci){
		delete assocStableUnitsByMci[mci];
	});
	initStableUnits(conn, onDone);
}
```

**File:** storage.js (L2521-2530)
```javascript
function resetMemory(conn, onDone){
	if (!onDone)
		return new Promise(resolve => resetMemory(conn, resolve));
	resetUnstableUnits(conn, function(){
		resetStableUnits(conn, function(){
			min_retrievable_mci = null;
			initializeMinRetrievableMci(conn, onDone);
		});
	});
}
```

**File:** validation.js (L357-357)
```javascript
	mutex.lock(arrAuthorAddresses, function(unlock){
```

**File:** aa_composer.js (L62-62)
```javascript
	mutex.lock(['aa_triggers'], function (unlock) {
```

**File:** aa_composer.js (L104-106)
```javascript
							let objUnitProps = storage.assocStableUnits[unit];
							if (!objUnitProps)
								throw Error(`handlePrimaryAATrigger: unit ${unit} not found in cache`);
```

**File:** db.js (L26-38)
```javascript
function executeInTransaction(doWork, onDone){
	module.exports.takeConnectionFromPool(function(conn){
		conn.query("BEGIN", function(){
			doWork(conn, function(err){
				conn.query(err ? "ROLLBACK" : "COMMIT", function(){
					conn.release();
					if (onDone)
						onDone(err);
				});
			});
		});
	});
}
```
