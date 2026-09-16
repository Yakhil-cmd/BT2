### Title
Improperly-sequenced cache cleanup lets a concurrent write-failure race crash every full node while it executes a queued AA trigger - ([File: aa_composer.js])

### Summary
`writer.saveJoint()` acquires the `"write"` mutex and, on a failed commit, calls `storage.resetMemory(conn)` which wipes and asynchronously rebuilds the in-memory unit caches (`assocStableUnits`, `assocUnstableUnits`). `aa_composer.handleAATriggers()` / `handlePrimaryAATrigger()`, however, is serialized only by a separate `"aa_triggers"` mutex and a dedicated DB connection — it does not hold the `"write"` lock while it looks up `storage.assocStableUnits[unit]`. If a `resetMemory` cleanup happens to run while an AA-trigger row for a just-stabilized unit is being processed, the lookup can observe the cache in a cleared/rebuilt state and throw an unconditional `Error`, exactly the "improperly sequenced cleanup on an in-flight context leads to an assertion failure and crash" pattern described in CVE-2017-3145 for BIND's fetch-context cleanup.

### Finding Description
`markMcIndexStable()` inserts an `aa_triggers` row for every AA address that received a payment in a newly-stabilized MCI [1](#0-0) , and `writer.saveJoint()` invokes `aa_composer.handleAATriggers()` right after commit to process those rows [2](#0-1) .

`handleAATriggers()` only takes the `"aa_triggers"` mutex, then reads the pending rows and processes each on its own connection: [3](#0-2) . Inside `handlePrimaryAATrigger()`, after the trigger has actually run (state changes evaluated, response constructed, `aa_triggers` row deleted) the code performs an unconditional lookup:

```
let objUnitProps = storage.assocStableUnits[unit];
if (!objUnitProps)
    throw Error(`handlePrimaryAATrigger: unit ${unit} not found in cache`);
``` [4](#0-3) 

Meanwhile, `writer.saveJoint()` holds a *different* mutex (`"write"`) while writing a unit, and if the KV batch or SQL commit fails it calls `storage.resetMemory(conn)`, which clears and lazily reinitializes `assocStableUnits`/`assocStableUnitsByMci` from the database: [5](#0-4) , [6](#0-5) .

Because `handleAATriggers()`/`handlePrimaryAATrigger()` runs under the `"aa_triggers"` mutex and its own connection — not under the `"write"` mutex — nothing prevents `resetMemory()` from tearing down and asynchronously rebuilding `assocStableUnits` concurrently with an in-flight `handlePrimaryAATrigger()` call that references the same map. If the reset happens to occur between the `DELETE FROM aa_triggers` and the `storage.assocStableUnits[unit]` read, the entry may momentarily be absent from the cache, hitting the `throw Error(...)` in `aa_composer.js` and crashing the node process — a direct analog of the BIND bug class: cleanup of a shared, asynchronously-managed context ("fetch context" in BIND, the unit-props cache in ocore) is not sequenced/synchronized against a concurrent consumer that still expects the context to be valid, producing an assertion-style crash instead of memory corruption (JS has no raw UAF, but the effect — an unconditional `throw` that kills the process — is functionally identical: an unhandled exception in Node.js terminates the process).

`forgetUnit()` explicitly guards against removing a *stable* unit's cache entry (`if (assocStableUnits[unit]) throw Error("trying to forget stable unit ...")`, [7](#0-6) ), showing the codebase assumes `assocStableUnits[unit]` is durable for stable units once set — an invariant that `resetMemory()`'s unsynchronized full-cache rebuild can violate with respect to concurrently-running AA trigger processing.

### Impact Explanation
An unhandled `Error` thrown inside the async callback chain of `handlePrimaryAATrigger` is not caught anywhere in this call path and will crash the Node.js process (uncaught exception). Because `aa_triggers` rows and stabilization are driven identically by all full nodes processing the same DAG, a race that manifests on one honest node processing a particular AA trigger has a good chance of manifesting on other nodes processing the very same trigger under similar load/timing, which can produce simultaneous crashes across the network — i.e., a network unable to confirm new units while nodes are down/restarting, matching the "node crash from an internal assertion-style failure" impact class asked about (analogous to BIND `named` crashing under CVE-2017-3145). This is reachable purely from ordinary AA-trigger execution driven by units any user can post (payments to an AA address); no privileged/network role is required to create the AA trigger itself.

### Likelihood Explanation
The likelihood is **moderate-to-low in practice** because it depends on the timing coincidence of (a) a `writer.saveJoint()` commit failure triggering `resetMemory()` and (b) an in-flight `handlePrimaryAATrigger()` read of `storage.assocStableUnits[unit]` for the very unit being processed, occurring in the same short window, without any lock coordinating the two. Commit failures are meant to be rare/exceptional, so this is not trivially or deterministically reproducible by an attacker on demand purely by posting units; however, an attacker who can also induce commit failures/contention (e.g., via heavy concurrent AA activity, resource exhaustion, or other bugs that raise commit failure rates) increases the window in which this race can fire. I could not fully verify from static reading alone whether `resetMemory()` and `handleAATriggers()` can truly interleave at runtime (e.g., whether some higher-level lock outside the snippets reviewed serializes them) — this would need dynamic/runtime confirmation.

### Recommendation
- Hold the `"write"` mutex (or an equivalent single global lock covering both cache resets and AA trigger processing) around the `storage.assocStableUnits[unit]` lookup and update in `handlePrimaryAATrigger`, or have `resetMemory()` acquire the `"aa_triggers"` mutex (or vice versa) before mutating the shared caches, so that a cache reset cannot interleave with in-flight AA-trigger processing.
- Replace the unconditional `throw Error(...)` at `aa_composer.js:105-106` with a controlled recovery path (e.g., re-fetch `objUnitProps` from the DB via `storage.readUnitProps` when the cache entry is missing) instead of crashing the process, consistent with defensive handling elsewhere in `storage.js` (`readUnitProps`).
- Audit other unsynchronized reads of `assocStableUnits`/`assocUnstableUnits` from code paths that run outside the `"write"` mutex (e.g., `graph.js`, `main_chain.js`, `data_feeds.js`) for the same class of race against `resetMemory()`/`shrinkCache()`.

### Proof of Concept
A concrete, reliably-triggerable PoC could not be constructed statically because it requires provoking a `writer.saveJoint()` commit failure (which calls `storage.resetMemory`) to interleave precisely with an in-flight `aa_composer.handlePrimaryAATrigger()` call for the same unit — a timing-dependent race that needs a running multi-process/dynamic environment (e.g., fault-injecting a KV batch-write or SQL commit failure while a large/slow AA trigger executes) to reproduce and confirm. This should be validated in a live/test environment (e.g., a Devin session with the ability to run the node and inject a forced commit failure during AA-trigger processing) rather than asserted from static code review alone.

### Citations

**File:** main_chain.js (L1691-1722)
```javascript
	function handleAATriggers() {
		// a single unit can send to several AA addresses
		// a single unit can have multiple outputs to the same AA address, even in the same asset
		const mci_column = mci >= constants.pemCurvesFixMci ? 'aa_addresses.mci' : 'aa_definition_units.main_chain_index';
		conn.query(
			"SELECT DISTINCT address, definition, units.unit, units.level \n\
			FROM units \n\
			CROSS JOIN outputs USING(unit) \n\
			CROSS JOIN aa_addresses USING(address) \n\
			LEFT JOIN assets ON asset=assets.unit \n\
			CROSS JOIN units AS aa_definition_units ON aa_addresses.unit=aa_definition_units.unit \n\
			WHERE units.main_chain_index = ? AND units.sequence = 'good' AND (outputs.asset IS NULL OR is_private=0) \n\
				AND NOT EXISTS (SELECT 1 FROM unit_authors CROSS JOIN aa_addresses USING(address) WHERE unit_authors.unit=units.unit) \n\
				AND " + mci_column + "<=? \n\
			ORDER BY units.level, units.unit, address", // deterministic order
			[mci, mci],
			function (rows) {
				count_aa_triggers = rows.length;
				if (rows.length === 0)
					return finishMarkMcIndexStable();
				var arrValues = rows.map(function (row) {
					return "("+mci+", "+conn.escape(row.unit)+", "+conn.escape(row.address)+")";
				});
				conn.query("INSERT INTO aa_triggers (mci, unit, address) VALUES " + arrValues.join(', '), function () {
					finishMarkMcIndexStable();
					// now calling handleAATriggers() from write.js
				//	process.nextTick(function(){ // don't call it synchronously with event emitter
				//		eventBus.emit("new_aa_triggers"); // they'll be handled after the current write finishes
				//	});
				});
			}
		);
```

**File:** writer.js (L702-713)
```javascript
							commit_fn(err ? "ROLLBACK" : "COMMIT", async function(){
								var consumed_time = Date.now()-start_time;
								profiler.add_result('write', consumed_time);
								console.log((err ? (err+", therefore rolled back unit ") : "committed unit ")+objUnit.unit+", write took "+consumed_time+"ms");
								profiler.stop('write-sql-commit');
								profiler.increment();
								if (err) {
									var headers_commission = require("./headers_commission.js");
									headers_commission.resetMaxSpendableMci();
									delete storage.assocUnstableMessages[objUnit.unit];
									await storage.resetMemory(conn);
								}
```

**File:** writer.js (L724-727)
```javascript
								if (bStabilizedAATriggers && !err) {
									console.log(`executing AA triggers`);
									const aa_composer = require("./aa_composer.js");
									await aa_composer.handleAATriggers();
```

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

**File:** aa_composer.js (L101-109)
```javascript
					handleTrigger(conn, batch, trigger, {}, {}, arrDefinition, address, mci, objMcUnit, false, arrResponses, function(){
						conn.query("DELETE FROM aa_triggers WHERE mci=? AND unit=? AND address=?", [mci, unit, address], async function(){
							await conn.query("UPDATE units SET count_aa_responses=IFNULL(count_aa_responses, 0)+? WHERE unit=?", [arrResponses.length, unit]);
							let objUnitProps = storage.assocStableUnits[unit];
							if (!objUnitProps)
								throw Error(`handlePrimaryAATrigger: unit ${unit} not found in cache`);
							if (!objUnitProps.count_aa_responses)
								objUnitProps.count_aa_responses = 0;
							objUnitProps.count_aa_responses += arrResponses.length;
```

**File:** storage.js (L2226-2229)
```javascript
	delete assocUnstableUnits[unit];
	if (!conf.bLight && assocStableUnits[unit])
		throw Error("trying to forget stable unit "+unit);
	delete assocStableUnits[unit];
```

**File:** storage.js (L2510-2530)
```javascript
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
