### Title
Unreleased DB connection on `throw Error` in AA trigger execution paths leads to connection-pool exhaustion - ([File: aa_composer.js])

### Summary
The CVE describes a classic "acquire without matching release on error path" bug: `of_find_node_by_name()` increments a refcount and the function forgets to call `of_node_put()` before an early return. The reachable analog in `ocore` is a database-connection resource, not a kernel refcount, but the pattern is identical: `db.takeConnectionFromPool()` hands out a connection that must be explicitly `.release()`d, and several AA-trigger-execution code paths in `aa_composer.js` `throw Error(...)` from inside the callback chain *before* `conn.release()` is reached, permanently leaking the connection out of the finite connection pool.

### Finding Description
`db.takeConnectionFromPool()` removes a connection from a bounded pool (`MAX_CONNECTIONS`, see `sqlite_pool.js`); the only way it is returned is an explicit `conn.release()` call [1](#0-0) . In several AA-trigger handling functions, a connection is taken, then deep inside nested asynchronous callbacks a `throw Error(...)` is used to signal an unexpected/invariant condition — with no `conn.release()` on that path:

- `handleTrigger()`'s "parameterized AA" (`base_aa`) redirection reads the base AA definition using the *current trigger's mci*, and throws if the base AA is not found at that point, without releasing the connection that was acquired by the caller (`handlePrimaryAATrigger`, `dryRunPrimaryAATrigger`, `estimatePrimaryAATrigger`): [2](#0-1) 
- `estimatePrimaryAATrigger()` itself takes its own connection from the pool and throws "AA not found" if `readAADefinition` returns nothing, again before any `conn.release()`: [3](#0-2) 
- `handlePrimaryAATrigger()` throws if the stable-unit cache entry is missing, deep inside the connection's transaction callback chain, again without releasing the connection first: [4](#0-3) 

Because `readAADefinition(conn, address, mci, ...)` is mci-scoped [5](#0-4) , whereas an AA definition's `base_aa` field is validated once at AA-definition time without necessarily re-checking that the base AA exists *at every possible trigger mci* thereafter, an attacker who controls an AA definition (unprivileged AA author) or who crafts a trigger against such an AA can cause `arrBaseDefinition` to be `null` at execution time, hitting the `throw Error("base AA not found: ...")` branch and leaking the connection that was checked out by the primary trigger-processing routine.

### Impact Explanation
Each leaked connection permanently reduces the size of the finite sqlite/mysql connection pool. Because `handleAATriggers()` — which processes every stable AA trigger unit — holds the global `'aa_triggers'` mutex for its entire run [6](#0-5) , an uncaught `throw` inside `handlePrimaryAATrigger` not only leaks a connection but also prevents `unlock()` from ever being called, since the `async.eachSeries` completion callback that calls `unlock()` is never reached. This freezes all future AA-trigger execution network-wide (every full node runs the same deterministic logic), which in turn stalls stabilization of any unit whose trigger is queued behind the stuck one — i.e., the node (and any node reproducing the same trigger) becomes unable to confirm new units / advance the DAG for AA-touching traffic, and after repeated occurrences the connection pool is exhausted, causing all further queries (validation, writing, etc.) to queue indefinitely. This matches the "network unable to confirm new units" bar for a valid analog.

### Likelihood Explanation
Reachability requires only posting an AA definition with a `base_aa` reference and later sending or contriving a trigger against it at an mci where the base AA is not yet visible to `readAADefinition(conn, base_aa, mci, ...)`, or hitting the cache-miss / not-found conditions during normal trigger processing — actions available to any ordinary AA author / trigger sender, not a privileged or malicious-peer/node actor. However, exploiting the exact mci-window/cache-miss race precisely is somewhat probabilistic and depends on specific AA composition and timing, so likelihood is moderate rather than trivial-and-guaranteed.

### Recommendation
Wrap the connection lifetime in `handlePrimaryAATrigger`, `estimatePrimaryAATrigger`, `dryRunPrimaryAATrigger`, and the `base_aa` branch of `handleTrigger` so that `conn.release()` (and, where applicable, `unlock()` of the `'aa_triggers'`/`'write'` mutex) is guaranteed to run before any `throw`, e.g. by replacing `throw Error(...)` with an explicit `conn.release(); unlock(); throw Error(...)` sequence, or by wrapping the trigger-execution pipeline in a `try/finally` that always releases the connection and mutex regardless of how the callback chain exits.

### Proof of Concept
Conceptual (not a working exploit, since the exact mci timing/cache-miss trigger conditions were not fully verified against `aa_validation.js`'s `base_aa` checks within the available indexing):
1. Define AA `A` with `template.base_aa = <address of AA B>`.
2. Arrange for a primary trigger unit to stabilize at an mci where `storage.readAADefinition(conn, B, mci, ...)` returns null for `B` (e.g. because AA `B`'s own defining unit is not yet stable/visible at that mci, despite passing AA `A`'s original definition-time validation).
3. `handlePrimaryAATrigger` → `handleTrigger` reaches the `base_aa` branch and throws `"base AA not found: " + template.base_aa"` [5](#0-4)  without releasing `conn` or the `'aa_triggers'` mutex acquired in `handleAATriggers` [6](#0-5) .
4. Repeat via additional trigger units to leak further connections until the pool (`MAX_CONNECTIONS` in `sqlite_pool.js`) is exhausted, stalling all subsequent AA processing and DB access.

Note: Due to index size limits, the full logic of `aa_validation.js`'s `base_aa` existence/timing checks could not be completely retrieved to conclusively prove the exact malicious input needed to hit the null-`arrBaseDefinition` branch at trigger-execution time; a Devin session with full repository access would be needed to confirm the precise trigger conditions and construct a concrete end-to-end PoC.

### Citations

**File:** sqlite_pool.js (L194-223)
```javascript
	function takeConnectionFromPool(handleConnection){

		if (!handleConnection)
			return new Promise(resolve => takeConnectionFromPool(resolve));

		if (!bReady){
			console.log("takeConnectionFromPool will wait for ready");
			eventEmitter.once('ready', function(){
				console.log("db is now ready");
				takeConnectionFromPool(handleConnection);
			});
			return;
		}
		
		// first, try to find a free connection
		for (var i=0; i<arrConnections.length; i++)
			if (!arrConnections[i].bInUse){
				//console.log("reusing previously opened connection");
				arrConnections[i].bInUse = true;
				return handleConnection(arrConnections[i]);
			}

		// second, try to open a new connection
		if (arrConnections.length < MAX_CONNECTIONS)
			return connect(handleConnection);

		// third, queue it
		//console.log("queuing");
		arrQueue.push(handleConnection);
	}
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

**File:** aa_composer.js (L101-106)
```javascript
					handleTrigger(conn, batch, trigger, {}, {}, arrDefinition, address, mci, objMcUnit, false, arrResponses, function(){
						conn.query("DELETE FROM aa_triggers WHERE mci=? AND unit=? AND address=?", [mci, unit, address], async function(){
							await conn.query("UPDATE units SET count_aa_responses=IFNULL(count_aa_responses, 0)+? WHERE unit=?", [arrResponses.length, unit]);
							let objUnitProps = storage.assocStableUnits[unit];
							if (!objUnitProps)
								throw Error(`handlePrimaryAATrigger: unit ${unit} not found in cache`);
```

**File:** aa_composer.js (L158-163)
```javascript
	db.takeConnectionFromPool(function (conn) {
		conn.query("BEGIN", function () {
			storage.readAADefinition(conn, address, null, arrDefinition => {
				if (!arrDefinition)
					throw Error("AA not found: " + address)
				readLastUnit(conn, function (objMcUnit) {
```

**File:** aa_composer.js (L433-444)
```javascript
	if (template.base_aa) { // parameterized AA
		if (params && Object.keys(params).length > 0)
			throw Error("unexpected params");
		storage.readAADefinition(conn, template.base_aa, mci, function (arrBaseDefinition) {
			if (!arrBaseDefinition)
				throw Error("base AA not found: " + template.base_aa);
			console.log("redirecting to base AA " + template.base_aa + " with params " + JSON.stringify(template.params));
			trigger_opts.params = template.params;
			trigger_opts.arrDefinition = arrBaseDefinition;
			handleTrigger(trigger_opts);
		});
		return;
```
