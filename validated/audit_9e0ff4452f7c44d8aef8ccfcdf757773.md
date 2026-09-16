### Title
Race condition between in-memory DAG caches and their DB commit lets concurrent validation crash the node or diverge on unit/stability state - ([File: writer.js], [File: main_chain.js])

### Summary
`writer.saveJoint()` mutates the shared, process-global in-memory DAG caches (`storage.assocUnstableUnits`, `storage.assocBestChildren`, `storage.assocUnstableMessages`) synchronously, long before the SQL transaction that persists the same unit is actually committed or rolled back [1](#0-0) . Because Node.js is single-threaded but event-loop driven, and `saveJoint`'s remaining work (main-chain update, pre-commit callbacks, batch write, `COMMIT`/`ROLLBACK`) spans multiple asynchronous I/O steps [2](#0-1) [3](#0-2) , there is a window during which the new unit is "fast-path visible" in memory to any other concurrently running validation of a different unit/author, while the corresponding rows are not yet durable in the database (and may still be rolled back on error, at which point only a partial reset is performed) [4](#0-3) .

This is the same bug class as CVE-2024-26779: a fast/optimized code path (`fast-xmit` in the kernel, here the in-memory DAG cache used by `conf.bFaster`) is enabled/exposed to consumers before the underlying object is fully and durably committed, allowing use of not-yet-finalized state.

### Finding Description
`main_chain.readBestChildrenProps()` implements exactly such a fast path: if all requested units are already present in `storage.assocUnstableUnits`, it returns `storage.assocBestChildren` directly without touching the database at all [5](#0-4) . Otherwise it queries the DB and then asserts that the cache and the DB agree, calling `throwError()` (an unrecoverable, crash-inducing routine) if they don't [6](#0-5) .

The premise of this optimization is that `assocUnstableUnits`/`assocBestChildren` are always synchronized with what is durably committed to the DB. That premise is violated by `writer.saveJoint`, which populates these caches immediately after the raw INSERT queries are queued (`storage.assocUnstableUnits[objUnit.unit] = objNewUnitProps;` and pushing into `storage.assocBestChildren[my_best_parent_unit]`) [7](#0-6) , well before `main_chain.updateMainChain()` runs, before any `preCommitCallback` executes, before the KV batch write, and before the SQL `COMMIT` (or `ROLLBACK`) actually happens [8](#0-7) .

`validation.validate()` only serializes concurrent processing per *author address* (`mutex.lock(arrAuthorAddresses, ...)`) [9](#0-8) , not globally, so a second unit from a different author can be validated concurrently while the first unit's `saveJoint` is still mid-flight inside the `["write"]` mutex. That concurrent validation path (e.g. parent/stability checks in `main_chain.js`, which is reached from ordinary unit validation for every posted unit) can observe the first unit through the shared in-memory caches even though:
- the first unit's transaction may still fail and be rolled back, in which case cache cleanup is only partial (`delete storage.assocUnstableMessages[objUnit.unit]; await storage.resetMemory(conn);` — no explicit removal of the just-added `assocUnstableUnits`/`assocBestChildren` entries is shown at this call site) [4](#0-3) , or
- the first unit simply hasn't reached `COMMIT` yet, so a peer/DB reader relying on `db.query` instead of the cache would not yet see it, creating a cache/DB view mismatch across concurrently executing validation logic.

### Impact Explanation
Because `readBestChildrenProps` treats a cache/DB mismatch as fatal (`throwError`), a divergence created by this timing window can crash the node process during ordinary unit validation — an availability impact that can propagate to "node unable to confirm new units" if triggered broadly, or, more subtly, cause two nodes processing units in a different order/timing to compute different best-parent/witnessed-level/stability decisions for the same DAG state, i.e., node disagreement on validity/stability. Both outcomes are explicitly in-scope impact categories.

### Likelihood Explanation
Triggering the race only requires posting two (or more) units concurrently, from different authors, where the second unit's ancestry/parent-lookup logic in `main_chain.js` executes while the first unit's `saveJoint()` transaction is still in flight — an ordinary, unprivileged scenario reachable by any unit poster submitting overlapping units, without needing a malicious peer, hub, or operator privilege. The exact timing window (between synchronous cache mutation and final `COMMIT`/`ROLLBACK`) is real and multi-step, spanning several `async.series`/`await` boundaries, so it is plausible under normal network load rather than purely theoretical, though the frequency of a rollback/mismatch severe enough to hit `throwError` versus a benign eventual-consistency read cannot be fully confirmed from static analysis alone (I could not trace every downstream consumer of `assocBestChildren`/`assocUnstableUnits` to confirm how many paths lack the DB-cross-check safety net that `readBestChildrenProps` has).

### Recommendation
- Update (and roll back) the in-memory DAG caches (`assocUnstableUnits`, `assocBestChildren`, `assocUnstableMessages`) atomically with the SQL commit/rollback of `writer.saveJoint`, e.g. by deferring the cache mutation to the `commit_fn` success callback, or by fully reverting the specific entries added for `objUnit.unit` on the `err` branch instead of relying on a generic `storage.resetMemory(conn)`.
- Ensure any fast-path cache reader (like `readBestChildrenProps`) cannot be reached for a unit whose write transaction has not yet committed — e.g., gate cache use on a per-unit "committed" flag rather than mere presence in `assocUnstableUnits`.
- Broaden the `mutex.lock` scope so that unrelated concurrent unit validations cannot observe partially-written global caches mid-transaction, mirroring how the kernel fix added the missing `sta->uploaded` check before enabling the fast path.

### Proof of Concept
1. Submit unit A (author X) whose message set will cause `saveJoint`'s post-INSERT, pre-commit stage to take non-trivial time (e.g., contains data that triggers `main_chain.updateMainChain` work or a slow `preCommitCallback`, such as a private/indivisible-asset chain precommit) so the window between cache population (`writer.js:596-602`) and `COMMIT` (`writer.js:702`) is wide.
2. Concurrently submit unit B (author Y) that references unit A as `best_parent_unit`/parent, forcing `main_chain.readBestChildrenProps(conn, [A], ...)` to run while A's cache entries exist but A's row is not yet committed.
3. Force or wait for A's transaction to abort (e.g., by making its `preCommitCallback` fail), leaving the DB without A but with residual state assumptions baked into B's already-completed validation, or observe `readBestChildrenProps`'s `arraysEqual` check fail and `throwError()` crash the node when B's DB query (run after A's rollback) disagrees with the transient cache snapshot B had used.

### Citations

**File:** writer.js (L590-613)
```javascript
			var batch = bCordova ? null : (bInLargerTx ? objValidationState.batch : kvstore.batch());
			if (bGenesis){
				storage.assocStableUnits[objUnit.unit] = objNewUnitProps;
				storage.assocStableUnitsByMci[0] = [objNewUnitProps];
				console.log('storage.assocStableUnitsByMci', storage.assocStableUnitsByMci)
			}
			else
				storage.assocUnstableUnits[objUnit.unit] = objNewUnitProps;
			if (!bGenesis && storage.assocUnstableUnits[my_best_parent_unit]) {
				if (!storage.assocBestChildren[my_best_parent_unit])
					storage.assocBestChildren[my_best_parent_unit] = [];
				storage.assocBestChildren[my_best_parent_unit].push(objNewUnitProps);
			}
			if (objUnit.messages) {
				objUnit.messages.forEach(function(message) {
					if (['data_feed', 'definition', 'system_vote', 'system_vote_count'].includes(message.app)) {
						if (!storage.assocUnstableMessages[objUnit.unit])
							storage.assocUnstableMessages[objUnit.unit] = [];
						storage.assocUnstableMessages[objUnit.unit].push(message);
						if (message.app === 'system_vote' && !objValidationState.bDryRun)
							eventBus.emit('system_var_vote', message.payload.subject, message.payload.value, arrAuthorAddresses, objUnit.unit, 0);
					}
				});
			}
```

**File:** writer.js (L614-716)
```javascript
			addInlinePaymentQueries(function(){
				async.series(arrQueries, function(){
					profiler.stop('write-raw');
					var arrOps = [];
					if (1 || objUnit.parent_units){ // genesis too
						if (!conf.bLight){
							if (objValidationState.bAA) {
								if (!objValidationState.initial_trigger_mci)
									throw Error("no initial_trigger_mci");
								var arrAADefinitionPayloads = objUnit.messages.filter(function (message) { return (message.app === 'definition'); }).map(function (message) { return message.payload; });
								if (arrAADefinitionPayloads.length > 0) {
									arrOps.push(function (cb) {
										console.log("inserting new AAs defined by an AA after adding " + objUnit.unit);
										storage.insertAADefinitions(conn, arrAADefinitionPayloads, objUnit.unit, objValidationState.initial_trigger_mci, objValidationState.initial_trigger_mci, true, cb, objValidationState.bDryRun);
									});
								}
							}
							if (!conf.bFaster)
								arrOps.push(updateBestParent);
							arrOps.push(updateLevel);
							if (!conf.bFaster)
								arrOps.push(updateWitnessedLevel);
							// will throw just after the upgrade
						//	if (!objValidationState.last_ball_timestamp && objValidationState.last_ball_mci >= constants.timestampUpgradeMci && !bGenesis)
						//		throw Error("no last_ball_timestamp");
							if (objValidationState.bHasSystemVoteCount && objValidationState.sequence === 'good') {
								const m = objUnit.messages.find(m => m.app === 'system_vote_count');
								if (!m)
									throw Error(`system_vote_count message not found`);
								if (m.payload === 'op_list')
									arrOps.push(cb => main_chain.applyEmergencyOpListChange(conn, objUnit.timestamp, cb));
							}
							arrOps.push(function(cb){
								console.log("updating MC after adding "+objUnit.unit);
								main_chain.updateMainChain(conn, batch, null, objUnit.unit, objValidationState.bAA, (_arrStabilizedMcis, _bStabilizedAATriggers) => {
									arrStabilizedMcis = _arrStabilizedMcis;
									bStabilizedAATriggers = _bStabilizedAATriggers;
									cb();
								});
							});
						}
						if (preCommitCallback)
							arrOps.push(function(cb){
								console.log("executing pre-commit callback");
								preCommitCallback(conn, cb);
							});
					}
					// only preCommitCallback can return err
					async.series(arrOps, function(err){
						profiler.start();
						
						function saveToKvStore(cb){
							if (err && bInLargerTx)
								throw Error("error on externally supplied db connection: "+err);
							if (err)
								return cb();
							// moved up
							/*if (objUnit.messages){
								objUnit.messages.forEach(function(message){
									if (['data_feed', 'definition', 'system_vote', 'system_vote_count'].includes(message.app)) {
										if (!storage.assocUnstableMessages[objUnit.unit])
											storage.assocUnstableMessages[objUnit.unit] = [];
										storage.assocUnstableMessages[objUnit.unit].push(message);
									}
								});
							}*/
							if (!conf.bLight){
							//	delete objUnit.timestamp;
								delete objUnit.main_chain_index;
								delete objUnit.actual_tps_fee;
							}
							if (bCordova) // already written to joints table
								return cb();
							var batch_start_time = Date.now();
							batch.put('j\n'+objUnit.unit, JSON.stringify(objJoint));
							if (bInLargerTx)
								return cb();
							batch.write({ sync: true }, function(err){
								console.log("batch write took "+(Date.now()-batch_start_time)+'ms');
								if (err)
									throw Error("writer: batch write failed: "+err);
								cb();
							});
						}
						
						saveToKvStore(function(){
							profiler.stop('write-batch-write');
							profiler.start();
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
								if (!bInLargerTx)
									conn.release();
								if (!err && !objValidationState.bDryRun){
```

**File:** main_chain.js (L704-712)
```javascript
function readBestChildrenProps(conn, arrUnits, handleResult){
	if (arrUnits.every(function(unit){ return !!storage.assocUnstableUnits[unit]; })){
		var arrProps = [];
		arrUnits.forEach(function(unit){
			if (storage.assocBestChildren[unit])
				arrProps = arrProps.concat(storage.assocBestChildren[unit]);
		});
		return handleResult(arrProps);
	}
```

**File:** main_chain.js (L713-722)
```javascript
	conn.query("SELECT unit, is_on_main_chain, main_chain_index, latest_included_mc_index, level, witnessed_level, is_free FROM units WHERE best_parent_unit IN(?)", [arrUnits], function(rows){
		if (arrUnits.every(function(unit){ return !!storage.assocUnstableUnits[unit]; })){
			var arrProps = [];
			arrUnits.forEach(function(unit){
				if (storage.assocBestChildren[unit])
					arrProps = arrProps.concat(storage.assocBestChildren[unit]);
			});
			if (!arraysEqual(_.sortBy(rows, 'unit'), _.sortBy(arrProps, 'unit'), ['unit', 'is_on_main_chain', 'main_chain_index', 'latest_included_mc_index', 'level', 'witnessed_level', 'is_free']))
				throwError("different best children of "+arrUnits.join(', ')+": db "+JSON.stringify(rows)+", mem "+JSON.stringify(arrProps));
		}
```

**File:** validation.js (L357-357)
```javascript
	mutex.lock(arrAuthorAddresses, function(unlock){
```
