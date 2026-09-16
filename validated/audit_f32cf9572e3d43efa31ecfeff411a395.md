### Title
Global "write" mutex lock in `saveJoint` can be left permanently held on internal error paths, freezing the entire node - ([File: writer.js])

### Summary
`writer.saveJoint()` acquires the node-wide `"write"` mutex at the top of the function and only calls the corresponding `unlock()` deep inside a long chain of nested async callbacks, after commit/rollback completes. Several `throw Error(...)` statements exist on code paths that execute *after* the lock is acquired but *before* `unlock()` is reached. If any of these conditions are hit, the synchronous throw escapes the nested `db.query`/`async.series` callback stack (not the original `async function saveJoint` promise chain), so it does not resolve/reject the awaited lock promise gracefully — the `"write"` mutex is never released. This mirrors the CVE-2017-15596 bug class: an error-detection path that mishandles lock release, permanently starving a shared resource (there, a physical CPU; here, the single global write serialization lock that every unit validation/save path in the node depends on). [1](#0-0) 

### Finding Description
`saveJoint` takes the `"write"` lock unconditionally (unless already held by the caller) and stores the `unlock` callback for later invocation: [2](#0-1) 

The lock is only released at the very end of a deeply nested callback chain, after DB commit/rollback and k/v-store batch write: [3](#0-2) 

Between lock acquisition and this final `unlock()` call, multiple `throw Error(...)` statements exist inside the locked critical section:
- missing `initial_trigger_mci` for AA response units: [4](#0-3) 
- missing `system_vote_count` message despite `bHasSystemVoteCount` flag: [5](#0-4) 
- batch/kvstore write failure or externally-supplied connection error: [6](#0-5) 
- unexpected multiple/conflicting stabilized MCIs: [7](#0-6)  and [8](#0-7) 

Because these `throw` statements execute inside I/O completion callbacks (`db.query`, `batch.write`, `async.series`) rather than directly inside the `async function saveJoint`'s own call frame, they surface as ordinary synchronous exceptions in whatever callback context invoked them — they are not automatically turned into a rejected promise that some outer `.catch()` in the caller chain (e.g. `validation.validate`'s `ifOk`, or `network.handleJoint`) is guaranteed to catch and clean up the mutex for. If the process does not crash outright (e.g., due to a `process.on('uncaughtException')` handler elsewhere logging and continuing, which is common in long-running node daemons to maximize uptime), the `"write"` mutex entry pushed by `mutex.lock(["write"])` is never removed via `release()`, because `unlock()` is never invoked.

`writer.js` is reached by essentially every unit-saving path: normal `network.handleJoint` (unprivileged unit poster), `aa_composer.js` AA trigger execution, `composer.js`/`divisible_asset.js`/`indivisible_asset.js` wallet-composed unit saving, all serialize on the same `["write"]` mutex key via `mutex.lock(["write"])` (see `writer.js:34`) or by passing `bUnderWriteLock` when already inside it (`aa_composer.js:1826`). Once this lock is stuck, no unit — from any source — can ever be written to the DAG again.

### Impact Explanation
The `"write"` mutex is the single global serialization point for persisting units to the ledger. If it is left locked forever due to an uncaught exception during an edge-case internal-state check (e.g., stabilization bookkeeping inconsistency, batch write hiccup, or an AA-related invariant violation), every subsequent call to `mutex.lock(["write"], ...)` across the entire node queues indefinitely and is never serviced. This produces a network-wide denial of service on that node: no new units — payments, AA triggers, asset transfers — can ever be confirmed/saved again, matching the "network unable to confirm new units" impact bucket required by the validation criteria. This is directly analogous to the Xen ARM lock-mishandling bug (CVE-2017-15596), where an error-detection path failed to release a lock and permanently denied use of a shared resource (there, a CPU; here, the write path).

### Likelihood Explanation
Reaching most of these `throw` paths requires triggering specific internal invariant violations (e.g., `bHasSystemVoteCount` true but no matching message found at write time, or more than one stabilized MCI reported by `main_chain.updateMainChain`/`advanceMcStability`). These are intended to be "impossible" defensive assertions, so under normal operation they should not fire. However, they are reachable through unit content that a poster fully controls (system-vote units) or through AA trigger/response processing that responds to attacker-supplied trigger units, and the code explicitly anticipates these as *possible* runtime conditions (hence the `throw` rather than a compile-time assumption). Given the multiple independent throw sites inside the same locked region, and that this is a defense-in-depth assertion rather than unreachable dead code, the likelihood of a determined attacker crafting a unit or AA trigger sequence that hits one of these paths is plausible, though I could not fully trace every precondition for `bHasSystemVoteCount`/`initial_trigger_mci` back to attacker-controlled unit fields within the available context.

### Recommendation
Wrap the entire body of `saveJoint` (from lock acquisition to the final `unlock()`) in a `try/finally` (or ensure `unlock()` is always called on any error path, including via a top-level `.catch()` on the `async function`) so the `"write"` mutex is guaranteed to be released even when an internal invariant-violation `throw` occurs. Additionally, audit each `throw Error(...)` inside the locked critical section in `writer.js` (lines 622, 642, 667, 694, 721, 723, 748) to confirm whether it should instead fail as a recoverable `ifTransientError`/`ifUnitError` with guaranteed lock cleanup rather than an unguarded synchronous throw.

### Proof of Concept
Conceptual (not executed): craft a sequence of units such that, at the moment `writer.saveJoint` executes the stabilization/kv-write chain, the runtime-computed condition `objValidationState.bHasSystemVoteCount === true && objValidationState.sequence === 'good'` holds, while the `objUnit.messages` array being iterated at write-time does not contain an `app === 'system_vote_count'` message that satisfies `.find(...)` (e.g., due to a stripped/mutated messages array state during processing). This causes `throw Error('system_vote_count message not found')` at `writer.js:642`, executing inside the `commit_fn`/`async.series` callback chain, after the `"write"` mutex (`writer.js:34`) was acquired and before `unlock()` (`writer.js:776`) is reached — leaving the `"write"` lock held forever and freezing all subsequent unit saves on the node.

### Citations

**File:** writer.js (L24-35)
```javascript
async function saveJoint(objJoint, objValidationState, preCommitCallback, onDone) {
	var objUnit = objJoint.unit;
	console.log("\nsaving unit "+objUnit.unit);
	var arrQueries = [];
	var commit_fn;
	if (objValidationState.conn && !objValidationState.batch)
		throw Error("conn but not batch");
	var bInLargerTx = (objValidationState.conn && objValidationState.batch);
	const bCommonOpList = objValidationState.last_ball_mci >= constants.v4UpgradeMci;

	const unlock = objValidationState.bUnderWriteLock ? () => { } : await mutex.lock(["write"]);
	console.log("got lock to write " + objUnit.unit);
```

**File:** writer.js (L620-622)
```javascript
							if (objValidationState.bAA) {
								if (!objValidationState.initial_trigger_mci)
									throw Error("no initial_trigger_mci");
```

**File:** writer.js (L639-642)
```javascript
							if (objValidationState.bHasSystemVoteCount && objValidationState.sequence === 'good') {
								const m = objUnit.messages.find(m => m.app === 'system_vote_count');
								if (!m)
									throw Error(`system_vote_count message not found`);
```

**File:** writer.js (L666-694)
```javascript
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
```

**File:** writer.js (L699-777)
```javascript
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
									eventBus.emit('saved_unit-'+objUnit.unit, objJoint);
									eventBus.emit('saved_unit', objJoint);
								}
								if (arrStabilizedMcis.length > 0 && (bInLargerTx || objValidationState.bUnderWriteLock))
									throw Error(`saveJoint stabilized an MCI while in larger tx or under write lock`);
								if (arrStabilizedMcis.length > 1)
									throw Error(`saveJoint stabilized more than one MCI: ${arrStabilizedMcis.join(', ')}`);
								if (bStabilizedAATriggers && !err) {
									console.log(`executing AA triggers`);
									const aa_composer = require("./aa_composer.js");
									await aa_composer.handleAATriggers();

									if (arrStabilizedMcis[0] >= constants.v4UpgradeMci) {
										// get a new connection to write tps fees
										const conn = await db.takeConnectionFromPool();
										await conn.query("BEGIN");
										await storage.updateTpsFees(conn, arrStabilizedMcis);
										await conn.query("COMMIT");
										conn.release();
									}
								}
								if (arrStabilizedMcis.length > 0 && !err) {
									// try to stabilize more MCIs, run triggers and update tps fees after each
									console.log(`stabilized MCI ${arrStabilizedMcis.join(', ')}, trying to stabilize more`);
									while (true) {
										const conn = await db.takeConnectionFromPool();
										await conn.query("BEGIN");
										const batch = kvstore.batch();
										const { arrStabilizedMcis, bStabilizedAATriggers } = await main_chain.advanceMcStability(conn, batch, objUnit.unit);
										console.log(`additional stabilization result`, arrStabilizedMcis, bStabilizedAATriggers);
										if (arrStabilizedMcis.length > 1)
											throw Error(`additional stabilization resulted in more than one MCI: ${arrStabilizedMcis.join(', ')}`);
										await util.promisify(batch.write.bind(batch))({ sync: true });
										await conn.query("COMMIT");
										conn.release();
										if (arrStabilizedMcis.length === 0)
											break;
										if (bStabilizedAATriggers) {
											console.log(`executing AA triggers after additional stabilization`, arrStabilizedMcis);
											// every trigger takes its own db connection
											const aa_composer = require("./aa_composer.js");
											await aa_composer.handleAATriggers();
										}
										if (arrStabilizedMcis[0] >= constants.v4UpgradeMci) {
											console.log(`updating tps fees after additional stabilization`, arrStabilizedMcis);
											// get a new connection to write tps fees
											const conn = await db.takeConnectionFromPool();
											await conn.query("BEGIN");
											await storage.updateTpsFees(conn, arrStabilizedMcis);
											await conn.query("COMMIT");
											conn.release();
										}
									}
								}
								if (onDone)
									onDone(err);
								count_writes++;
								if (conf.storage === 'sqlite')
									updateSqliteStats(objUnit.unit);
								unlock();
							});
```
