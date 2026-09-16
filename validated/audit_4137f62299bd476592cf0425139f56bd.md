## Title
Non-atomic KV-store batch flush before SQL COMMIT allows durable RocksDB metadata that outlives a rolled-back/crashed unit or stabilization transaction - ([File: writer.js], [File: main_chain.js])

### Summary
The btrfs bug fixes a class of issue where dirty metadata is durably written to disk after the filesystem is already in an error/inconsistent state, because the write path does not gate on that state before flushing. `ocore` has an analogous two-phase-commit hazard: unit/stabilization writes are split across a SQL transaction (`units`, `aa_responses`, `system_votes`, etc.) and a separate RocksDB batch (`kvstore`) holding joints, AA state vars, and data feeds. In several places the RocksDB batch is flushed with `sync: true` **before** the corresponding SQL `COMMIT`, so a crash or unhandled exception between the two operations durably persists RocksDB data for a unit/MCI whose SQL-side commit never happened (and is rolled back on restart).

### Finding Description
In `writer.js`'s `saveJoint()`, the kvstore batch (built up during `main_chain.updateMainChain`, which via `markMcIndexStable` performs `batch.put(...)` for data feeds/state-vars/joints) is written to disk with `batch.write({ sync: true }, ...)` and only afterwards does the code call `commit_fn(err ? "ROLLBACK" : "COMMIT", ...)` to finalize the SQL side: [1](#0-0) 

The same ordering (KV `batch.write` durably flushed, *then* SQL `COMMIT`) recurs in the MC-stabilization loop that runs after every unit save, and in `main_chain.js`'s `stabilizeMci()`: [2](#0-1) [3](#0-2) 

`markMcIndexStable` itself mutates in-memory caches (`storage.assocStableUnits`, `assocUnstableUnits`) and issues `batch.put` for data feeds and system votes as part of the same batch that later gets flushed to RocksDB with `sync: true`: [4](#0-3) [5](#0-4) 

Because RocksDB's `sync: true` write is a real fsync to disk (analogous to btrfs's real metadata writeback), and the SQL `COMMIT` happens strictly afterward, any interruption between these two operations (process crash, OOM kill, unhandled exception in an `arrOp` such as the numerous synchronous `throw Error(...)` calls scattered through `updateMainChain`/`markMcIndexStable`/`writer.js`, or an unexpected DB error at commit time) leaves:
- RocksDB permanently containing joints (`j\n<unit>`), AA state vars, and data-feed index entries for a unit/MCI, **and**
- SQL having rolled back (or never committed) the corresponding `is_stable`, `sequence`, `aa_responses`, and `system_votes` rows.

On restart, SQL is the source of truth for caches like `assocStableUnits`/`assocUnstableUnits` (rebuilt from SQL), but RocksDB read paths (`storage.readAAStateVars`, data-feed lookups via `df\n`/`dfv\n` keys, `readAsset`/`readJoint` via `j\n` keys) will still return the now-orphaned, never-officially-committed data. This is precisely the class of bug btrfs fixed: writeback of dirty metadata that should have been discarded because the transaction it belonged to never completed.

### Impact Explanation
An orphaned-but-durable RocksDB write for a unit that SQL considers unstable/non-existent can produce:
- Data feed queries (`data_feed[[...]]` in oscript) returning values from a unit that isn't actually stable per SQL, letting an AA compute against wrong/premature data feed values → AA fund loss or unintended payouts.
- AA state vars diverging between nodes that crashed at different points in the pipeline, so the same trigger produces different results on different nodes → node disagreement on validity/stability of the resulting AA response units, which the DAG consensus protocol assumes are deterministic across all nodes.
- Persisted `j\n<unit>` joint content for a unit whose SQL row was rolled back, which could later confuse re-processing/catch-up logic that assumes `kvstore` and SQL states are in lock-step.

This crosses the "node disagreement on validity or stability" bar in the validation rules, since any two nodes that crash/restart at slightly different points during the exact same stabilization sequence can end up with different derived AA/data-feed state that is invisible to SQL-level consistency checks.

### Likelihood Explanation
This is not an attacker-controlled trigger in the classic sense; it requires an interruption (crash, kill, unhandled exception) between the two writes rather than being remotely forced by a single malicious unit. Numerous unconditional `throw Error(...)` statements exist inside the exact code paths that run between batch population and the final SQL commit (e.g., `updateMainChain`'s `throwError` calls, `system_vote_count message not found`, `markMcIndexStable`'s `unrecognized app in unstable message`), any of which — if hit due to a subtly malformed but validation-passing unit crafted by an ordinary unit poster — becomes an uncaught exception in a live production node, which in most deployments terminates the Node.js process. That gives an unprivileged unit poster a realistic path to force the interruption at exactly the vulnerable point (right after `batch.write` flushed but before SQL `COMMIT` executes), since these throws occur inside the async pipeline stages that run before the batch flush in `saveJoint`, and in the post-flush pipeline stages of the "try to stabilize more MCIs" loop.

### Recommendation
- Reorder operations so the RocksDB batch is only flushed with `sync: true` *after* the SQL `COMMIT` has succeeded, or make the two writes recoverable/idempotent (e.g., write a durable "pending" marker first, and only apply real state after both sides confirm).
- On startup, cross-validate RocksDB `stable`/`data_feed`/`state var` writes against the SQL `is_stable`/`main_chain_index` state for the corresponding MCI/unit, and roll back or ignore any writes for units SQL doesn't consider committed/stable.
- Convert the unconditional `throw Error(...)` calls in `main_chain.js`/`writer.js` critical sections into propagated `err` values (or wrap with crash-safe handling) so a malformed-but-validation-passing unit cannot trivially crash the process at the precise moment between the KV flush and SQL commit.

### Proof of Concept
Not independently reproducible from static analysis alone — reproducing this requires (1) crafting or identifying a unit that passes `validation.js` but triggers one of the synchronous `throw Error(...)` statements inside `main_chain.updateMainChain`/`markMcIndexStable` (or otherwise crashing the process) at the moment right after `batch.write({ sync: true }, ...)` in `writer.js` line 691 (or the `advanceMcStability` loop's `batch.write` at line 749) has completed but before the following `conn.query("COMMIT")` completes, and (2) restarting the node to observe that RocksDB-held AA state vars / data feed entries for that unit persist while the SQL `units.is_stable` row was rolled back. I was not able to fully verify at what exact code offsets an uncaught exception in Node.js terminates the process versus being caught by `async.series`, so this likelihood assessment carries moderate uncertainty; a Devin session with full source and a controllable test harness (able to trigger a mid-pipeline crash) would be needed to confirm exploitability end-to-end.

### Citations

**File:** writer.js (L687-702)
```javascript
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
```

**File:** writer.js (L741-751)
```javascript
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
```

**File:** main_chain.js (L1263-1270)
```javascript
async function stabilizeMci(mci) {
	const conn = await db.takeConnectionFromPool();
	await conn.query("BEGIN");
	const batch = kvstore.batch();
	const count_aa_triggers = await markMcIndexStable(conn, batch, mci);
	await util.promisify(batch.write.bind(batch))({ sync: true });
	await conn.query("COMMIT");
	conn.release();
```

**File:** main_chain.js (L1288-1316)
```javascript
function markMcIndexStable(conn, batch, mci, onDone){
	if (!onDone)
		return new Promise(resolve => markMcIndexStable(conn, batch, mci, resolve));
	profiler.start();
	let count_aa_triggers;
	var arrStabilizedUnits = [];
	if (mci > 0)
		storage.assocStableUnitsByMci[mci] = [];
	for (var unit in storage.assocUnstableUnits){
		var o = storage.assocUnstableUnits[unit];
		if (o.main_chain_index === mci && o.is_stable === 0){
			o.is_stable = 1;
			storage.assocStableUnits[unit] = o;
			storage.assocStableUnitsByMci[mci].push(o);
			arrStabilizedUnits.push(unit);
		}
	}
	arrStabilizedUnits.forEach(function(unit){
		delete storage.assocUnstableUnits[unit];
	});
	conn.query(
		"UPDATE units SET is_stable=1 WHERE is_stable=0 AND main_chain_index=?", 
		[mci], 
		function(){
			// next op
			handleNonserialUnits();
		}
	);

```

**File:** main_chain.js (L1607-1616)
```javascript
										arrAuthorAddresses.forEach(function(address){
											// duplicates will be overwritten, that's ok for data feed search
											if (strValue !== null)
												batch.put('df\n'+address+'\n'+feed_name+'\ns\n'+strValue+'\n'+strMci, unit);
											if (numValue !== null)
												batch.put('df\n'+address+'\n'+feed_name+'\nn\n'+numValue+'\n'+strMci, unit);
											// if several values posted on the same mci, the latest one wins
											batch.put('dfv\n'+address+'\n'+feed_name+'\n'+strMci, value+'\n'+unit);
										});
									}
```
