### Title
Global "write" mutex is never released when a RocksDB batch write fails during unit/AA-trigger saving - ([File: writer.js])

### Summary
`writer.saveJoint()` acquires the process-wide `"write"` mutex before persisting a unit, but the completion callback of the RocksDB `batch.write()` call throws an `Error` instead of releasing that mutex when the write fails. The same defective pattern is reused for AA-trigger persistence in `aa_composer.js`. Because the throw happens inside an asynchronous native-binding callback, it is never caught by the surrounding `async.series`/`saveToKvStore` control flow, so `unlock()` is never reached and the `"write"` lock is held forever.

### Finding Description
`saveJoint()` takes the sole global write lock used by the whole node for persisting units: [1](#0-0) 

Deep inside the same function, once all SQL and pre-commit steps succeed, the joint is written to the RocksDB batch and the batch is flushed: [2](#0-1) 

If `batch.write` returns an error (I/O failure, disk full, corrupted RocksDB `.sync` write, etc.), the callback does `throw Error(...)` instead of calling `cb()`. This throw occurs inside the RocksDB native binding's own completion callback, not inside any `try/catch` that could route the error back to `saveToKvStore`'s caller. `cb()` is never invoked, so `saveToKvStore(function(){ ... unlock(); })`'s continuation (line 699, ending in `unlock()` at line 776) never executes: [3](#0-2) [4](#0-3) 

The identical anti-pattern exists in AA-trigger persistence, which is invoked from inside `saveJoint()` (via `aa_composer.handleAATriggers()` at line 727) while the same `"write"` mutex is still held: [5](#0-4) [6](#0-5) 

`mutex.js` implements locking purely as an in-process array with no timeout or watchdog — once a key is pushed and never released, every future caller of `mutex.lock(["write"], ...)` queues forever: [7](#0-6) 

The `"write"` lock is not a niche lock — it serializes every unit save across the entire node: base payments, divisible/indivisible asset payments, and AA-trigger execution all route through `saveJoint()` and thus through this same mutex key.

This is a direct structural analog of BIT-mariadb-2022-38791: `compress_write` failing to release `data_mutex` on a stream-write failure, causing a permanent deadlock. Here, `batch.write`'s failure callback fails to release the equivalent serialization primitive (`mutex.lock(["write"])`) that gates all unit persistence.

### Impact Explanation
If the underlying RocksDB write ever fails (disk full, disk I/O error, corrupted database, storage device going read-only, etc.) while any unit — including one submitted by an ordinary unprivileged unit poster or triggered by any AA-trigger sender — is being saved, the `"write"` mutex is left locked permanently. From that point on:
- No further units can be validated and saved (`writer.saveJoint` blocks forever waiting for the lock).
- No further AA triggers can execute.
- No further MC stabilization can occur (also gated behind the same write path).

This matches the "network unable to confirm new units" impact category: the affected node stalls indefinitely and cannot process new joints, even though the rest of the process may keep running (Node does not necessarily crash on an uncaught exception thrown from a native-addon callback if any process-level exception handling exists elsewhere, and even if it does crash and restart, a subsequent occurrence during heavy disk pressure will repeat the same freeze — this is a genuine correctness/liveness bug in the locking discipline regardless of process survival).

### Likelihood Explanation
Disk-write failures are not attacker-arbitrary, but they are a realistic and externally-influenceable local condition: AA state variables, data feeds, and unit payloads are all written through this exact RocksDB batch path, and an attacker who can drive disk usage up (e.g., via AA state growth, spamming units/triggers) increases the probability of hitting a disk-full or write-failure condition at precisely the moment `batch.write` executes. Given the “write” mutex is exercised on every single unit save, the exposure window is effectively 100% of the node's write traffic, so any transient storage failure — however triggered — reliably wedges the node rather than being contained/retried.

### Recommendation
- In `writer.js` (`saveToKvStore`, lines 691-696) and `aa_composer.js` (`handlePrimaryAATrigger`, lines 111-114), replace the `throw Error(...)` on `batch.write` failure with proper error propagation: call `cb(err)`/an error callback that still reaches the code path invoking `unlock()`/`conn.release()`, or wrap the whole `saveJoint` operation in a `try/finally` that unconditionally releases the `"write"` mutex.
- Apply the same fix to the other `throw Error("writer: batch write failed...")` and `throw Error('error from data stream...')` occurrences in `kvstore.js`, `sqlite_migrations.js`, and `migrate_to_kv.js` that sit inside functions holding mutexes (`checkStorageSizes`, `checkBalances`, `addTypesToStateVars`), so that any lock acquired before the failing I/O operation is guaranteed to be released even on error.
- Consider adding a lock-acquisition timeout/watchdog in `mutex.js` so a stuck lock does not permanently wedge the node.

### Proof of Concept
1. Configure or force the node's RocksDB store to fail on the next write (e.g., simulate `ENOSPC`/disk-full, or corrupt the underlying rocksdb files so the native `batch.write` callback returns an error) — this can plausibly be induced by an attacker flooding AA state variables/data feeds to exhaust disk space on a resource-constrained node.
2. Post (or trigger, via an AA call) any valid unit so that `writer.saveJoint()` is invoked and acquires `mutex.lock(["write"])` (`writer.js:34`).
3. When `batch.write({ sync: true }, ...)` at `writer.js:691` returns an error, the callback executes `throw Error("writer: batch write failed: "+err)` (`writer.js:693-694`) instead of calling `cb()`.
4. Observe that `unlock()` at `writer.js:776` is never reached — `arrLockedKeyArrays` in `mutex.js` retains the `["write"]` entry forever.
5. Post any subsequent unit; `mutex.lock(["write"], ...)` queues indefinitely because `isAnyOfKeysLocked` always finds `"write"` locked (`mutex.js:34-59`), so the node can never validate/save another unit — the node stops confirming new units.

### Citations

**File:** writer.js (L34-35)
```javascript
	const unlock = objValidationState.bUnderWriteLock ? () => { } : await mutex.lock(["write"]);
	console.log("got lock to write " + objUnit.unit);
```

**File:** writer.js (L687-696)
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
```

**File:** writer.js (L699-702)
```javascript
						saveToKvStore(function(){
							profiler.stop('write-batch-write');
							profiler.start();
							commit_fn(err ? "ROLLBACK" : "COMMIT", async function(){
```

**File:** writer.js (L724-727)
```javascript
								if (bStabilizedAATriggers && !err) {
									console.log(`executing AA triggers`);
									const aa_composer = require("./aa_composer.js");
									await aa_composer.handleAATriggers();
```

**File:** writer.js (L771-777)
```javascript
								if (onDone)
									onDone(err);
								count_writes++;
								if (conf.storage === 'sqlite')
									updateSqliteStats(objUnit.unit);
								unlock();
							});
```

**File:** aa_composer.js (L110-116)
```javascript
							var batch_start_time = Date.now();
							batch.write({ sync: true }, function(err){
								console.log("AA batch write took "+(Date.now()-batch_start_time)+'ms');
								if (err)
									throw Error("AA composer: batch write failed: "+err);
								conn.query("COMMIT", function () {
									conn.release();
```

**File:** mutex.js (L34-59)
```javascript
function release(arrKeys){
	for (var i=0; i<arrLockedKeyArrays.length; i++){
		if (_.isEqual(arrKeys, arrLockedKeyArrays[i])){
			arrLockedKeyArrays.splice(i, 1);
			return;
		}
	}
}

function exec(arrKeys, proc, next_proc){
	arrLockedKeyArrays.push(arrKeys);
	console.log("lock acquired", arrKeys);
	var bLocked = true;
	proc(function unlock(unlock_msg) {
		if (!bLocked)
			throw Error("double unlock?");
		if (unlock_msg)
			console.log(unlock_msg);
		bLocked = false;
		release(arrKeys);
		console.log("lock released", arrKeys);
		if (next_proc)
			next_proc.apply(next_proc, arguments);
		handleQueue();
	});
}
```
