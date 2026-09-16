### Title
Global `write` mutex is never released if an exception is thrown between lock acquisition and the single `unlock()` call in `saveJoint` - (File: writer.js)

### Summary
`writer.saveJoint()` acquires the global `write` mutex once at the top of the function and releases it via a single `unlock()` call at the very end of a long asynchronous callback chain. Any exception thrown anywhere along that chain — and there are more than 30 `throw Error(...)` statements scattered through the queries, level/witnessed-level computation, MC update, and post-stabilization logic that runs before `unlock()` — permanently deadlocks the `write` lock, mirroring the MariaDB `ds_compress.cc` bug class where an error path skips releasing a held lock.

### Finding Description
`saveJoint` takes the `write` lock (or a no-op if `objValidationState.bUnderWriteLock`) before doing any work: [1](#0-0) 
The lock is released exactly once, at the tail end of the deeply nested `async.series`/callback chain, inside `commit_fn`'s completion callback: [2](#0-1) 

Between these two points the function performs many synchronous operations that can `throw`, e.g. in `determineInputAddressFromSrcOutput`, `updateBestParent`, `updateLevel`, `updateWitnessedLevelByWitnesslist`, and the post-commit stabilization/AA-trigger loop: [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7) 

None of these `throw` statements are wrapped in a `try/catch` that releases the `write` mutex before propagating; the code relies entirely on reaching the single success/near-tail path to call `unlock()`. Because `saveJoint` is invoked directly from the unit-validation success path (`validation.validate`'s `ifOk` callback in `network.js`'s `handleJoint`, from `composer.js`, `divisible_asset.js`, `indivisible_asset.js`, and from AA trigger execution in `aa_composer.js`), a single crafted/edge-case unit (or AA trigger causing a stabilization edge case) that trips one of these invariant checks (e.g. `"different best parents"`, `"different max level"`, `"different witnessed levels"`, `"saveJoint stabilized an MCI while in larger tx or under write lock"`, `"additional stabilization resulted in more than one MCI"`) throws inside the mutex-held region without ever calling `unlock()`.

`mutex.lock`/`mutex.exec` provides no exception safety either — it just invokes `proc(unlock)` with no `try/finally`, so a thrown exception inside `proc` propagates up without invoking `unlock`, leaving the key permanently marked as locked in `arrLockedKeyArrays`: [9](#0-8) 

### Impact Explanation
The `write` mutex serializes every call to `writer.saveJoint`, which is the single choke point for committing any unit (public payments, AA triggers, asset issuance, etc.) to the DAG. Once the lock is stuck, `mutex.lock(["write"], ...)` calls from all subsequent `saveJoint` invocations queue forever and are never serviced (`handleQueue` only fires on `unlock`), meaning the node can no longer confirm or commit any new unit — a full node-wide denial of service that stops it from processing the network. This matches the required "network unable to confirm new units" impact bar for this class of bug and is directly analogous to the referenced MariaDB deadlock CVE, where an error path failed to release a held lock, causing a hang.

### Likelihood Explanation
Any process that throws uncaught exceptions is typically a `process.on('uncaughtException')`-level crash in Node, which in most deployments restarts the process — that would reset the mutex state on restart, somewhat limiting persistence of the deadlock across restarts. However, several of the throw sites are reachable via legitimate error paths that a node operator or attacker-influenced conditions (race in level/witnessed-level bookkeeping, stabilization edge cases involving AA triggers) can hit without necessarily crashing the whole process if the throw is caught by an outer handler (e.g. inside `async.series`'s callback context or a `Promise` chain that swallows it as an unhandled rejection depending on Node version/configuration). Given the number of invariant-violation throws deep inside the locked section, and that this file underwent recent refactoring (`async`/`await` mixed with old-style `async.series`, several `//` commented-out `mutex.lock` wrappers suggesting this exact hazard was previously handled explicitly), the likelihood of hitting one of these edge cases under contention (concurrent unstable structure changes, AA trigger cascades, or crafted units causing "different levels"/"different witnessed levels" mismatches) is non-trivial for a network processing arbitrary posted units.

### Recommendation
Wrap the entire body of `saveJoint` (or at minimum every code path between lock acquisition and the final `unlock()`) in a `try/finally` (or ensure `mutex.exec`/`mutex.lock` itself guarantees `unlock` runs on thrown exceptions), so that any `throw Error(...)` releases the `write` lock before propagating. Additionally, harden `mutex.exec` in `mutex.js` to call `release(arrKeys)` and `handleQueue()` in a `finally` block around `proc(unlock)`, so a single caller's uncaught exception cannot deadlock the whole node.

### Proof of Concept
Conceptual PoC (cannot be executed without live node access):
1. Trigger a code path that causes `writer.saveJoint` to hit one of the mid-function invariant checks, e.g. cause `updateWitnessedLevelByWitnesslist`'s `setWitnessedLevel` to compute a `witnessed_level` different from `objValidationState.witnessed_level` (line 511) — achievable by racing two units that mutate best-parent/witness list state concurrently, or by an AA-trigger-caused stabilization pass computing `arrStabilizedMcis.length > 1` (line 723) or `> 1` additional stabilization (line 748).
2. When `throwError`/`throw Error(...)` fires, the enclosing `mutex.lock(["write"], ...)` frame from `writer.js:34` never reaches `unlock()` at line 776.
3. Observe subsequent unit submissions/AA trigger executions hang indefinitely because `mutex.lock(["write"], ...)` queues forever (`mutex.js:75-85`), confirmed by the periodic diagnostic log at `mutex.js:118-121` showing a permanently non-empty `locked keys` list.

### Citations

**File:** writer.js (L34-35)
```javascript
	const unlock = objValidationState.bUnderWriteLock ? () => { } : await mutex.lock(["write"]);
	console.log("got lock to write " + objUnit.unit);
```

**File:** writer.js (L301-322)
```javascript
		function determineInputAddressFromSrcOutput(asset, denomination, input, handleAddress){
			conn.query(
				"SELECT address, denomination, asset FROM outputs WHERE unit=? AND message_index=? AND output_index=?",
				[input.unit, input.message_index, input.output_index],
				function(rows){
					if (rows.length > 1)
						throw Error("multiple src outputs found");
					if (rows.length === 0){
						if (conf.bLight) // it's normal that a light client doesn't store the previous output
							return handleAddress(null);
						else
							throw Error("src output not found");
					}
					var row = rows[0];
					if (!(!asset && !row.asset || asset === row.asset))
						throw Error("asset doesn't match");
					if (denomination !== row.denomination)
						throw Error("denomination doesn't match");
					var address = row.address;
					if (arrAuthorAddresses.indexOf(address) === -1)
						throw Error("src output address not among authors");
					handleAddress(address);
```

**File:** writer.js (L440-448)
```javascript
				function(rows){
					if (rows.length !== 1)
						throw Error("zero or more than one best parent unit?");
					my_best_parent_unit = rows[0].unit;
					if (my_best_parent_unit !== objValidationState.best_parent_unit)
						throwError("different best parents, validation: "+objValidationState.best_parent_unit+", writer: "+my_best_parent_unit);
					conn.query("UPDATE units SET best_parent_unit=? WHERE unit=?", [my_best_parent_unit, objUnit.unit], function(){ cb(); });
				}
			);
```

**File:** writer.js (L468-485)
```javascript
		function updateLevel(cb){
			if (bGenesis)
				return cb();
			conn.cquery("SELECT MAX(level) AS max_level FROM units WHERE unit IN(?)", [objUnit.parent_units], function(rows){
				if (!conf.bFaster && rows.length !== 1)
					throw Error("not a single max level?");
				determineMaxLevel(function(max_level){
					if (conf.bFaster)
						rows = [{max_level: max_level}]
					if (max_level !== rows[0].max_level)
						throwError("different max level, sql: "+rows[0].max_level+", props: "+max_level);
					objNewUnitProps.level = max_level + 1;
					conn.query("UPDATE units SET level=? WHERE unit=?", [rows[0].max_level + 1, objUnit.unit], function(){
						cb();
					});
				});
			});
		}
```

**File:** writer.js (L508-517)
```javascript
			function setWitnessedLevel(witnessed_level){
				profiler.start();
				if (witnessed_level !== objValidationState.witnessed_level)
					throwError("different witnessed levels, validation: "+objValidationState.witnessed_level+", writer: "+witnessed_level);
				objNewUnitProps.witnessed_level = witnessed_level;
				conn.query("UPDATE units SET witnessed_level=? WHERE unit=?", [witnessed_level, objUnit.unit], function(){
					profiler.stop('write-wl-update');
					cb();
				});
			}
```

**File:** writer.js (L720-723)
```javascript
								if (arrStabilizedMcis.length > 0 && (bInLargerTx || objValidationState.bUnderWriteLock))
									throw Error(`saveJoint stabilized an MCI while in larger tx or under write lock`);
								if (arrStabilizedMcis.length > 1)
									throw Error(`saveJoint stabilized more than one MCI: ${arrStabilizedMcis.join(', ')}`);
```

**File:** writer.js (L747-748)
```javascript
										if (arrStabilizedMcis.length > 1)
											throw Error(`additional stabilization resulted in more than one MCI: ${arrStabilizedMcis.join(', ')}`);
```

**File:** writer.js (L774-776)
```javascript
								if (conf.storage === 'sqlite')
									updateSqliteStats(objUnit.unit);
								unlock();
```

**File:** mutex.js (L43-59)
```javascript
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
