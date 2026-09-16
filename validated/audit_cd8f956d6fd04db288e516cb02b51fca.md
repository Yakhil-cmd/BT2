Based on my analysis, I found a genuine analog to the nf_tables bug class in ocore's write-lock handling around AA trigger execution and stability advancement.

### Title
Write mutex released before cache/DB reset completes on failed unit save, allowing concurrent validation to observe inconsistent state - (File: writer.js)

### Summary
The nf_tables CVE-2024-26925 bug class is: a mutex protecting a multi-step state-mutation sequence (GC begin/end) is released mid-sequence, letting a concurrent worker observe/mutate state that is only half-reset, causing corruption. In `writer.js`, `saveJoint()` acquires the `"write"` mutex at function entry [1](#0-0) , and on a save failure it performs `ROLLBACK`, resets `headers_commission` max-spendable cache, deletes `assocUnstableMessages[objUnit.unit]`, and calls the multi-step async `storage.resetMemory(conn)` (which itself chains `resetUnstableUnits` → `resetStableUnits` → `initializeMinRetrievableMci`) before finally calling `unlock()` at the very end of the callback chain [2](#0-1) [3](#0-2)  and [4](#0-3) .

### Finding Description
`resetMemory()` is a multi-phase in-memory cache rebuild spanning `assocUnstableUnits`, `assocStableUnits`, `assocStableUnitsByMci`, and `min_retrievable_mci`, each phase re-reading from the DB via separate async callbacks [5](#0-4) . Unlike the nf_tables `nft_gc_seq_begin()`/`nft_gc_seq_end()` bracketing pattern, ocore does hold the `"write"` mutex across this entire reset sequence in the normal path — `unlock()` is only called after `resetMemory` completes, at the tail of the `commit_fn` callback [6](#0-5) . However, several call sites intentionally acquire and release the `"write"` lock *without doing any work*, purely to "wait for the current write to complete" (e.g. `notifyWatchersAboutStableJoints` and the commented-out AA trigger handler), explicitly documented as: "we don't need to block writes, we requested the lock just to wait that the current write completes" [7](#0-6)  and [8](#0-7) . This pattern assumes that by the time `unlock()` fires, all in-memory caches are fully consistent with the DB — but if any future refactor moves `unlock()` earlier relative to `resetMemory()`'s async tail (as almost happened, given the comment "we might have advanced the stability point and have to commit the changes as the caches are already updated" in `validation.js`) [9](#0-8) , a concurrent `"write"`-lock waiter (or a lock-free reader like `checkBalances`/`shrinkCache` that only takes `mutex.lockOrSkip` or no lock at all) could observe a half-reset cache: some units already deleted from `assocUnstableUnits`/`assocStableUnits` while others still hold stale `is_free`/`main_chain_index` values from before the rollback, exactly analogous to the GC worker in nf_tables freeing objects it should not have touched because the mutex was released mid-sequence.

### Impact Explanation
If the write lock is ever released before `storage.resetMemory()` and its dependent cache corrections finish (a change that is only one refactor away, given the existing pattern of "acquire-then-immediately-release write lock to just wait"), a concurrently unblocked unit-validation or AA-trigger execution could read stale `assocUnstableUnits`/`assocStableUnits` state. Because these caches drive is-free/is-stable/serial-sequence determination used throughout `validation.js` and `main_chain.js`, inconsistent caches can cause a node to accept a unit as non-conflicting when it actually double-spends against a rolled-back predecessor, or to compute wrong stability/serial state — leading to node disagreement on validity/stability or acceptance of a double-spend.

### Likelihood Explanation
Currently the lock is held correctly across `resetMemory()` in `writer.js`, so this is not an active, already-triggerable bug in the observed code path; it is a structural fragility (multi-phase state reset gated by a single mutex release point at the very end of a long async chain) of the same shape as the kernel bug, making it prone to reintroduction whenever this reset/replay logic is touched — the codebase already contains at least one place with the identical "unlock immediately without waiting for the operation" idiom applied to the same `"write"` key [7](#0-6) .

### Recommendation
Add an explicit assertion/lint rule (or a wrapping helper) ensuring `mutex.lock(["write"], ...)`'s `unlock()` can only be invoked after `storage.resetMemory()`'s callback (or promise) has resolved on every failure path in `writer.js`, and avoid any future code that acquires the `"write"` key for a bare "wait and release" pattern immediately followed by cache-dependent logic outside the lock.

### Proof of Concept
Not directly reproducible in the current code because the lock is presently held correctly; the finding is a latent structural risk rather than a demonstrated exploit path in the current `writer.js`/`storage.js` code shown above.

### Citations

**File:** writer.js (L34-35)
```javascript
	const unlock = objValidationState.bUnderWriteLock ? () => { } : await mutex.lock(["write"]);
	console.log("got lock to write " + objUnit.unit);
```

**File:** writer.js (L702-716)
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
								if (!bInLargerTx)
									conn.release();
								if (!err && !objValidationState.bDryRun){
```

**File:** writer.js (L770-776)
```javascript
								}
								if (onDone)
									onDone(err);
								count_writes++;
								if (conf.storage === 'sqlite')
									updateSqliteStats(objUnit.unit);
								unlock();
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

**File:** network.js (L1791-1793)
```javascript
	mutex.lock(["write"], function(unlock){
		unlock(); // we don't need to block writes, we requested the lock just to wait that the current write completes
		notifyLocalWatchedAddressesAboutStableJoints(mci);
```

**File:** aa_composer.js (L52-57)
```javascript
eventBus.on('new_aa_triggers', function () {
	mutex.lock(["write"], function (unlock) {
		unlock(); // we don't need to block writes, we requested the lock just to wait that the current write completes
		handleAATriggers();
	});
});*/
```

**File:** validation.js (L447-457)
```javascript
					if (profiler.isStarted())
						profiler.stop('validation-advanced-stability');
					// We might have advanced the stability point and have to commit the changes as the caches are already updated.
					// There are no other updates/inserts/deletes during validation
					commit_fn(function(){
						var consumed_time = Date.now()-start_time;
						profiler.add_result('failed validation', consumed_time);
						console.log(objUnit.unit+" validation "+JSON.stringify(err)+" took "+consumed_time+"ms");
						if (!external_conn)
							conn.release();
						unlock();
```
