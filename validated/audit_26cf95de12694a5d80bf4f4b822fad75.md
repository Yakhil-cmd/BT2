### Title
Unit metadata added to in-memory `assocBestChildren`/`assocUnstableUnits` caches before commit is not verifiably rolled back on write failure - ([File: writer.js])

### Summary
`writer.saveJoint()` optimistically registers a newly-composed unit's properties (`objNewUnitProps`) into the process-wide in-memory caches `storage.assocUnstableUnits` and `storage.assocBestChildren[my_best_parent_unit]` *before* the underlying DB transaction (`arrOps` / `preCommitCallback` / `COMMIT`) has actually succeeded. [1](#0-0) 
If a later step in the same write pipeline fails (e.g. `preCommitCallback` returns an error, causing `ROLLBACK`), the error branch only explicitly deletes `storage.assocUnstableMessages[objUnit.unit]` and calls `storage.resetMemory(conn)` — it does not visibly, explicitly remove the just-pushed entry from `storage.assocBestChildren[my_best_parent_unit]` nor `storage.assocUnstableUnits[objUnit.unit]` at this call site. [2](#0-1) 

### Finding Description
This mirrors the CVE-2023-54193 bug class: a side-effect that registers an object into an auxiliary list (`driver_list` in the kernel case; `assocBestChildren`/`assocUnstableUnits` here) happens before the operation that "owns" the object's lifetime commits, and the failure/cleanup path (which frees/rolls back the object) does not guarantee it is also removed from every list it was inserted into. In the kernel this produces a literal use-after-free; in ocore's JS in-memory cache model the analogous failure mode is a **stale/phantom unit reference surviving a rolled-back write**, reachable by any node that composes and submits a payment, AA-related unit, or data-feed unit whose write later fails (e.g. through a `preCommitCallback` error in `indivisible_asset.js`/`divisible_asset.js`, or an `arrOps` failure such as `updateMainChain`).

Because `assocBestChildren` and `assocUnstableUnits` directly participate in the DAG's best-parent selection, level computation, and main-chain determination (used pervasively by `main_chain.js` and `storage.js` for consensus calculations), a dangling reference to a unit that was never actually persisted to the DB can cause the in-memory consensus state to diverge from the authoritative DB state. Whether `storage.resetMemory(conn)` fully reconciles these two specific caches for every affected parent unit could not be confirmed from the code reviewed; if it does not, this represents an unverified cache-consistency gap in the write-failure path, directly on the trusted "compose-and-write" code path that any unprivileged unit poster reaches.

### Impact Explanation
If the caches are not fully unwound, a node's local view of `assocBestChildren`/best-parent chains can retain a unit that does not exist in the database. Because these caches feed main-chain and stability computations, this can lead to the node computing a different best parent / MC / stability outcome than a node whose caches are clean, i.e. **node disagreement on unit validity or stability** — one of the explicitly accepted high-impact outcomes for this class of finding.

### Likelihood Explanation
The write pipeline (`writer.saveJoint`) is reached on every locally composed unit, including via `indivisible_asset.js`/`divisible_asset.js` `preCommitCallback` flows that can legitimately fail (e.g., private-chain validation errors), and via `arrOps` steps such as `main_chain.updateMainChain`. Any of these failing after `objNewUnitProps` has been pushed into `assocBestChildren` triggers the code path in question, so the precondition is not rare or attacker-exotic — it is a standard error path in unit composition.

### Recommendation
Audit `storage.resetMemory()` (called from `writer.js:712`) to confirm it removes/reverts every reference added at `writer.js:596-602`, specifically:
- delete `storage.assocUnstableUnits[objUnit.unit]`
- remove the pushed `objNewUnitProps` entry from `storage.assocBestChildren[my_best_parent_unit]` (analogous to `_.pull` used in `storage.forgetUnit()`)
before/at the same point that the transaction is rolled back, for every failure branch in `writer.saveJoint`, not only the generic post-commit `err` handler. If `resetMemory` does a full-cache reload from DB rather than surgical removal, verify this is unconditionally triggered on every error branch of `saveJoint`, including early-return paths inside `preCommitCallback`.

### Proof of Concept
Not independently reproduced — this is a reachability/code-consistency analysis, not a confirmed exploit. To verify: compose an indivisible/divisible-asset payment unit with a `preCommitCallback` designed to fail after `writer.saveJoint`'s `arrOps` have already executed (so `objNewUnitProps` has been pushed to `assocBestChildren`), force the failure, and inspect `storage.assocBestChildren[my_best_parent_unit]` and `storage.assocUnstableUnits[unit]` afterward to confirm whether the phantom entry persists in memory despite the `ROLLBACK`.

**Note on confidence**: I was unable to retrieve and inspect the full implementation of `storage.resetMemory()` within the available tool budget, so I cannot definitively confirm whether it already correctly reverses these two cache insertions. This finding should be treated as a code-path analog requiring verification of `storage.resetMemory()`'s exact behavior before treating it as a confirmed vulnerability.

### Citations

**File:** writer.js (L596-602)
```javascript
			else
				storage.assocUnstableUnits[objUnit.unit] = objNewUnitProps;
			if (!bGenesis && storage.assocUnstableUnits[my_best_parent_unit]) {
				if (!storage.assocBestChildren[my_best_parent_unit])
					storage.assocBestChildren[my_best_parent_unit] = [];
				storage.assocBestChildren[my_best_parent_unit].push(objNewUnitProps);
			}
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
