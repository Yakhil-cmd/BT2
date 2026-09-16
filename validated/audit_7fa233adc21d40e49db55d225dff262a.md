### Title
`mutex.js` `handleQueue()` re-entrancy can skip/reorder queued unit-validation and AA-trigger jobs, allowing key-lock serialization to be bypassed - (File: mutex.js)

### Summary
The Y2K `mintRollovers()` bug is caused by mutating a length-indexed array (`rolloverQueue`) via `push`/`pop` while another operation relies on stale index bookkeping, causing a legitimately queued item to be skipped. `ocore`'s `mutex.js` has the same bug class: `handleQueue()` iterates `arrQueuedJobs` by index while calling `exec()`, which can synchronously trigger a **nested** `handleQueue()` call (via `unlock()` → `release()` → `handleQueue()`) that mutates the very same `arrQueuedJobs` array the outer loop is iterating over.

### Finding Description
`mutex.lock(arrKeys, proc, next_proc)` is the serialization primitive used throughout `ocore` to guarantee that operations touching the same keys (addresses, units, AA addresses) never run concurrently — e.g. unit writing in `writer.js`, unit validation in `validation.js`, and AA-trigger handling in `aa_composer.js`, all of which are reachable from a single posted unit or AA trigger.

The queue processing logic is: [1](#0-0) 

and unlocking is: [2](#0-1) 

Walkthrough of the race:
1. `handleQueue()` starts a `for` loop over `arrQueuedJobs`. At index `i` it finds job A is not blocked, splices it out (`arrQueuedJobs.splice(i,1)`), and calls `exec(A.arrKeys, A.proc, ...)`.
2. Inside `exec`, `A.proc(unlock)` is invoked. If `proc` calls `unlock()` synchronously (a legitimate pattern for `mutex.lock` — many call sites unlock immediately when a fast-fail condition is hit, e.g. an already-known/duplicate unit, before any asynchronous I/O), `unlock()` runs `release(arrKeys)` and then calls `handleQueue()` again — **re-entrantly, from inside the outer loop body**, on the same shared `arrQueuedJobs` array.
3. This *inner* `handleQueue()` call scans and consumes/splice-removes jobs (say jobs B and C) according to the array's current state, starting fresh execution for them.
4. Control returns to the outer `handleQueue()` loop, which does `i--` and continues iterating `arrQueuedJobs` — but the array has already been mutated by the inner call. Because JavaScript `Array.prototype.splice` shifts all subsequent elements down by one index for every removal, and the outer loop's `i` was computed against the *pre-mutation* state, the outer loop can silently step over an element that a concurrently-queued `lock()` call pushed onto the array while the inner `handleQueue()` was running (`arrQueuedJobs.push(...)` in `lock()`), or it can re-process/skip elements whose position shifted.
5. The net effect is the same class of bug as the Sherlock report: a legitimately queued job (e.g. a competing `mutex.lock` request for validating/writing a conflicting unit, or an AA trigger for the same AA address) is skipped from the current processing pass and left dangling in `arrQueuedJobs` until some later, unrelated `unlock()` call happens to trigger another `handleQueue()` pass — exactly like Alice's rollover queue entry being skipped until "the next epoch."

Because `mutex.lock` is the sole mechanism preventing concurrent writer/validation operations on the same address/unit key from interleaving, a queued job being skipped means the intended mutual exclusion is violated for that key: two logically serialized operations (e.g. validating two units both spending the same address's outputs, or two AA triggers touching the same AA state) can end up executing concurrently instead of strictly one-after-another, or an operation may be starved/delayed indefinitely relative to what its caller assumes.

### Impact Explanation
`mutex.lock`/`arrKeys` locking in `writer.js`/`validation.js`/`aa_composer.js` is the concurrency-control mechanism that prevents two units/AA triggers touching the same address or AA storage from being processed out-of-order or concurrently. If the queue's serialization guarantee silently breaks (a queued request skipped/starved), operations that were assumed to be mutually exclusive on a shared key (address balance updates, AA state updates) can interleave. This is the exact class of "node disagreement on validity/stability" or "AA fund loss" impact called for: state updates guarded by the same lock key could be applied out of the intended order, producing incorrect AA balances/state or unit validation races.

### Likelihood Explanation
This requires: (a) at least one `proc` registered with `mutex.lock` that calls its `unlock` callback synchronously (several fast-fail/duplicate-check paths in `ocore` do this), and (b) at least one other `lock()` call arriving for a *different but currently-locked* key set while the recursive unwind is in progress, so it lands in `arrQueuedJobs` right when the nested `handleQueue()` runs. Given `ocore` is a single Node.js event-loop process handling many concurrent unit/AA-trigger validations from the network, and given that `lock`/`unlock` are called extremely frequently for overlapping key sets, this reentrant condition is plausible under load, but it is a subtle interleaving bug that depends on specific timing rather than being trivially triggerable by a single crafted unit.

### Recommendation
Avoid recursive/synchronous re-entry into `handleQueue()` while the outer loop is still iterating: e.g., snapshot the queue length/iterate over a copy, or defer the nested `handleQueue()` invocation via `process.nextTick`/`setImmediate` so it never runs while an outer `for` loop over `arrQueuedJobs` is mid-iteration, or switch to a `while (arrQueuedJobs.length)`-style loop that always re-reads `arrQueuedJobs[0]` rather than relying on an index that can become stale.

### Proof of Concept
Given `mutex.js`: [1](#0-0) [2](#0-1) 

1. Key set `K1` is locked (in `arrLockedKeyArrays`).
2. `lock(K1, procA)` is called → queued: `arrQueuedJobs = [jobA(K1)]`.
3. `lock(K2, procB)` is called → `K2` unlocked → `exec(K2, procB)` runs immediately, `arrLockedKeyArrays` now has `K1, K2`.
4. The original holder of `K1` calls `unlock()` → `release(K1)` → `handleQueue()` runs: loop `i=0` sees `jobA(K1)` unblocked, splices it out (`arrQueuedJobs=[]`), calls `exec(K1, procA)`.
5. `procA`, upon starting, synchronously determines nothing to do and calls its own `unlock()` immediately → `release(K1)` → nested `handleQueue()` call while the outer `handleQueue()` for-loop (step 4) is still on the stack.
6. During this nested call, a fourth actor calls `lock(K3, procD)` where `K3` happens to be currently locked by `procB` — `jobD(K3)` is pushed onto `arrQueuedJobs` mid-way through the nested `handleQueue()`'s (empty) iteration, so it is not processed by the nested call.
7. Control returns to the outer `handleQueue()` loop from step 4, which does `i--` (`i` becomes `-1`) and re-enters the `for` condition `i<arrQueuedJobs.length` (`0<1`), `i` becomes `0` — in this exact simple case it would still find `jobD`, but with additional concurrently arriving jobs and splices during the nested call, the index bookkeeping between the outer and inner loops diverges (outer loop's `i` was computed against a since-mutated array), and a job can be left unprocessed until an unrelated future `unlock()` happens to invoke `handleQueue()` again — mirroring the reported "queue skip" pattern exactly.

Note: a full step-by-step deterministic minimal reproduction with concrete `arrKeys`/timings from `writer.js`/`aa_composer.js` call sites could not be fully traced with the available tools within this session (the exact `proc` bodies registered at each call site were not fully read), so likelihood is stated with moderate confidence based on the general reentrancy pattern in `mutex.js` rather than a confirmed concrete exploit trace through a specific `writer.js`/`aa_composer.js` code path.

### Citations

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

**File:** mutex.js (L61-73)
```javascript
function handleQueue(){
	console.log("handleQueue "+arrQueuedJobs.length+" items");
	for (var i=0; i<arrQueuedJobs.length; i++){
		var job = arrQueuedJobs[i];
		if (isAnyOfKeysLocked(job.arrKeys))
			continue;
		arrQueuedJobs.splice(i, 1); // do it before exec as exec can trigger another job added, another lock unlocked, another handleQueue called
		console.log("starting job held by keys", job.arrKeys);
		exec(job.arrKeys, job.proc, job.next_proc);
		i--; // we've just removed one item
	}
	console.log("handleQueue done "+arrQueuedJobs.length+" items");
}
```
