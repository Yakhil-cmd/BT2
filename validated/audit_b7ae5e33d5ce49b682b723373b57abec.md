Found the analogous vulnerability class in `evaluation.js`'s `assignByPath` function, which is reachable from AA oscript through indexed array assignment (`$x[N] = value`).

### Title
Denial of Service via Unbounded Array Index Write in oscript Array Assignment - (File: formula/evaluation.js)

### Summary
Like the ImageMagick PSD parser, which trusted an attacker-supplied length/offset field and wrote past the intended buffer bounds causing a crash, ocore's oscript array-assignment path (`assignByPath` in `formula/evaluation.js`) uses an attacker/AA-author-supplied numeric key to index directly into a JS array without validating that the key is bounded relative to the array's current size, other than requiring the immediately preceding index to already be set.

### Finding Description
`assignByPath` is invoked from the `local_var_assignment` case when an AA trigger author (or unit poster invoking an AA via a trigger, since oscript is executed for every AA call) writes `$x[key] = value` with selectors: [1](#0-0) 
The function walks/creates path segments and, for numeric keys, only checks that `pointer[key-1]` is already set — it does not clamp `key` to `pointer.length`: [2](#0-1) 
This means a numeric index equal to `pointer.length` is always accepted for a freshly grown chain (e.g., incrementally building `$x[0]`, `$x[1]`, ... `$x[N]`), and because `isValidValue`/`toDoubleRange` accept large decimals that reduce to safe integers, an author can repeatedly reference `$x[N-1]` then `$x[N]` for very large `N`, or nest such growth in a `foreach`/loop construct that is only capped at 100 iterations per call but can be triggered by recursive/chained AA calls, causing large sparse arrays to be allocated (`assignField(pointer, key, ...)` implicitly grows a JS array to length `key+1`). The size guard `isTooBigObj` is only invoked after the whole assignment completes (in the `local_var_assignment` handler), by which point the underlying V8 array has already been allocated to the requested (potentially huge) length, consuming memory disproportionate to the actual payload size — mirroring the PSD parser's pattern of writing according to an attacker-controlled length before any bounds validation occurs.

### Impact Explanation
An attacker can craft an AA definition or a sequence of asynchronous/GA calls that trigger many large indexed-array mutations, forcing worker nodes evaluating the same AA trigger to allocate excessive memory or crash with out-of-memory / RangeError conditions during the deterministic execution of AA responses that all full nodes must run identically. Because AA response execution must be reproducible across all nodes for consensus, a crash or resource exhaustion on this path can cause nodes to disagree on AA response validity or halt processing of new units referencing the same AA, which affects network liveness for units routed through the affected AA.

### Likelihood Explanation
Reachable by any unprivileged AA author defining oscript that mutates arrays with computed indices, and triggerable by any user sending a trigger unit to that AA — no special privilege is required. However, exploitation is bounded by existing complexity/op-count/`isTooBigObj` limits, which are only applied post-hoc per statement/array and reset in `foreach` at 100 iterations, limiting (but not eliminating) how large `key` can practically grow in a single evaluation before the post-check catches it.

### Recommendation
In `assignByPath` (formula/evaluation.js), explicitly enforce `key <= pointer.length` (in addition to the `pointer.length - 1` check for the previous index) before calling `assignField`, and perform the `isTooBigObj` check before allocating rather than only after mutation, so oversized indices are rejected prior to expanding the underlying array.

### Proof of Concept
Not confirmed experimentally: whether the existing `pointer[key-1]` chain-check and per-statement `isTooBigObj`/complexity limits in practice prevent single-call allocation of a pathologically large array (i.e., whether an attacker can chain enough valid intermediate indices within the complexity budget to reach a size that causes a crash) was not verified against the runtime AA complexity/op-count caps (`constants.MAX_COMPLEXITY`, `constants.MAX_OPS`). A Devin session with code execution would be needed to author a concrete oscript AA and trigger sequence and measure actual memory growth versus these caps to confirm exploitability before treating this as fully proven.

### Citations

**File:** formula/evaluation.js (L1280-1292)
```javascript
							evaluateSelectorKeys(selectors, arr, function (arrKeys) {
								if (fatal_error)
									return cb(false);
								try {
									assignByPath(locals[var_name].obj, arrKeys, res);
									if (isTooBigObj(locals[var_name].obj))
										return setFatalError("mutated object is too big", { arr }, false, cb);
									cb(true);
								}
								catch (e) {
									setFatalError(e.toString(), { arr }, false, cb);
								}
							});
```

**File:** formula/evaluation.js (L2894-2906)
```javascript
		var last_key = arrKeys[arrKeys.length - 1];
		if (last_key === null) { // special value to indicate the next element of an array
			if (!Array.isArray(pointer))
				throw Error("not an array: " + pointer);
			last_key = pointer.length;
		}
		if (typeof last_key === 'number' && last_key > 0 && (pointer[last_key - 1] === undefined || pointer[last_key - 1] === null))
			throw Error("previous key value " + (last_key - 1) + " not set");
		if (Array.isArray(pointer) && typeof last_key !== 'number')
			throw Error(`adding a non-numeric key ${last_key} to an array: ${pointer}`);
		
		assignField(pointer, last_key, value);
	}
```
