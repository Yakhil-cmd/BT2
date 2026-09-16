### Title
Throw-based "assert" guard on attacker-influenced sequence state crashes validating nodes instead of gracefully rejecting the unit - (File: validation.js)

### Summary
`validation.js`'s payment-input validation contains several `throw Error(...)` guards that are only supposed to catch "impossible" internal-invariant violations, mirroring the reported Solidity `assert()` misuse: guards on state that is actually influenced by attacker-controlled parameters (a posted unit's inputs/timing) are implemented as unconditional throws instead of graceful `require()`-style rejections (`return cb(...)`). This is the same bug class as the external report — the difference being that in `ocore` a `throw` inside a validation callback is an uncaught exception that kills the Node.js process, rather than "wasting gas": every full node that processes the malicious unit crashes.

### Finding Description
In `validatePaymentInputsAndOutputs`, when validating a `transfer` input that spends a non-private output, the code loads the current `sequence` of the referenced source output and asserts an invariant that is expected to never occur for a stable output: [1](#0-0) 

```
if (rows.length > 1)
    throw Error("more than 1 src output");
...
if (bStableInParents) {
    if (src_output.sequence === 'temp-bad')
        throw Error("spending a stable temp-bad output " + input.unit);
    if (src_output.sequence === 'final-bad')
        return cb("spending a stable final-bad output " + input.unit);
}
```

Note the asymmetry: the `final-bad` case (which is a completely normal, externally reachable outcome for any node) is handled with a graceful `return cb(...)`, i.e. a `require()`-style rejection. The `temp-bad` case, by contrast, is treated as "should never happen" and implemented with `throw Error(...)`, i.e. an `assert()`-style guard.

The invariant that "a stable output is never `temp-bad`" is enforced elsewhere, in `markMcIndexStable`, which re-evaluates every non-`good` unit on a newly stabilized MCI and flips its `sequence` to either `good` or `final-bad`: [2](#0-1) 

This re-evaluation happens as a multi-step, non-atomic sequence of separate `conn.query` calls: `is_stable=1` is set first (line 1309), and only afterwards, in a second pass, is `sequence` corrected for any row that is still `temp-bad` (lines 1320-1351). A payment unit validated by `validatePaymentInputsAndOutputs` reads `is_stable`/`sequence` directly from the `units` table with a plain `SELECT` (lines 2443-2448), not from a value guaranteed to be transactionally consistent with the invariant enforced in `markMcIndexStable`. Any unit-poster that references, as a payment input, an output whose containing unit is mid-stabilization (already flagged `is_stable=1` at line 1309 of `main_chain.js` but not yet corrected away from `temp-bad` by the subsequent query at line 1337) will hit the `throw Error("spending a stable temp-bad output ...")` guard in `validation.js:2457-2458` during that window, exactly as an unexpected `assert()` failure would in the reported Solidity code — except here it is not merely "wasted gas": it is an unhandled exception in `validation.js`, which (like the other analogous `throw Error(...)` guards in the same file, e.g. lines 2421-2424 and 2450-2451, and in `main_chain.js` such as line 1333 "temp-bad and with content_hash?") is not wrapped by any local `try/catch`, so it propagates as an uncaught exception in the validating node's process, since no local recovery/`ifUnitError` conversion exists for it (unlike `final-bad`, which is a normal validation failure returned via `cb`).

### Impact Explanation
An uncaught `throw` originating from inside `validation.validate()`'s asynchronous callback chain is not caught by the `ifUnitError`/`ifJointError`/`ifTransientError` dispatcher in `validate()` (`validation.js:458-471`), because it never reaches the `err` return path — it is a synchronous JS exception thrown from within a DB callback. This crashes the Node.js process of every full node that attempts to validate the malicious unit (via `network.js`'s `handleJoint`, `composer.js`'s save path, or `aa_composer.js`'s AA unit validation, all of which funnel into `validation.validate`). If a large fraction of full nodes process the same crafted unit, none of them can continue to validate or confirm new units until manually restarted, which matches the required "network unable to confirm new units" impact bar.

### Likelihood Explanation
Reaching the specific race window (a source output whose containing unit is flagged `is_stable=1` while `sequence` is still `temp-bad`, i.e., between `main_chain.js:1309` and the completion of `handleNonserialUnits()` at line ~1360) requires precise timing relative to the node's own stabilization pass and is not fully proven end-to-end here without deeper tracing of the write-lock scoping around `markMcIndexStable` versus `validatePaymentInputsAndOutputs` (I was not able to confirm within available tool calls whether both paths share the same write mutex, which would determine whether this window is actually reachable from a concurrently-processed unit, or only a purely internal consistency check that can never fire). This uncertainty should be treated as an open verification item.

### Recommendation
Replace the `assert`-style `throw Error("spending a stable temp-bad output " + input.unit)` (and the sibling internal-invariant throws around it, e.g. `"more than 1 src output"`, `"src output amount is not a number"`, `"no denomination in src coin"`, `"no src coin amount"`) with graceful `require()`-style rejections that call `cb(...)` (optionally via `createTransientError`/`createJointError` if a retry or different node behavior is warranted), exactly as is already done two lines below for the `final-bad` case. This ensures that if the assumed invariant is ever violated — whether due to a genuine bug, a race condition, or a future protocol change — the offending unit is rejected as invalid/transient rather than crashing the validating node.

### Proof of Concept
Not independently reproduced; the report is based on static analysis of the reachable code path in `validation.js:2450-2461` and the stabilization logic in `main_chain.js:1288-1365` that produces the `temp-bad`/stable state pair the guard assumes is impossible. Confirming exploitability would require constructing two conflicting units and timing a third spending unit's validation to land inside the stabilization window identified above.

### Citations

**File:** validation.js (L2450-2461)
```javascript
							if (rows.length > 1)
								throw Error("more than 1 src output");
							if (rows.length === 0)
								return cb("input unit "+input.unit+" not found");
							var src_output = rows[0];
							var bStableInParents = (src_output.main_chain_index !== null && src_output.main_chain_index <= objValidationState.last_ball_mci);
							if (bStableInParents) {
								if (src_output.sequence === 'temp-bad')
									throw Error("spending a stable temp-bad output " + input.unit);
								if (src_output.sequence === 'final-bad')
									return cb("spending a stable final-bad output " + input.unit);
							}
```

**File:** main_chain.js (L1318-1351)
```javascript
	function handleNonserialUnits(){
	//	console.log('handleNonserialUnits')
		conn.query(
			"SELECT * FROM units WHERE main_chain_index=? AND sequence!='good' ORDER BY unit", [mci], 
			function(rows){
				var arrFinalBadUnits = [];
				async.eachSeries(
					rows,
					function(row, cb){
						if (row.sequence === 'final-bad'){
							arrFinalBadUnits.push(row.unit);
							return row.content_hash ? cb() : setContentHash(row.unit, cb);
						}
						// temp-bad
						if (row.content_hash)
							throw Error("temp-bad and with content_hash?");
						findStableConflictingUnits(row, function(arrConflictingUnits){
							var sequence = (arrConflictingUnits.length > 0) ? 'final-bad' : 'good';
							console.log("unit "+row.unit+" has competitors "+arrConflictingUnits+", it becomes "+sequence);
							conn.query("UPDATE units SET sequence=? WHERE unit=?", [sequence, row.unit], function(){
								if (sequence === 'good')
									conn.query("UPDATE inputs SET is_unique=1 WHERE unit=?", [row.unit], function(){
										storage.assocStableUnits[row.unit].sequence = 'good';
										cb();
									});
								else{
									arrFinalBadUnits.push(row.unit);
									// treat this unit as a non-existent competitor from now on
									conn.query("UPDATE inputs SET is_unique=NULL WHERE unit=?", [row.unit], function(){
										setContentHash(row.unit, cb);
									});
								}
							});
						});
```
