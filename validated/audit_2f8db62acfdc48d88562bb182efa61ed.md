### Title
Reachable `throw Error(...)` assertions inside async unit-validation callbacks crash the node via the global `uncaughtException` handler - (File: `validation.js`, `network.js`)

### Summary
CVE-2024-1622 describes a Routinator bug where an unhandled/mis-checked error condition caused the daemon to terminate on a specific, externally-triggerable event instead of being handled gracefully. `ocore` has an analogous class of bug: `validation.js` contains multiple "should be unreachable" invariant checks implemented as `throw Error(...)` inside asynchronous DB-query callbacks rather than as calls to the validation `callback`. Because these throws happen inside `conn.query` callbacks (not inside a `try/catch` that funnels into the `callback`), they become uncaught exceptions that propagate to the process-wide `uncaughtException` handler in `network.js`, which deliberately re-throws to kill the process.

### Finding Description
`validation.js`'s `validatePaymentInputsAndOutputs` walks each payment input and, when checking a `transfer` input, reads the referenced source output: [1](#0-0) 

If the source output's owning unit is stable in the submitter's parents (`bStableInParents`) but its `sequence` column is `temp-bad`, the code does not return a normal validation error via `cb(...)`; it directly throws: [2](#0-1) 

This branch is reached purely from processing a single posted unit's `payment` message input — a path fully reachable by an unprivileged unit poster (anyone constructing and broadcasting a unit that spends a prior output). The `sequence='temp-bad'` value is a normal, expected on-disk state used elsewhere in the codebase during conflict resolution (see `validation.js:1325-1326` setting `objValidationState.sequence` to `temp-bad`, and `writer.js:63-72` which persists `temp-bad` sequences via additional queries generated during double-spend handling), so it's not an artificial state — it's the exact state produced by legitimate double-spend/fork resolution while a competing unit is still unstable.

The throw executes inside the `conn.query(...)` callback of `validatePaymentInputsAndOutputs`, several async layers deep inside `validate()`'s `async.series` pipeline: [3](#0-2) 

None of the enclosing async callback chain wraps this callback in a `try/catch`, so the exception is not converted into `callbacks.ifUnitError`/`ifJointError` the way other validation failures are (see the structured error dispatch used for every other validation failure): [4](#0-3) 

Instead it escapes to the top of the event loop and is caught only by the global handler installed in `network.js`, which explicitly re-throws to terminate the process: [5](#0-4) 

This mirrors the CVE-2024-1622 bug class exactly: a specific, reachable, non-malicious-peer condition (an ordinary sequence state produced by normal fork/double-spend bookkeeping) is mishandled by an assertion-style `throw` instead of a graceful validation error, and the process's own top-level error handling policy converts that into a full daemon crash.

Other structurally identical "unreachable" throws exist in the same function and in `checkForDoublespends`, all reachable from ordinary unit/message validation of a posted unit: [6](#0-5) [7](#0-6) 

### Impact Explanation
If a `temp-bad` source-output state can coexist with `bStableInParents=true` (e.g., via timing windows in main-chain stabilization/nonserial resolution, or via light/other code paths that persist `temp-bad` on units later found stable before `main_chain.js`'s `handleNonserialUnits` has resolved them to `good`/`final-bad`), any full node that validates a unit spending such an output will hit the `throw`, escape to `process.on('uncaughtException')`, and crash. Because full nodes need to validate every incoming unit, this can be used to remotely halt any full node that receives (or is fed) the crafted unit, i.e., "a network unable to confirm new units" if replicated across nodes — matching the accepted impact category of node crash/DoS from a single posted unit.

### Likelihood Explanation
Reaching the exact `temp-bad`+`bStableInParents` combination requires hitting a specific timing/state window in the stabilization pipeline (main-chain stabilization is supposed to resolve `temp-bad` to `good`/`final-bad` before advancing stability per `main_chain.js:handleNonserialUnits`), so likelihood is not guaranteed on every node/every time, but the *reachability* of the code path from a single posted, unprivileged unit (no hub/peer/node compromise, no operator access) is direct and requires no elevated capability — only crafting a payment input referencing an existing output whose owning unit is mid-conflict-resolution.

### Recommendation
Replace the `throw Error(...)` assertions inside `validatePaymentInputsAndOutputs` (and the analogous ones in `checkForDoublespends`) with calls to `cb(...)`/`callback(...)` carrying a normal validation error, consistent with every other validation failure path in `validate()`. This ensures unexpected-but-reachable states cause the unit to be rejected (`ifUnitError`) rather than crashing the entire node process, removing the single point where an "impossible" invariant violation is escalated by the global `uncaughtException` handler into an unconditional `throw err` process kill.

### Proof of Concept
1. Construct address `A` that double-authors two conflicting units `U1` and `U2` both spending from the same address, such that conflict-resolution logic in `validateAuthor`/`checkSerialAddressUse` marks one of them (`U1`) with `sequence='temp-bad'` and schedules the corresponding `writer.js` additional query (`validation.js:1325-1339`, `writer.js:63-72`).
2. Before main-chain stabilization fully resolves `U1`'s sequence to `good`/`final-bad` (`main_chain.js` `handleNonserialUnits`), have `U1` become part of the stable main chain state seen by a victim node (i.e., its output becomes `bStableInParents=true` for a subsequently validated unit).
3. Post a new unit `U3` whose payment input spends the output produced by `U1`.
4. When the victim node validates `U3`, `validatePaymentInputsAndOutputs` finds `src_output.sequence === 'temp-bad'` with `bStableInParents === true` and executes `throw Error("spending a stable temp-bad output " + input.unit)` at `validation.js:2458`.
5. The exception is uncaught by the async validation pipeline, propagates to `process.on('uncaughtException')` in `network.js:4530`, which logs it and re-throws (`network.js:4542`), terminating the node process.

### Citations

**File:** validation.js (L435-443)
```javascript
				function(cb){
					profiler.start();
					validateAuthors(conn, objUnit.authors, objUnit, objValidationState, cb);
				},
				function(cb){
					profiler.stop('validation-authors');
					profiler.start();
					objUnit.content_hash ? cb() : validateMessages(conn, objUnit.messages, objUnit, objValidationState, cb);
				}
```

**File:** validation.js (L445-472)
```javascript
			function(err){
				if(err){
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
						if (typeof err === "object"){
							if (err.error_code === "unresolved_dependency")
								callbacks.ifNeedParentUnits(err.arrMissingUnits, err.bRequestPrunedContent);
							else if (err.error_code === "need_hash_tree") // need to download hash tree to catch up
								callbacks.ifNeedHashTree();
							else if (err.error_code === "invalid_joint") // ball found in hash tree but with another unit
								callbacks.ifJointError(err.message);
							else if (err.error_code === "transient")
								callbacks.ifTransientError(err.message);
							else
								throw Error("unknown error code");
						}
						else
							callbacks.ifUnitError(err);
					});
```

**File:** validation.js (L1672-1673)
```javascript
					if (arrAuthorAddresses.indexOf(objConflictingRecord.address) === -1)
						throw Error("conflicting "+type+" spent from another address?");
```

**File:** validation.js (L1688-1692)
```javascript
							throw Error("unreachable code, conflicting "+type+" in unit "+objConflictingRecord.unit);
						}
						else{ // arrAddressesWithForkedPath is not set when validating private payments
							if (objValidationState.arrAddressesWithForkedPath && objValidationState.arrAddressesWithForkedPath.indexOf(objConflictingRecord.address) === -1)
								throw Error("double spending "+type+" without double spending address?");
```

**File:** validation.js (L2449-2461)
```javascript
						function(rows){
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

**File:** network.js (L4530-4543)
```javascript
process.on('uncaughtException', (err) => {
	console.log('Uncaught exception:', err);
	console.error('Uncaught exception:', err);
	if (!conf.bLight) {
		let hosts = [...Object.keys(messagesInWork), ...Object.keys(requestsInWork)];
		if (currentJointHost)
			hosts.push(currentJointHost);
		console.log('Clients with pending requests/messages at the time of uncaught exception:', hosts);
		const fs = require('fs');
		const app_data_dir = require('./desktop_app.js').getAppDataDir();
		fs.writeFileSync(`${app_data_dir}/uncaught_exception_clients.txt`, hosts.concat(Object.keys(assocBlockedPeers)).join('\n'), 'utf8');
	}
	throw err; // crash the process to avoid ending up in an inconsistent state
});
```
