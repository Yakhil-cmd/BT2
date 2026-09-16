## Analysis

The relevant crash-inducing pattern is `storage.js:readBaseAADefinitionAndParams`, called from `formula/evaluation.js` (`callGetter`, used by `remote_func_call`/`get()` in oscript formulas). This function throws a raw, unguarded `Error` inside an async DB-callback context rather than passing an error to its callback: [1](#0-0) 

Specifically, when `base_aa` is set on a parameterized AA but `readAADefinition(conn, base_aa, to_mci, ...)` returns no definition (`!arrBaseDefinition`), the code does `throw Error("base AA not found: " + base_aa)` [2](#0-1) . This throw happens inside a `conn.query` callback — an asynchronous context with no enclosing `try/catch` on the call stack — so it becomes an uncaught exception.

`network.js` installs a global handler that intentionally re-throws to crash the entire node process on any uncaught exception: [3](#0-2) 

This mirrors the NFS bug class: a code path assumes a referenced object (`base_aa`'s AA definition) is always resolvable/non-null, and when it isn't, the code dereferences/throws unconditionally instead of gracefully failing — causing a crash ("oops" ≈ Node process termination here) instead of graceful degradation.

### Reachability
`readBaseAADefinitionAndParams` is invoked from `callGetter` in `formula/evaluation.js:3307`, which is used whenever an oscript formula performs a remote getter call (`remote_func_call`, e.g. `$aa.getter()`), reachable directly from any AA's `getters` or trigger-time formula evaluation. An attacker who defines or triggers an AA that calls `get()` against an address which used to be a valid `base_aa`-having AA, at a point where the base AA's own definition is not visible at the queried `to_mci` (e.g., due to MCI-boundary timing / unstable visibility edge cases handled specially elsewhere in the codebase, such as `readAssetInfoPossiblyDefinedByAA`'s explicit handling of "defined later than last ball" scenarios) can trigger this branch. Unlike similar functions (`readAsset`, `readAssetInfoPossiblyDefinedByAA`) that carefully handle "not found because not yet stable" cases by returning `null`/error through callbacks, `readBaseAADefinitionAndParams` has no equivalent handling — it unconditionally throws.

Because this exception is not something `formulaParser.evaluate`'s try/catch (which wraps only synchronous parsing, not callback bodies) can intercept, it propagates as an uncaught exception, hitting the handler in `network.js:4530-4543` that deliberately crashes the process.

### Impact
A full-node crash halts unit processing entirely — the node stops validating/confirming new units until manually restarted, matching the "network unable to confirm new units" outcome class. Since any full node evaluating the relevant AA trigger/getter call would hit the same code path deterministically, this is a reliable, low-privilege DoS vector triggerable by a single crafted AA definition + trigger from an unprivileged unit poster / AA trigger sender.

I could not fully confirm from the available index whether normal AA validation (`aa_validation.js` `base_aa` checks) prevents all cases where `base_aa`'s definition could become unavailable at getter-evaluation time (e.g., due to MCI/timing race between when a parameterized AA is defined vs. when its `base_aa` becomes visible via `readAADefinition`'s `mci<=?` filter). This would need dynamic testing/tracing beyond static code search to fully validate the exact trigger sequence.

### Title
Uncaught exception on missing base AA definition crashes the node - (File: storage.js)

### Summary
`readBaseAADefinitionAndParams()` in `storage.js` throws an unguarded synchronous `Error` from inside an asynchronous DB-query callback when a referenced `base_aa` definition cannot be resolved, instead of passing the failure to its callback. Because this happens outside any try/catch on the call stack, it becomes an uncaught exception. `network.js` installs a handler that deliberately re-throws on any uncaught exception to crash the node process, so this code path is a full node-crash vector.

### Finding Description
`readBaseAADefinitionAndParams(conn, address, to_mci, handleDefinitionAndParams)` reads an AA's definition, and if it has a `base_aa` field, attempts to read the base AA's definition at the same `to_mci`: [1](#0-0) 

If `readAADefinition` for `base_aa` returns nothing (`!arrBaseDefinition`), the function throws instead of invoking `handleDefinitionAndParams(null)` or otherwise reporting an error through the callback chain (contrast with the `!arrDefinition` case just two lines earlier, which correctly calls back with `null`). This is called from `formula/evaluation.js`'s `callGetter`, which underlies remote getter calls (`get()`/`remote_func_call`) in oscript AA formulas: [4](#0-3) 

Because the throw occurs inside a `conn.query` callback (an async boundary), no surrounding `try/catch` (including `formulaParser`'s own error handling for formula evaluation) can catch it, and it surfaces as a Node.js uncaught exception. `network.js` explicitly turns any such uncaught exception into a process crash: [3](#0-2) 

### Impact Explanation
This is analogous to the NFS CVE's root cause: a helper function assumes a referenced dependent object (base AA definition) will always be resolvable, and when called from a valid-but-edge-case path where that assumption doesn't hold, the code faults instead of degrading gracefully. In ocore's case, the fault directly triggers deliberate process termination, halting the entire node's unit processing and consensus participation — matching "a network unable to confirm new units" if triggered broadly, or at minimum causing repeated crash/restart cycles for any node evaluating the offending AA trigger or getter call.

### Likelihood Explanation
Likelihood depends on whether an unprivileged AA author/trigger sender can construct a scenario where `base_aa`'s AA definition is not visible via `readAADefinition` at the exact `to_mci` used for evaluation, despite `base_aa` being validly set. AA validation elsewhere in the codebase (e.g. `readAssetInfoPossiblyDefinedByAA` and `readAsset` in `storage.js`) demonstrates that "defined later than last ball" / MCI-visibility races for AA-related objects are a known, exploitable edge case that the codebase otherwise handles carefully — but `readBaseAADefinitionAndParams` lacks equivalent handling. This suggests the unguarded throw is reachable under legitimate MCI-boundary conditions triggerable by posting units/triggers, though I could not fully verify the exact reproduction sequence with the available static index.

### Recommendation
Change `readBaseAADefinitionAndParams` so that when `arrBaseDefinition` is not found, it calls `handleDefinitionAndParams(null)` (or an explicit error indicator) instead of throwing, and have `callGetter`/`formula/evaluation.js` propagate this as a normal formula-evaluation failure (bounce) rather than crashing. Audit other `throw Error(...)` statements inside asynchronous DB-callback bodies in `storage.js` and `aa_composer.js` for the same anti-pattern, since any of them can similarly crash the process given `network.js`'s uncaught-exception handler.

### Proof of Concept
Conceptual (not fully verified end-to-end): 
1. Define AA `B` (`base_aa` target) and, before/at a point where `B`'s definition unit is not yet counted as stable at the `to_mci` that will later be used for evaluation, define parameterized AA `A` with `base_aa: B`.
2. Trigger another AA `C` that calls `get(A_address, 'someGetter', ...)` (a remote getter call), causing `callGetter` → `readBaseAADefinitionAndParams(conn, A_address, last_ball_mci, ...)` to run with a `to_mci` at which `B`'s definition doesn't resolve via `readAADefinition`.
3. `readAADefinition` returns `null` for `B`, hitting `throw Error("base AA not found: " + base_aa)` inside the `conn.query` callback, producing an uncaught exception that crashes the node via the handler in `network.js`.

### Citations

**File:** storage.js (L813-828)
```javascript
function readBaseAADefinitionAndParams(conn, address, to_mci, handleDefinitionAndParams) {
	if (!handleDefinitionAndParams)
		return new Promise(resolve => readBaseAADefinitionAndParams(conn, address, to_mci, (arrBaseDefinition, params, storage_size) => resolve({ arrBaseDefinition, params, storage_size })));
	readAADefinition(conn, address, to_mci, function (arrDefinition, unit, storage_size) {
		if (!arrDefinition)
			return handleDefinitionAndParams(null);
		var base_aa = arrDefinition[1].base_aa;
		if (!base_aa)
			return handleDefinitionAndParams(arrDefinition, null, storage_size);
		readAADefinition(conn, base_aa, to_mci, function (arrBaseDefinition) {
			if (!arrBaseDefinition)
				throw Error("base AA not found: " + base_aa);
			handleDefinitionAndParams(arrBaseDefinition, arrDefinition[1].params, storage_size);
		});
	});
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

**File:** formula/evaluation.js (L3305-3317)
```javascript
	// no need to cloneDeep, we need to rewrite only storage size, assocBalances cache can be updated by reference
	let objGetterValidationState = _.clone(objValidationState);
	storage.readBaseAADefinitionAndParams(conn, aa_address, objValidationState.last_ball_mci, function (arrBaseDefinition, params, storage_size) {
		if (!arrBaseDefinition)
			return cb("remote AA not found: " + aa_address);
		// rewrite storage size with the storage size of the AA being called
		objGetterValidationState.storage_size = storage_size;
		var f = getFormula(arrBaseDefinition[1].getters);
		const caller_aa = callerInfo && callerInfo.caller_aa;
		const call_line = callerInfo && callerInfo.call_line;
		const call_xpath = callerInfo && callerInfo.call_xpath;

		addAstTrace({ system: 'enter to getters', aa: aa_address, formula: f, caller_aa, call_line, call_xpath });
```
