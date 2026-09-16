Based on the investigation, `ocore`'s payment-input validation contains an assertion-style `throw Error(...)` guarding an invariant on attacker-influenced data, which is directly analogous to the `parse_attributes()` assertion abort in `CVE-2017-12961`: both are "should never happen" checks embedded in code that processes untrusted, remotely supplied input, and both cause the process to abort instead of gracefully rejecting the input.

### Title
Assertion-style `throw Error` on stable `temp-bad` source output crashes every validating node - (File: validation.js)

### Summary
`validatePaymentInputsAndOutputs()` in `validation.js` processes the `inputs` array of a `payment` message contained in an untrusted, network-received unit. When resolving a `transfer` input it queries the source output and asserts that a stable output can never have `sequence='temp-bad'`, throwing a bare, uncaught `Error` if that invariant is violated [1](#0-0) . This throw happens inside a raw DB-callback, outside of any `try/catch`, so it is not converted into a normal validation error (`ifUnitError`/`ifJointError`) but instead propagates as an uncaught exception.

### Finding Description
`ocore`'s validation pipeline is designed so that malformed or invalid units are rejected via `callback("...")`, which `validate()` turns into `ifUnitError`/`ifJointError`/`ifTransientError` callbacks [2](#0-1) . However, several code paths in the same file use `throw Error(...)` instead of `callback(...)` to guard invariants that the author believed could "never happen" — for example: "more than 1 src output" [3](#0-2) , "src output amount is not a number" [4](#0-3) , and, most notably, "spending a stable temp-bad output" [5](#0-4) .

This mirrors the CVE-2017-12961 bug class exactly: an `assert`/invariant check embedded deep in a parser/validator that is reachable with attacker-supplied data and, when violated, aborts the whole process rather than returning a controlled error. In `ocore`, `main_chain.js`'s `markMcIndexStable()` is supposed to resolve every `temp-bad` unit at the moment it becomes stable to either `good` or `final-bad` [6](#0-5) , so a `temp-bad`+stable combination is assumed impossible. But this resolution happens as a multi-step async DB update sequence per unit (`findStableConflictingUnits` → `UPDATE units SET sequence=...` → `UPDATE inputs SET is_unique=...`), while `assocStableUnits[unit].sequence` is only patched in memory afterward. If a new unit referencing that just-stabilized output is validated by `validatePaymentInputsAndOutputs()` in the narrow window before the `sequence` column is actually updated in the DB (e.g. concurrent write/validation activity, or a crash/restart mid-`markMcIndexStable`), the assumed-impossible state ends up being read, and the bare `throw Error` fires, crashing the whole node process (`process.on('uncaughtException', ... ) { ... throw err; }` in `network.js`) [7](#0-6) .

### Impact Explanation
Any node (light-unaware, full validating node) that validates a unit spending an output whose defining unit is caught in this narrow "resolving temp-bad" window will crash. Because this code path is exercised by every full node independently validating the same broadcast unit, a unit crafted or timed to hit this window can crash the entire population of validating nodes that reach that state, matching the "network unable to confirm new units" impact category — analogous to the CVE's remote DoS via assertion abort. Unlike normal validation errors, this failure mode bypasses graceful rejection (`ifUnitError`) entirely.

### Likelihood Explanation
Reaching this exact race window requires a double-spend scenario that stabilizes with the losing (`temp-bad`) branch, plus a follow-on unit referencing the loser's output being validated during the brief interval between the `sequence` column update and the in-memory cache/`is_unique` update in `markMcIndexStable()`/`handleNonserialUnits()`. This is a narrower trigger than a straightforward single crafted unit, so likelihood is lower than the CVE's simple malformed-file trigger, but it is still reachable by an ordinary unprivileged unit poster orchestrating a double-spend and timing a follow-up spend, without any special network/hub/peer privileges.

### Recommendation
Wrap the invariant checks in `validatePaymentInputsAndOutputs()` (lines 2450-2458, 2475-2476) in the same defensive pattern used elsewhere in `validation.js` — convert `throw Error(...)` into `return cb(createTransientError(...))` or a plain validation error, so a violated invariant results in rejecting/deferring the unit instead of crashing the process. Additionally, ensure `markMcIndexStable()`'s per-unit DB updates and in-memory cache updates for `sequence` are atomic/ordered so no other validation can observe a `stable && temp-bad` state.

### Proof of Concept
1. Author two conflicting (double-spend) units `A` and `B` spending the same output from address `X`.
2. Allow the network to stabilize the main chain so that `A` resolves to `good` and `B` resolves to `temp-bad`→`final-bad` via `markMcIndexStable()`/`handleNonserialUnits()` [6](#0-5) .
3. Concurrently with the DB update sequence in step 2 (e.g. by flooding the node with many stabilizing units to widen the async window, or via a full-node restart/crash that leaves the `units.sequence` column stale versus the `assocUnstableUnits`/`assocStableUnits` cache), submit a new unit `C` whose payment input references the output produced by `B`.
4. When `validatePaymentInputsAndOutputs()` for `C` reads `src_output.sequence === 'temp-bad'` while `src_output.main_chain_index` is already stable, it executes `throw Error("spending a stable temp-bad output " + input.unit)` [5](#0-4) , which is caught by `process.on('uncaughtException', ...)` and re-thrown, crashing the node [7](#0-6) .

### Citations

**File:** validation.js (L118-138)
```javascript
function validate(objJoint, callbacks, external_conn) {
	
	var objUnit = objJoint.unit;
	if (typeof objUnit !== "object" || objUnit === null)
		throw Error("no unit object");
	if (!objUnit.unit)
		throw Error("no unit");
	
	console.log("\nvalidating joint identified by unit "+objJoint.unit.unit);
	
	if (!isStringOfLength(objUnit.unit, constants.HASH_LENGTH))
		return callbacks.ifJointError("wrong unit length");
	
	try{
		// UnitError is linked to objUnit.unit, so we need to ensure objUnit.unit is true before we throw any UnitErrors
		if (objectHash.getUnitHash(objUnit) !== objUnit.unit)
			return callbacks.ifJointError("wrong unit hash: "+objectHash.getUnitHash(objUnit)+" != "+objUnit.unit);
	}
	catch(e){
		return callbacks.ifJointError("failed to calc unit hash: "+e);
	}
```

**File:** validation.js (L2450-2451)
```javascript
							if (rows.length > 1)
								throw Error("more than 1 src output");
```

**File:** validation.js (L2454-2461)
```javascript
							var src_output = rows[0];
							var bStableInParents = (src_output.main_chain_index !== null && src_output.main_chain_index <= objValidationState.last_ball_mci);
							if (bStableInParents) {
								if (src_output.sequence === 'temp-bad')
									throw Error("spending a stable temp-bad output " + input.unit);
								if (src_output.sequence === 'final-bad')
									return cb("spending a stable final-bad output " + input.unit);
							}
```

**File:** validation.js (L2475-2476)
```javascript
							if (typeof src_output.amount !== 'number')
								throw Error("src output amount is not a number");
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
