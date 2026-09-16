# CVE-2021-24029 Analog Found

### Title
Unhandled assertion-style crash on crafted payment input referencing a "stable temp-bad" output - ([File: validation.js])

### Summary
CVE-2021-24029 describes a "packet of death": a specially crafted protocol message drives an implementation into a state it assumes is impossible, so the code hits a hard assertion/crash instead of returning a protocol-level error. `ocore`'s unit validator contains the same anti-pattern: several code paths reachable directly from an untrusted, attacker-composed unit use `throw Error(...)` to encode "this should never happen" invariants inside the async validation pipeline invoked from `network.js`'s `handleJoint`/`validation.validate()`. If an attacker can construct a unit whose payment input references an output whose on-disk state violates the assumed invariant, the thrown error escapes the `async`/callback chain as an uncaught exception rather than being surfaced through the normal `ifUnitError`/`ifJointError` callback contract, crashing the node process that is validating the peer-submitted unit.

### Finding Description
In `validateInlinePayload`'s `checkInputDoubleSpend` transfer-input handler, when a payment input references a stable source output, the code enforces: [1](#0-0) 

`bStableInParents` is derived purely from `main_chain_index <= objValidationState.last_ball_mci` — it does not re-check the `is_stable` DB flag or otherwise defend against timing/edge cases where a row's `sequence` has not yet been resolved from `'temp-bad'` to `'good'`/`'final-bad'`. The resolution of `'temp-bad'` sequences into finalized values happens in a separate, later step of stabilization: [2](#0-1) 

The validator's `throw Error("spending a stable temp-bad output " + input.unit)` assumes this resolution has always already happened by the time `main_chain_index <= last_ball_mci`, an assumption that a crafted joint (with a fabricated/edge-case `last_ball`/`last_ball_unit` combination pointing to an output still mid-resolution, or reached during light/catchup code paths that populate `main_chain_index` independently of `is_stable`/`sequence` bookkeeping) can violate, turning what should be a rejected unit into an uncaught `Error` that propagates out of the DB-callback chain in `validateAuthors`/`validateMessages`, unwinding past `network.js handleJoint`'s `validation.validate()` call entirely.

The same “this can’t happen” pattern recurs immediately around it and in the generic double-spend checker, showing this is a systemic weakness in how impossible-state assumptions are enforced on attacker-controlled input rather than gracefully rejected: [3](#0-2) [4](#0-3) 

All of this executes inside `validate()`'s `async.series` pipeline, which is invoked directly from the network-facing `handleJoint` for any freshly received unit, i.e. reachable by any unprivileged peer/unit poster: [5](#0-4) [6](#0-5) 

Unlike the well-formed error paths (`ifUnitError`, `ifJointError`, `ifTransientError`) that are wired to safely reject bad units, a `throw Error()` inside the nested SQL callback bypasses `async.series`'s error-first callback contract entirely, becomes an unhandled exception, and (depending on the surrounding domain/process setup) can terminate the node process — precisely the "packet of death" pattern in the mvfst advisory, where a message that should have been treated as a protocol error instead triggers a fatal assertion.

### Impact Explanation
A crash of the validating full node process caused by a single crafted unit is a network-availability impact: any node (hub, witness, or full node) that receives and validates the malicious unit halts, which can be used to repeatedly take down or destabilize nodes on the network, preventing confirmation of new units for the affected node(s) and, if widely propagated, for the broader network (an unauthenticated remote DoS reachable from an ordinary unit post, not requiring a malicious peer/hub — it only requires posting a unit whose payment input targets a carefully chosen, real DAG state).

### Likelihood Explanation
Exploitability depends on being able to reliably drive a legitimate output row into the `main_chain_index <= last_ball_mci` while `sequence` is still `'temp-bad'` — a narrow timing/ordering window that requires understanding of `ocore`'s stabilization sequencing (`main_chain.js:markMcIndexStable`) and last-ball selection rules, so it is not trivial to hit blindly, but it is fully reachable through only the normal "post a unit" interface exposed to any unprivileged unit poster, with no reliance on a malicious peer, hub, or node collusion.

### Recommendation
Convert every assertion-style `throw Error(...)` in the input-validation and double-spend-checking code paths that are reachable from untrusted network-submitted units (`validation.js` around lines 2451/2458/1673/1688/1692, and equivalents) into a soft rejection via `callback("...")`/`cb("...")` so the caller can classify it as `ifUnitError`, exactly like the surrounding, properly-guarded checks. Where the invariant truly should never be violated, add an explicit runtime guard on `is_stable` (not just `main_chain_index`) before trusting `sequence`, and add a global top-level guard around `validation.validate()`'s async callbacks so any unexpected uncaught exception during peer-triggered validation degrades to a rejected unit and a logged incident, not a process crash.

### Proof of Concept
Conceptual (schema-level) PoC, mirroring the mvfst "malformed but syntactically valid" packet-of-death approach:
1. Identify/construct a base unit `U` whose output will be referenced as a payment input, and arrange (via crafted, valid-looking DAG structure/parents/last_ball) for `U`'s `main_chain_index` to become `<= last_ball_mci` of the attacking unit while the stabilization step in `main_chain.js:markMcIndexStable` that would resolve `U.sequence` from `'temp-bad'` to `'good'`/`'final-bad'` has not yet completed/committed for that node (e.g., during catchup/light processing or a narrow post-mci-flag-set race).
2. Post unit `V` that spends `U`'s output as a `"transfer"` payment input.
3. `validation.js`'s transfer-input handler computes `bStableInParents = true` (line 2455) and finds `src_output.sequence === 'temp-bad'`, hitting `throw Error("spending a stable temp-bad output " + input.unit)` (line 2458) inside a raw SQL result callback, outside any `try/catch` guarded by the `async.series` error-first contract, crashing the node validating `V`.

### Citations

**File:** validation.js (L440-472)
```javascript
					profiler.stop('validation-authors');
					profiler.start();
					objUnit.content_hash ? cb() : validateMessages(conn, objUnit.messages, objUnit, objValidationState, cb);
				}
			], 
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

**File:** validation.js (L1671-1692)
```javascript
				function(objConflictingRecord, cb2){
					if (arrAuthorAddresses.indexOf(objConflictingRecord.address) === -1)
						throw Error("conflicting "+type+" spent from another address?");
					if (conf.bLight) // we can't use graph in light wallet, the private payment can be resent and revalidated when stable
						return cb2(objUnit.unit+": conflicting "+type);
					graph.determineIfIncludedOrEqual(conn, objConflictingRecord.unit, objUnit.parent_units, function(bIncluded){
						if (bIncluded){
							var error = objUnit.unit+": conflicting "+type+" in inner unit "+objConflictingRecord.unit;

							// too young (serial or nonserial)
							if (objConflictingRecord.main_chain_index > objValidationState.last_ball_mci || objConflictingRecord.main_chain_index === null)
								return cb2(error);

							// in good sequence (final state); final-bad is excluded by the query and treated as non-existent
							if (objConflictingRecord.sequence === 'good')
								return cb2(error);

							throw Error("unreachable code, conflicting "+type+" in unit "+objConflictingRecord.unit);
						}
						else{ // arrAddressesWithForkedPath is not set when validating private payments
							if (objValidationState.arrAddressesWithForkedPath && objValidationState.arrAddressesWithForkedPath.indexOf(objConflictingRecord.address) === -1)
								throw Error("double spending "+type+" without double spending address?");
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

**File:** main_chain.js (L1318-1336)
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
```

**File:** network.js (L1149-1180)
```javascript
function handleJoint(ws, objJoint, bSaved, bPosted, callbacks){
	if ('aa' in objJoint)
		return callbacks.ifJointError("AA unit cannot be broadcast");
	var unit = objJoint.unit.unit;
	if (typeof unit !== 'string')
		return callbacks.ifJointError("invalid unit");
	const version = objJoint.unit.version;
	if (typeof version !== 'string')
		return callbacks.ifJointError("invalid version");
	const fVersion = parseFloat(version);
	if (!(fVersion >= constants.fVersion4 || objJoint.ball)) // covers NaN too
		return callbacks.ifTransientError("version is too old");
	if (assocUnitsInWork[unit])
		return callbacks.ifUnitInWork();
	assocUnitsInWork[unit] = true;
	
	var validate = function(){
		mutex.lock(['handleJoint'], function(unlock){
			if (ws && !conf.bLight)
				currentJointHost = ws.host;
			// clear host only if validation completed with any result, otherwise it crashed and we keep it for a while to avoid DoS from the same peer
			const clearHost = () => {
				if (ws && !conf.bLight)
					currentJointHost = null;
			};
			validation.validate(objJoint, {
				ifUnitError: function(error){
					console.log(objJoint.unit.unit+" validation failed: "+error);
					clearHost();
					callbacks.ifUnitError(error);
					if (constants.bDevnet)
						throw Error(error);
```
