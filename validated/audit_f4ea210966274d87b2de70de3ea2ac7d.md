### Title
Denial-of-Service via uncaught invariant-violation `throw` when validating a payment input spending a stable output - (File: `validation.js`)

### Summary
The gvisor CVE is a DoS caused by a reference-counting/state-tracking bug that trips an internal invariant and panics the sandbox process when triggered by a permitted-but-untrusted actor. The closest reachable analog in this codebase is the "should never happen" `throw Error(...)` guards inside the unprivileged unit-validation path in `validation.js`, most notably in `validatePaymentInputsAndOutputs`, where a payment-input row that is stable but still carries an inconsistent internal `sequence` state causes the validator to `throw` instead of returning a normal validation error.

### Finding Description
`validatePaymentInputsAndOutputs` in `validation.js` looks up the source output being spent by a `transfer` input and inspects its `sequence`/stability fields: [1](#0-0) 

If the row is stable (`main_chain_index <= last_ball_mci`) and its `sequence` is `'temp-bad'`, the code does not return a normal validation error — it `throw`s:
```
if (src_output.sequence === 'temp-bad')
    throw Error("spending a stable temp-bad output " + input.unit);
```
This is a defensive assertion meaning "a stable unit must never remain `temp-bad` — it should always have been finalized to `good` or `final-bad` by the time it's stable." It is analogous to the gvisor bug: an internal bookkeeping invariant (there, mount refcounts; here, `sequence` state transition of stable units) that, if violated, does not degrade gracefully but throws/panics.

Critically, `validate()` in `validation.js` only wraps *some* code paths in `try/catch` (joint hash/format checks); most of the deep validation call chain (including `validatePaymentInputsAndOutputs`) is invoked through `async.series` callbacks with no surrounding `try/catch`, so a `throw` inside these deep functions escapes as an uncaught exception: [2](#0-1) [3](#0-2) 

That uncaught exception propagates out of the node's event loop, and the global handler in `network.js` intentionally lets it kill the process: [4](#0-3) 

The comment even documents the intent: *"crash the process to avoid ending up in an inconsistent state."* This mirrors the gvisor advisory's exact bug class — a bookkeeping/reference-tracking inconsistency intentionally converted into a hard process crash rather than a recoverable error, reachable via a single crafted unit rather than requiring privileged/root-equivalent access.

Multiple similar "impossible state" `throw`s exist along the same unprivileged validation call path (posted-unit validation, AA trigger validation), e.g.: [5](#0-4) [6](#0-5) 

These all sit inside the same unauthenticated `validate()` pipeline invoked by `network.js`'s `handleJoint` for every unit received/posted from any peer or light client: [7](#0-6) 

### Impact Explanation
If any of these "impossible" states can actually be reached by a carefully crafted unit (e.g., a specific double-spend/sequence-resolution edge case that leaves a stable output's `sequence` as `'temp-bad'`, or two co-signed outputs producing duplicate rows), the throw is not confined to rejecting that single bad unit — it escapes validation entirely and crashes the whole node process via the `uncaughtException` handler. Since every full node (and hub) runs the identical validation code on every unit it receives, a single malicious unit broadcast to the network could be used to crash any node that processes it, i.e., "a network unable to confirm new units" if propagated broadly — directly matching the accepted impact categories (network unable to confirm new units / node disagreement due to some nodes crashing while others that already had a cached bad state do not).

### Likelihood Explanation
Likelihood is Medium: unlike the gvisor bug (which required root + volume-mount permission), reaching this code requires only posting an ordinary unit with a payment input referencing an existing unit/output — no special privilege, asset issuer status, or AA authorship required, which is a much weaker precondition than the original report. However, I was not able to fully confirm, given the exploration budget, the exact double-spend/finalization sequence in `main_chain.js`/`writer.js` that would leave a stable output's `sequence` value as `'temp-bad'` rather than resolved to `'good'`/`'final-bad'` before stabilization — this is stated as an internally-believed invariant ("should never happen") rather than a proven-reachable state from my analysis. Confirming exploitability requires tracing the full sequence-resolution state machine across `main_chain.js` (stability advancement) and `writer.js` (sequence finalization on stabilization), which I could not fully complete within this investigation.

### Recommendation
- Replace the `throw Error("spending a stable temp-bad output " + input.unit)` (and the sibling `throw` at `validation.js:2450-2451` "more than 1 src output") with a normal validation-error return (`return cb(...)`) so a violated invariant rejects only the offending unit instead of crashing the process.
- Audit all `throw` statements reachable from `validate()`/`validateAuthor`/`validatePaymentInputsAndOutputs`/AA trigger validation that represent "should never happen" invariants and convert genuinely externally-triggerable ones into graceful `ifUnitError`/`ifTransientError` callbacks.
- If the invariant is provably unreachable given current business logic, add a regression test to lock in that guarantee, and consider catching such internal-consistency exceptions at the `validate()` boundary and mapping them to `ifUnitError` rather than letting them propagate to `uncaughtException`.

### Proof of Concept
Not established. Reaching the `throw` requires constructing a unit whose spent output is stable (`main_chain_index <= last_ball_mci`) yet still has `sequence = 'temp-bad'` at read time — I could not trace a concrete, confirmed sequence-transition bug in `main_chain.js`/`writer.js` within the scope of this investigation that produces that exact state. A conclusive PoC would require reproducing the double-spend resolution/stabilization state machine to show a stable unit whose `sequence` is never advanced past `'temp-bad'`.

### Citations

**File:** validation.js (L118-155)
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

	const bGenesis = storage.isGenesisUnit(objUnit.unit);

	var bAA = false;
	if (objJoint.aa) {
		bAA = true;
		var aa_mci = objJoint.aa_mci;
		delete objJoint.aa;
		delete objJoint.aa_mci;
	}
	else {
		if (isArrayOfLength(objUnit.authors, 1) && !isNonemptyObject(objUnit.authors[0].authentifiers) && !objUnit.content_hash && !conf.bLight)
			return callbacks.ifTransientError("possible AA");
	}
	
	if (isTooDeeplyNestedOrHasTooManyNodes(objUnit))
		return bAA ? callbacks.ifUnitError("unit is too deeply nested") : callbacks.ifJointError("unit is too deeply nested");
```

**File:** validation.js (L357-444)
```javascript
	mutex.lock(arrAuthorAddresses, function(unlock){
		
		var conn = null;
		var commit_fn = null;
		var start_time = null;

		async.series(
			[
				function(cb){
					if (external_conn) {
						conn = external_conn;
						start_time = Date.now();
						commit_fn = function (cb2) { cb2(); };
						return cb();
					}
					db.takeConnectionFromPool(function(new_conn){
						conn = new_conn;
						start_time = Date.now();
						commit_fn = function (cb2) {
							conn.query(objValidationState.bAdvancedLastStableMci ? "COMMIT" : "ROLLBACK", function () { cb2(); });
						};
						conn.query("BEGIN", function(){cb();});
					});
				},
				function(cb){
					profiler.start();
					checkDuplicate(conn, objUnit, cb);
				},
				function(cb){
					profiler.stop('validation-checkDuplicate');
					profiler.start();
					objUnit.content_hash ? cb() : validateHeadersCommissionRecipients(objUnit, cb);
				},
				function(cb){
					profiler.stop('validation-hc-recipients');
					profiler.start();
					!objUnit.parent_units
						? cb()
						: validateHashTreeBall(conn, objJoint, cb);
				},
				function(cb){
					profiler.stop('validation-hash-tree-ball');
					profiler.start();
					!objUnit.parent_units
						? cb()
						: validateParentsExistAndOrdered(conn, objUnit, cb);
				},
				function(cb){
					profiler.stop('validation-parents-exist');
					profiler.start();
					!objUnit.parent_units
						? cb()
						: validateHashTreeParentsAndSkiplist(conn, objJoint, cb);
				},
				function(cb){
					profiler.stop('validation-hash-tree-parents');
				//	profiler.start(); // conflicting with profiling in determineIfStableInLaterUnitsAndUpdateStableMcFlag
					!objUnit.parent_units
						? cb()
						: validateParents(conn, objJoint, objValidationState, cb);
				},
				function(cb){
				//	profiler.stop('validation-parents');
					profiler.start();
					!objJoint.skiplist_units
						? cb()
						: validateSkiplist(conn, objJoint.skiplist_units, cb);
				},
				function(cb){
					profiler.stop('validation-skiplist');
					validateWitnesses(conn, objUnit, objValidationState, cb);
				},
				function (cb) {
					validateAATrigger(conn, objUnit, objValidationState, cb);
				},
				function (cb) {
					validateTpsFee(conn, objJoint, objValidationState, cb);
				},
				function(cb){
					profiler.start();
					validateAuthors(conn, objUnit.authors, objUnit, objValidationState, cb);
				},
				function(cb){
					profiler.stop('validation-authors');
					profiler.start();
					objUnit.content_hash ? cb() : validateMessages(conn, objUnit.messages, objUnit, objValidationState, cb);
				}
			], 
```

**File:** validation.js (L1169-1174)
```javascript
		storage.readAADefinition(conn, objAuthor.address, objValidationState.aa_mci, function (arrDefinition) {
			if (!arrDefinition)
				throw Error("AA definition not found " + objAuthor.address);
			checkSerialAddressUse();
		});
		return;
```

**File:** validation.js (L2443-2461)
```javascript
					conn.query(
						"SELECT amount, is_stable, sequence, address, main_chain_index, denomination, asset \n\
						FROM units \n\
						LEFT JOIN outputs ON units.unit=outputs.unit AND message_index=? AND output_index=? \n\
						WHERE units.unit=?",
						[input.message_index, input.output_index, input.unit],
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

**File:** network.js (L1149-1184)
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
					purgeJointAndDependenciesAndNotifyPeers(objJoint, error, function(){
						delete assocUnitsInWork[unit];
					});
					unlock();
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
