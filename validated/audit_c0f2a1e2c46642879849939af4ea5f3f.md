### Title
Reachable assertion-style `throw Error()` in payment input validation crashes the node on attacker-crafted input — ([File: validation.js])

### Summary
CVE-2017-12959 is a reachable-assertion DoS in `dict_add_mrset()`: an internal invariant assumed by the parser is violated by crafted-but-parseable input, triggering an `assert()` abort of the whole process. `ocore`'s unit-validation pipeline in `validation.js` contains the same anti-pattern: several code paths reached while validating an ordinary, unprivileged unit rely on `throw Error(...)` to enforce invariants that are assumed — but not proven — to always hold. Because these `throw` statements execute inside asynchronous `conn.query()` callbacks deep in the `async.series`/`async.forEachOfSeries` control flow of `validate()`, they are not caught by any surrounding `try/catch` and propagate as an uncaught exception, crashing the Node.js process, exactly like an `assert()` abort in the C analog.

### Finding Description
`validatePaymentInputsAndOutputs()` (part of `validateMessages` → `validateMessage` → `validateInlinePayload`, all reachable directly from `validate()`) processes payment inputs supplied verbatim by whoever posts the unit. When validating a `"transfer"` input it queries the referenced source output and enforces several conditions with plain `if` checks that return a normal validation error (`cb(...)`), but a subset of conditions instead `throw Error(...)`, e.g.: [1](#0-0) 

and the analogous invariant-violation throws further up in `checkForDoublespends`: [2](#0-1) 

These `throw`s assume that a stable output can never have `sequence === 'temp-bad'`, that a double-spend’s conflicting record can only belong to an address that authored the current unit, and that once a fork is detected the losing address is always tracked in `arrAddressesWithForkedPath`. All of this state is derived from data written by earlier processing of units that themselves originated from unprivileged posters (payments, AA responses, and asset transfers), and the invariants are enforced only by convention across many code paths (`writer.js`, `main_chain.js`), not by a single authoritative check. As seen in `dict_add_mrset`, whenever an edge case in upstream state construction (e.g., non-serial forks, double-spends across an unusual number of conflicting branches, timing of AA writes, or a race between two concurrently validated units for the same author) produces state that these invariants don't anticipate, the `throw Error(...)` fires.

Crucially, unlike the many other checks in `validateMessage`/`validateAuthor`/`validateParents` that report failures through the callback chain (`return callback("...")`), these particular checks abort synchronously with `throw`. Since they execute inside `conn.query` callbacks nested several levels deep in `async.series`, there is no enclosing `try/catch` in `validate()` (the only `try/catch` wraps the initial hash computation at the top of `validate()`): [3](#0-2) 

An uncaught exception thrown from inside a database-driver callback is not caught by Node's normal error-handling and results in process termination (or, in some drivers, an unhandled promise-rejection state that halts further event-loop work), taking down the whole node.

### Impact Explanation
Any unprivileged unit poster who can arrange for the validator to reach one of these invariant-violation branches (for example, by causing a legitimate-looking but sequence-ambiguous double-spend, or exploiting a race between concurrently-processed conflicting inputs) can crash the validating node process. Because `validate()` is on the hot path for every incoming unit (via `network.js`'s `handleJoint` → `validation.validate`) and also for AA triggers (`aa_composer.js`'s `validateAndSaveUnit`), a single crafted unit can stop a node from continuing to validate and confirm new units — a network-availability impact ("network unable to confirm new units") consistent with the required impact classes, without requiring a malicious peer/hub — the trigger is the unit's content itself, postable by anyone.

### Likelihood Explanation
Reaching these specific `throw` branches requires assembling a precise combination of database state (a source output that is stable yet not in "good"/"final-bad" sequence, or a double-spend whose conflicting record belongs to a non-author address) that the surrounding code assumes cannot occur. This is a non-trivial but realistic scenario given the complexity of DAG forks, double-spend resolution, and asynchronous validation of concurrent units — the same class of "should never happen" condition that historically has been hit in production DAG-consensus systems. Exploitability is Medium-to-High: it does not require any privileged role, only crafting units/inputs that create the fork/double-spend state.

### Recommendation
Replace all invariant-enforcing `throw Error(...)` calls inside `validatePaymentInputsAndOutputs`/`checkForDoublespends` (and equivalent spots elsewhere in `validation.js`) that are reachable while processing untrusted, attacker-supplied unit content with regular `callback("...")` unit-validation errors instead of hard throws. Where such states genuinely indicate unrecoverable internal corruption (not attacker-reachable), keep the `throw` but audit call paths to guarantee external input cannot reach them, and wrap outer async callbacks with defensive `try/catch` that convert unexpected exceptions into `ifTransientError`/`ifUnitError` responses rather than allowing them to crash the process.

### Proof of Concept
Conceptual reproduction (exact DB state construction not verified end-to-end due to index limitations):
1. Post two units, A and B, that both reference the same public payment output as an input from different addresses such that one is later resolved with `sequence` other than `'good'`/`'final-bad'` while stable (e.g., through a `'temp-bad'` state that is expected to be transient before stabilization).
2. Post a third unit C that spends the same output referenced by A once A's output row is stable but still carries `sequence === 'temp-bad'`.
3. When validator reaches `validatePaymentInputsAndOutputs` for unit C and evaluates the source-output row for A, it hits:
`if (src_output.sequence === 'temp-bad') throw Error("spending a stable temp-bad output " + input.unit);` [4](#0-3) 
4. The `throw` is not caught anywhere in the async call chain and crashes the node process handling this validation.

Note: I was not able to fully confirm, purely from the indexed code, the exact sequence of writer/main_chain operations that leaves a stable output with `sequence === 'temp-bad'` (this requires tracing `writer.js` and `main_chain.js` state transitions in more depth than the index surfaced). I recommend a Devin session with full repository access to trace `sequence` state transitions in `writer.js` and `main_chain.js` to build a concrete, testable PoC unit sequence.

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

**File:** validation.js (L1661-1692)
```javascript
function checkForDoublespends(conn, type, sql, arrSqlArgs, objUnit, objValidationState, onAcceptedDoublespends, cb){
	conn.query(
		sql, 
		arrSqlArgs,
		function(rows){
			if (rows.length === 0)
				return cb();
			var arrAuthorAddresses = objUnit.authors.map(function(author) { return author.address; } );
			async.eachSeries(
				rows,
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

**File:** validation.js (L2450-2458)
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
```
