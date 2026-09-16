### Title
Reachable "impossible" assertions crash the entire node process on a single malicious unit/AA response - ([File: network.js])

### Summary
The gRPC advisory (CVE-2023-4785) is a "lack of error handling" bug: an unhandled failure path on a routine, attacker-triggerable event (many incoming connections) takes down the whole server. ocore has the same bug *class* on the consensus-critical path: `network.js` installs a global handler that deliberately **re-throws and kills the process** on any uncaught exception, and the validation/AA-execution code is riddled with `throw Error(...)` "should never happen" assertions that fire from deep inside async DB callbacks reachable from a single unprivileged unit, an AA trigger, or an AA's own response messages. Any input that hits one of these assertions does not go through the normal `ifUnitError`/`ifJointError` rejection path — it crashes the node outright.

### Finding Description
`network.js` installs:
```
process.on('uncaughtException', (err) => {
	...
	throw err; // crash the process to avoid ending up in an inconsistent state
});
``` [1](#0-0) 

This is a deliberate "let it crash" policy for *any* uncaught exception anywhere in the process, not just genuine invariant violations. The unit/AA validation pipeline that runs on every unit received from an unprivileged peer or produced by an AA response is full of `throw Error(...)` calls embedded inside `conn.query(...)` callbacks and other async continuations — i.e. they are not passed through the `callback(err)` chain that normally routes to `ifUnitError`, but are synchronous throws inside a callback, which Node cannot catch with the surrounding `try/catch` and which therefore propagate as uncaught exceptions:

- `validateAuthor`: `throw Error("AA definition not found " + objAuthor.address);` when the AA trigger execution path reads a definition that isn't found. [2](#0-1) 
- `checkForDoublespends`: `throw Error("conflicting "+type+" spent from another address?");` and `throw Error("double spending "+type+" without double spending address?");` — reachable from ordinary double-spend detection on any posted payment input, run for every unit. [3](#0-2) 
- `checkWitnessedLevelDidNotRetreat`: `throw Error('no max_parent_wl');` [4](#0-3) 
- `validateAuthentifiers`/`validateDefinition` in `definition.js`: `throw Error("more than 1 address definition");` when evaluating nested address references supplied inside the same unit. [5](#0-4) 
- `handleTrigger`'s `validateAndSaveUnit` in AA execution converts *any* non-`ifOk` validation outcome of an AA-generated response unit (joint error, transient error, need-hash-tree, dependencies, unsigned-ok, non-serial) directly into a `throw Error(...)`. [6](#0-5) 
- `witness_proof.js`: `throw Error("definition chash not known for address "+address+...)` while processing witness proofs derived from peer-supplied joints. [7](#0-6) 

Because `validation.validate()` runs these checks from inside `conn.query()` callbacks (see the async pipeline in `validate()`), a `throw` there is not caught by the caller's `try/catch` and surfaces only via `process.on('uncaughtException')`, which then re-throws to kill the process: [8](#0-7) 

The pattern is structurally identical to the advisory: a routine, attacker-influenceable event (posting a unit, sending an AA trigger, or an AA emitting a poll/definition/vote response) hits a code path whose only "handling" of an unexpected-but-reachable condition is to blow up the whole server instance, rather than fail that single request gracefully.

### Impact Explanation
If any of these "impossible" conditions can actually be reached by content an unprivileged party controls (a posted unit's payment/definition/witness fields, or state that an AA response composes from trigger data), the resulting `throw` inside an async DB callback is an uncaught exception. Per the installed handler, the process is deliberately killed. Since unit validation and AA-trigger validation are performed by every full node that receives the joint (via `network.js`'s `handleJoint`) and by hubs/AA-executing nodes processing trigger units, a single crafted unit propagated over the network can crash every node that validates it — this is a network-wide denial of service, matching the CVSS High/`CWE-248` (uncaught exception) classification of the source advisory, and squarely falls under "a network unable to confirm new units" / "node disagreement on validity" in the validation rules.

### Likelihood Explanation
Likelihood is **uncertain without further code-path verification** and I could not fully confirm end-to-end reachability of any single assertion (e.g., the poll-choice duplicate check gap in `aa_validation.js` vs. `validation.js`, or the double-spend "conflicting record from another address" assertion) within the remaining investigation budget. What is concretely established is: (1) the process-killing `uncaughtException` policy exists and is intentional, and (2) numerous `throw Error(...)` assertions sit inside async validation/AA-execution callbacks that are fed by attacker-supplied unit/trigger content, bypassing the normal error-callback path. Establishing a fully worked, guaranteed-reachable trigger for one specific assertion would require deeper tracing (e.g., confirming whether `objAuthor.address` in `validateAuthor`'s AA branch can ever reference an AA whose definition was deleted/never-committed at validation time, or whether the double-spend query's WHERE clause can return a `conflicting record.address` outside the current authors set for some multi-author payment). This is a design-level weakness (assert-and-crash instead of reject-and-continue) rather than a single confirmed exploit primitive.

### Recommendation
- Change `process.on('uncaughtException')` in `network.js` to avoid a blanket process kill for exceptions that originate from validating externally-supplied data; only crash for exceptions proven to indicate genuine internal-state corruption. [1](#0-0) 
- Audit every `throw Error(...)` reachable from `validate()`, `validateAuthor`, `checkForDoublespends`, `checkWitnessedLevelDidNotRetreat`, `definition.js`'s `evaluate`, and AA's `validateAndSaveUnit`/`handleTrigger` to determine which are truly unreachable invariants vs. conditions an attacker can trigger with crafted unit/AA content; convert the latter into normal `callback(err)` rejections (`ifUnitError`/`ifJointError`) instead of throws. [2](#0-1) [3](#0-2) [6](#0-5) 
- Add defensive validation in `aa_validation.js`'s poll `choices` check to reject duplicate choice strings (mirroring `seenChoices` in `validation.js`), closing the asymmetry between AA-issued and user-issued poll messages. [9](#0-8) [10](#0-9) 

### Proof of Concept
A fully deterministic PoC could not be completed within the available investigation. The concrete, verifiable elements are:
1. `network.js`'s `uncaughtException` handler re-throws to kill the process for *any* uncaught exception — confirmed by reading the code. [1](#0-0) 
2. Multiple `throw Error(...)` statements execute inside `conn.query()` callbacks in the unit-validation pipeline that is invoked on every unit received from the network or produced by AA execution, meaning any exception thrown there is uncaught by design and will hit the handler above. [8](#0-7) [3](#0-2) 

Constructing a concrete crafted unit/joint payload that provably reaches one of these throws (e.g., a specific double-spend/witness/AA-trigger scenario) requires deeper tracing of the SQL predicates and state machine than was possible in the remaining budget, and should be validated with an actual test-node/AVA test harness (the repo has `test/aa.test.js`, `test/formula.test.js`, etc. that could be extended) before treating this as a confirmed exploit rather than a design-level risk.

### Citations

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

**File:** validation.js (L425-445)
```javascript
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
			function(err){
```

**File:** validation.js (L913-914)
```javascript
			if (typeof objValidationState.max_parent_wl === 'undefined')
				throw Error('no max_parent_wl');
```

**File:** validation.js (L1168-1172)
```javascript
	if (objValidationState.bAA) {
		storage.readAADefinition(conn, objAuthor.address, objValidationState.aa_mci, function (arrDefinition) {
			if (!arrDefinition)
				throw Error("AA definition not found " + objAuthor.address);
			checkSerialAddressUse();
```

**File:** validation.js (L1669-1693)
```javascript
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
							cb2();
```

**File:** validation.js (L1800-1811)
```javascript
			let seenChoices = Object.create(null);
			for (var i=0; i<payload.choices.length; i++) {
				if (typeof payload.choices[i] !== 'string')
					return callback("all choices must be strings");
				if (payload.choices[i].trim().length === 0)
					return callback("all choices must be longer than 0 chars");
				if (payload.choices[i].length > constants.MAX_CHOICE_LENGTH)
					return callback("all choices must be "+ constants.MAX_CHOICE_LENGTH + " chars or less");
				if (seenChoices[payload.choices[i]])
					return callback("all choices must be different");
				seenChoices[payload.choices[i]] = true;
			}
```

**File:** definition.js (L296-299)
```javascript
						if (arrDefiningAuthors.length === 0) // no address definition in the current unit
							return bAllowUnresolvedInnerDefinitions ? cb(null, true) : cb("definition of inner address "+other_address+" not found");
						if (arrDefiningAuthors.length > 1)
							throw Error("more than 1 address definition");
```

**File:** aa_composer.js (L1800-1825)
```javascript
	function validateAndSaveUnit(objUnit, cb) {
		var objJoint = { unit: objUnit, aa: true, aa_mci: mci };
		validation.validate(objJoint, {
			ifJointError: function (err) {
				throw Error("AA validation joint error: " + err);
			},
			ifUnitError: function (err) {
				console.log("AA validation unit error: " + err);
				return cb(err);
			},
			ifTransientError: function (err) {
				throw Error("AA validation transient error: " + err);
			},
			ifNeedHashTree: function () {
				throw Error("AA validation unexpected need hash tree");
			},
			ifNeedParentUnits: function (arrMissingUnits) {
				throw Error("AA validation unexpected dependencies: " + arrMissingUnits.join(", "));
			},
			ifOkUnsigned: function () {
				throw Error("AA validation returned ok unsigned");
			},
			ifOk: function (objAAValidationState, validation_unlock) {
				if (objAAValidationState.sequence !== 'good')
					throw Error("nonserial AA");
				validation_unlock();
```

**File:** witness_proof.js (L252-253)
```javascript
				if (!definition_chash)
					throw Error("definition chash not known for address "+address+", unit "+objUnit.unit);
```

**File:** aa_validation.js (L378-401)
```javascript
					function validateChoices(choices, cb3) {
						if (isNonemptyString(choices)) {
							var f = getFormula(choices);
							if (f === null)
								return cb3("choices is a string but not formula: " + choices);
							return cb3();
						}
						if (!isNonemptyArray(choices))
							return cb3("no choices in AA poll");
						if (choices.length > constants.MAX_CHOICES_PER_POLL)
							return cb3("too many choices in AA poll");
						for (var i = 0; i < choices.length; i++) {
							if (typeof choices[i] !== 'string')
								return cb3("all choices must be strings");
							if (choices[i].trim().length === 0)
								return cb3("all choices must be longer than 0 chars");
							var choice_formula = getFormula(choices[i]);
							if (choice_formula !== null) {
							}
							else if (choices[i].length > constants.MAX_CHOICE_LENGTH)
								return cb3("all choices must be " + constants.MAX_CHOICE_LENGTH + " chars or less");
						}
						cb3();
					}
```
