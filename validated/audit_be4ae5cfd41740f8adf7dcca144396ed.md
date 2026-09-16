### Title
Uncaught `throw Error()` during AA trigger execution crashes the whole node - (File: aa_composer.js, formula/evaluation.js)

### Summary
CVE-2019-10162 crashes PowerDNS because the authoritative server exits on an internal parsing/lookup error while automatically processing a record that an unprivileged zone owner controls (an outgoing NOTIFY lookup on a MASTER zone), instead of treating the failure as a local/soft error. The analogous bug class in ocore is that AA trigger execution paths use bare `throw Error(...)` for conditions the developers believed "can't happen," but these throws execute deep inside async callback chains that have no surrounding `try/catch`. Since `network.js` installs a global `process.on('uncaughtException', ...)` handler that deliberately re-throws to kill the process (`network.js:4530-4543`), any such internal throw reachable from data an ordinary unit-poster controls (a payment to an AA address, i.e. an AA trigger) brings down the entire node, not just the offending unit.

### Finding Description
Any address (unprivileged) can trigger execution of an Autonomous Agent by sending it a payment; this queues a row in `aa_triggers` and is later executed by `handlePrimaryAATrigger` / `handleTrigger` in `aa_composer.js`: [1](#0-0) 

`handleTrigger` and its numerous nested helper functions (`pickParents`, `bounce`, `finish`, `handleSecondaryTriggers`, `validateAndSaveUnit`, etc.) are riddled with `throw Error(...)` statements guarding conditions such as "limci of last AA > mci", "response_unit with bouncing a secondary AA", "secondary triggers while bouncing", "AA validation joint error", "AA writer returned error", etc.: [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) 

These are executed inside deeply nested `db.query`/callback chains with **no `try/catch`** anywhere in the call stack back to the event loop. The formula/oscript evaluator that runs the AA's own logic (`formula/evaluation.js`) contains the same pattern - dozens of `throw Error(...)` calls used as internal sanity assertions during formula evaluation of attacker-influenced `trigger.data`/`trigger.output`/state variables, e.g. the `last_ball_timestamp` assertion and the "bad opts for non-AA" assertion at the top of `evaluate()`: [6](#0-5) 

Because `validateAADefinition`/`formulaValidator.validate` (static validation, `aa_validation.js`/`formula/validation.js`) and the actual runtime `evaluate()` in `formula/evaluation.js` are two independently maintained implementations of the same grammar, any place where they disagree about what is "impossible" turns a merely-invalid trigger into an unhandled exception at evaluation time rather than a graceful `bounce()`. The developers were clearly aware of this risk: the dry-run path added specifically to catch such crashes before "real" execution states this directly — *"if it would crash, let it crash now, not when we execute the trigger for real"*: [7](#0-6) 

When such a throw fires (during either the dry run in `network.js` `ifOk` or the real trigger execution in `aa_composer.js handleAATriggers`), it becomes an uncaught exception. `network.js` registers a global handler that logs it and then **deliberately re-throws to crash the process**: [8](#0-7) 

This is the direct structural analog of CVE-2019-10162: an unprivileged party (there, the owner of a MASTER zone; here, any unit poster who can address a payment/trigger to a public AA) causes the node, while performing routine, automatic follow-up processing of that party's own data (there, NOTIFY lookups; here, AA trigger execution), to hit an internal error path that the code treats as fatal (`throw`) instead of recoverable, taking the whole server down.

### Impact Explanation
A crashed full node is a denial of service: it stops confirming new units, stops running any other AAs, and (per `network.js:4533-4540`) all pending client requests are aborted. Because triggers are processed asynchronously from the `aa_triggers` table after a unit stabilizes, an attacker only needs to get **one** malformed trigger stabilized once to crash every full node that reaches that MCI, which is a synchronized, reproducible network-wide DoS rather than a single-peer issue — this maps to the report's accepted impact category "a network unable to confirm new units."

### Likelihood Explanation
Reaching any *specific* one of these internal throws requires finding a concrete formula/state/definition construction where the static validator (`aa_validation.js` / `formula/validation.js`) accepts a formula/trigger as valid, but the runtime evaluator (`formula/evaluation.js`) or the trigger orchestration (`aa_composer.js`) hits a code path whose author assumed "can never happen." This is exactly the class of bug PowerDNS had (validation/processing logic drift). The existence of the dedicated dry-run mechanism and its comment acknowledging trigger execution "would crash" is direct evidence that the codebase authors consider this a real, previously-observed risk category, not a theoretical one — but demonstrating a concrete unvalidated-yet-crashing formula/trigger combination requires deeper fuzzing of the oscript grammar/evaluator pair than is possible from static review alone.

### Recommendation
- Wrap the entire `handleTrigger`/`handleSecondaryTriggers`/`validateAndSaveUnit` call chain (and the formula `evaluate()` entry point) in a top-level `try/catch` that converts any internal `Error` into a normal AA bounce (`bounce(err.message)`) instead of letting it propagate to `uncaughtException`.
- Audit every `throw Error(...)` in `aa_composer.js` and `formula/evaluation.js` and reclassify those reachable from attacker-controlled `trigger`/formula content as recoverable errors (`return cb("...")` / `bounce(...)`), reserving `throw` only for conditions truly independent of any unit content (e.g. DB corruption).
- Add automated differential fuzzing between `formula/validation.js` (static validator) and `formula/evaluation.js` (runtime evaluator) to catch validator/evaluator divergence before deployment.
- Consider not re-throwing inside `process.on('uncaughtException', ...)` for errors that originate from AA-trigger processing specifically — instead void/skip just that trigger and continue operating, at minimum logging enough context to reproduce and fix without repeat outages.

### Proof of Concept
Not constructible from static analysis alone: exploitation requires discovering a concrete oscript/AA definition and trigger payload for which `aa_validation.js`/`formula/validation.js` returns no error but `formula/evaluation.js` or `aa_composer.js handleTrigger` hits one of the internal `throw Error(...)` assertions during execution (e.g. via a crafted `base_aa`/parameterized-AA redirection, a remote-AA `$f(...)` call, or a formula computing a state var name/format that the validator’s static analysis cannot fully model but the evaluator rejects with a hard throw instead of a bounce). Given the existence of the repo's own `dryRunPrimaryAATrigger` safety net and its comment acknowledging "it would crash," this is flagged as a design-level risk (validator/evaluator parity gap combined with process-crashing error handling) rather than a single reproduced exploit input.

### Citations

**File:** aa_composer.js (L91-101)
```javascript
function handlePrimaryAATrigger(mci, unit, address, arrDefinition, arrPostedUnits, onDone) {
	db.takeConnectionFromPool(function (conn) {
		conn.query("BEGIN", function () {
			var batch = kvstore.batch();
			readMcUnit(conn, mci, function (objMcUnit) {
				readUnit(conn, unit, function (objUnit) {
					var arrResponses = [];
					var trigger = getTrigger(objUnit, address);
					trigger.initial_address = trigger.address;
					trigger.initial_unit = trigger.unit;
					handleTrigger(conn, batch, trigger, {}, {}, arrDefinition, address, mci, objMcUnit, false, arrResponses, function(){
```

**File:** aa_composer.js (L896-900)
```javascript
						if (rows.length > 0) {
							var row = rows[0];
							if (row.latest_included_mc_index >= mci)
								throw Error("limci of last AA > mci");
							return handleParents([row.unit, objMcUnit.unit].sort());
```

**File:** aa_composer.js (L1671-1674)
```javascript
	function finish(objResponseUnit) {
		if (bBouncing && bSecondary) {
			if (objResponseUnit)
				throw Error('response_unit with bouncing a secondary AA');
```

**File:** aa_composer.js (L1717-1719)
```javascript
			}
			if (bBouncing)
				throw Error("secondary triggers while bouncing");
```

**File:** aa_composer.js (L1800-1837)
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
				objAAValidationState.bUnderWriteLock = true;
				objAAValidationState.conn = conn;
				objAAValidationState.batch = batch;
				objAAValidationState.initial_trigger_mci = mci;
				objAAValidationState.bDryRun = trigger_opts.bDryRun;
				writer.saveJoint(objJoint, objAAValidationState, null, function(err){
					if (err)
						throw Error('AA writer returned error: ' + err);
					cb();
				});
			}
		}, conn);
```

**File:** formula/evaluation.js (L93-98)
```javascript
	if (!ValidationUtils.isPositiveInteger(objValidationState.last_ball_timestamp))
		throw Error('last_ball_timestamp is not a number: ' + objValidationState.last_ball_timestamp);

	const bAA = (mci >= constants.pemCurvesFixMci) ? !opts.messages : (messages.length === 0);
	if (!bAA && (bStatementsOnly || bStateVarAssignmentAllowed || bObjectResultAllowed))
		throw Error("bad opts for non-AA");
```

**File:** network.js (L1271-1281)
```javascript
					if (conf.bDryRunNewTriggers && !conf.bLight && !objJoint.ball && objValidationState.count_primary_aa_triggers) {
						const outputAddresses = objJoint.unit.messages
							.filter(msg => msg.app === 'payment')
							.reduce((acc, msg) => acc.concat(msg.payload.outputs.map(output => output.address)), []);
						const rows = await db.query("SELECT address, definition FROM aa_addresses WHERE address IN (?)", [outputAddresses]);
						for (let { address, definition } of rows) {
							console.log(`dry run trigger for AA address ${address} in submitted unit ${unit}`);
							const trigger = aa_composer.getTrigger(objJoint.unit, address);
							// if it would crash, let it crash now, not when we execute the trigger for real
							await aa_composer.dryRunPrimaryAATrigger(trigger, address, JSON.parse(definition));
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
