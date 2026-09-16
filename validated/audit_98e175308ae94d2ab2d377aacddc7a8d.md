### Title
Unhandled exception in AA dry-run trigger evaluation crashes the node process - ([File: network.js])

### Summary
CVE-2019-2811 describes a MySQL bug where a network-reachable operation performed with sufficient privilege can trigger a hang/crash (complete DoS) of the database server due to an unhandled internal error condition. The analogous weakness in `ocore--019` is that the AA-trigger "dry run on submit" code path in `handleJoint`'s `ifOk` callback [1](#0-0)  invokes `aa_composer.getTrigger()` and `aa_composer.dryRunPrimaryAATrigger()` — functions that internally use bare `throw Error(...)` for a large number of "should never happen" invariant violations inside `aa_composer.js`'s `handleTrigger()` [2](#0-1)  and `getTrigger()` [3](#0-2)  — from inside an `async` function with no surrounding `try/catch`, and the codebase has no `process.on('unhandledRejection', ...)` handler in production code (only present in test files). In modern Node.js, an unhandled promise rejection terminates the process, so any unit that drives this code path into one of these throw conditions produces a full node crash.

### Finding Description
When `conf.bDryRunNewTriggers` is enabled and a node is not light and not replaying a ball-joint, every freshly submitted unit that has a payment output to an AA address is dry-run through the full AA trigger-composition machinery synchronously, in-band with normal unit validation, before the unit is even saved: [4](#0-3) 

The comment "if it would crash, let it crash now, not when we execute the trigger for real" makes explicit that the authors expect `getTrigger`/`dryRunPrimaryAATrigger`/`handleTrigger` to be able to throw. But this call happens inside `ifOk: async function (...)`, and any exception thrown synchronously inside that async function body (via `getTrigger`'s `throw Error("no outputs to " + receiving_address)` [5](#0-4) , or any of `handleTrigger`'s numerous internal invariant throws such as `throw Error("assocBalances and bAir do not match")`, `throw Error('bad AA definition ' + arrDefinition)`, `throw Error("unexpected params")`, `throw Error("base AA not found: " + template.base_aa)` [6](#0-5) ) turns into a rejected promise that nothing in `network.js` catches.

Because there is no global `unhandledRejection` handler registered in the production code (`grep` shows the handler exists only in `test/aa.test.js` and `test/aa_composer.test.js`), Node's default behavior for unhandled rejections applies — since Node.js 15, this crashes the process, exactly mirroring the "complete DOS ... hang or frequently repeatable crash" impact described in the CVE. The same `handleTrigger` throw-heavy pattern is also reached (without even the `bDryRunNewTriggers` gate) from the "real" trigger-execution path `handlePrimaryAATrigger` → `handleTrigger` → `handleSecondaryTriggers` → `getTrigger` [7](#0-6) , which every full node runs automatically once an AA-trigger becomes stable — so a poster does not even need `bDryRunNewTriggers` to be enabled; they only need to construct a trigger/secondary-call chain that hits one of these "impossible" branches on the real execution path, which every full node on the network executes identically and deterministically for the same stabilized unit.

### Impact Explanation
Any full/hub node whose operator has enabled `conf.bDryRunNewTriggers`, or — more critically — any full node processing a stabilized AA trigger through the mandatory `handleAATriggers`/`handleTrigger` pipeline, can be crashed by a single crafted but network-accepted unit if it drives execution into one of the many unguarded `throw Error(...)` invariant checks in `aa_composer.js`. Because AA-trigger processing runs identically and deterministically on every node that reaches the same stable MCI, a single malicious unit is a repeatable, network-wide denial of service: every node that processes the poisoned trigger crashes, matching the CVE's "frequently repeatable crash (complete DOS)" characterization exactly. This is reachable purely by posting an ordinary unit/AA trigger — no elevated privilege beyond being a normal unit poster or AA author is required.

### Likelihood Explanation
Exploitability depends on finding a concrete, currently-reachable input that survives all of `validation.js`'s `validateAATrigger` [8](#0-7)  and `aa_validation.js`'s AA-definition validation, yet still lands in one of `handleTrigger`'s "impossible" throw branches (e.g., a `base_aa` template pointing to an AA definition that is valid at definition-validation time but not resolvable via `storage.readAADefinition` at actual trigger-execution mci due to a race/catch-up timing difference, or a secondary-trigger address whose generated response unit ends up with no outputs to the intended address after formula evaluation). The extensive set of unguarded throws across `handleTrigger`, `getTrigger`, `handleSecondaryTriggers`, `evaluateAA`, and `validateAndSaveUnit` [9](#0-8)  constitutes a wide attack surface of "should never happen" assumptions that are enforced only by defensive programming, not by prior formal validation, and the total absence of an `unhandledRejection` guard means any one of them reaching an async context is fatal to the whole process rather than just failing the one unit.

### Recommendation
- Add a process-wide `process.on('unhandledRejection', ...)` handler analogous to the existing `uncaughtException` handler in `network.js` [10](#0-9) , so unexpected AA errors are logged/handled instead of silently promoting to a fatal crash while leaving the actual root cause of the DoS unaddressed.
- Wrap the dry-run AA call in `network.js`'s `ifOk` handler in a `try/catch`/`.catch()` that reports a normal `ifUnitError`/`ifJointError` instead of allowing the exception to propagate as an unhandled rejection.
- Convert the internal `throw Error(...)` invariant checks in `aa_composer.js` (`handleTrigger`, `getTrigger`, `handleSecondaryTriggers`, `validateAndSaveUnit`) into callback-based error returns (bounce/callback with error) wherever the invariant can actually be violated by attacker-controlled unit/trigger content, reserving `throw` only for conditions that are truly unreachable given upstream validation.

### Proof of Concept
Conceptual (not verified against a live network due to index/code-access limits noted below):
1. Define AA `A` as a parameterized AA with `base_aa` pointing to AA address `B`.
2. Ensure `B`'s AA-definition unit is stable relative to `A`'s own last-ball MCI at definition-validation time, but arrange for `B`'s definition to not yet be resolvable via `storage.readAADefinition` at the specific `mci` used during actual `handleTrigger` execution (e.g., by exploiting catch-up/timing skew between definition validation and trigger execution, or via `bDryRunNewTriggers` racing against unstabilized `aa_addresses` state).
3. Send a payment triggering `A`.
4. `handleTrigger` reaches `storage.readAADefinition(conn, template.base_aa, mci, ...)` with `arrBaseDefinition` falsy and executes `throw Error("base AA not found: " + template.base_aa)` inside the async context, crashing every node that processes this trigger, and (if `bDryRunNewTriggers` is enabled) crashing the receiving node immediately upon submission via the unguarded `ifOk` async handler in `network.js`.

Note: I was not able to fully confirm from static inspection whether `storage.readAADefinition`/`aa_validation.js` fully close this specific race for every code path, given the size of the codebase and index limits; a Devin session with full repository and test access would be needed to construct and confirm a concrete failing unit sequence end-to-end.

### Citations

**File:** network.js (L1258-1282)
```javascript
				ifOk: async function(objValidationState, validation_unlock){
					clearHost();
					if (objJoint.unsigned)
						throw Error("ifOk() unsigned");
					if (bPosted && objValidationState.sequence !== 'good') {
						validation_unlock();
						callbacks.ifUnitError("The transaction would be non-serial (a double spend)");
						delete assocUnitsInWork[unit];
						unlock();
						if (ws)
							writeEvent('nonserial', ws.host);
						return;
					}
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

**File:** aa_composer.js (L375-397)
```javascript
function getTrigger(objUnit, receiving_address) {
	var trigger = { address: objUnit.authors[0].address, unit: objUnit.unit, outputs: {} };
	if ("max_aa_responses" in objUnit)
		trigger.max_aa_responses = objUnit.max_aa_responses;
	objUnit.messages.forEach(function (message) {
		if (message.app === 'data' && !trigger.data) // use the first data message, ignore the subsequent ones
			trigger.data = message.payload;
		else if (message.app === 'payment' && message.payload) {
			var payload = message.payload;
			var asset = payload.asset || 'base';
			payload.outputs.forEach(function (output) {
				if (output.address === receiving_address) {
					if (!trigger.outputs[asset])
						trigger.outputs[asset] = 0;
					trigger.outputs[asset] += output.amount; // in case there are several outputs
				}
			});
		}
	});
	if (Object.keys(trigger.outputs).length === 0)
		throw Error("no outputs to " + receiving_address);
	return trigger;
}
```

**File:** aa_composer.js (L419-445)
```javascript
		if (!!trigger_opts.bAir !== !!trigger_opts.assocBalances)
			throw Error("assocBalances and bAir do not match");
	}
	else
		trigger_opts = { conn, batch, trigger, params, stateVars, arrDefinition, address, mci, objMcUnit, bSecondary, arrResponses, onDone };
	if (arrDefinition[0] !== 'autonomous agent')
		throw Error('bad AA definition ' + arrDefinition);
	if (!trigger.initial_address)
		trigger.initial_address = trigger.address;
	if (!trigger.initial_unit)
		trigger.initial_unit = trigger.unit;
	var error_message = '';
	var responseVars = {};
	var template = arrDefinition[1];
	if (template.base_aa) { // parameterized AA
		if (params && Object.keys(params).length > 0)
			throw Error("unexpected params");
		storage.readAADefinition(conn, template.base_aa, mci, function (arrBaseDefinition) {
			if (!arrBaseDefinition)
				throw Error("base AA not found: " + template.base_aa);
			console.log("redirecting to base AA " + template.base_aa + " with params " + JSON.stringify(template.params));
			trigger_opts.params = template.params;
			trigger_opts.arrDefinition = arrBaseDefinition;
			handleTrigger(trigger_opts);
		});
		return;
	}
```

**File:** aa_composer.js (L1720-1741)
```javascript
			async.eachSeries(
				rows,
				function (row, cb) {
					var child_trigger = getTrigger(objUnit, row.address);
					child_trigger.initial_address = trigger.initial_address;
					child_trigger.initial_unit = trigger.initial_unit;
					if ("max_aa_responses" in trigger && mci >= constants.pemCurvesFixMci) // propagate the cap set on the primary trigger to secondary triggers
						child_trigger.max_aa_responses = trigger.max_aa_responses;
					var arrChildDefinition = JSON.parse(row.definition);

					var child_trigger_opts = { ...trigger_opts };
					child_trigger_opts.trigger = child_trigger;
					child_trigger_opts.params = {};
					child_trigger_opts.arrDefinition = arrChildDefinition;
					child_trigger_opts.address = row.address;
					child_trigger_opts.bSecondary = true;
					child_trigger_opts.onDone = function (objSecondaryUnit, bounce_message) {
						if (bounce_message)
							return cb(bounce_message);
						cb();
					};
					handleTrigger(child_trigger_opts);
```

**File:** aa_composer.js (L1800-1838)
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
	}
```

**File:** validation.js (L986-1038)
```javascript
async function validateAATrigger(conn, objUnit, objValidationState, callback) {
	if (objValidationState.last_ball_mci < constants.v4UpgradeMci || objValidationState.bAA || !objValidationState.last_ball_mci) {
		if ("max_aa_responses" in objUnit)
			return callback(`max_aa_responses should not be there`);
		if (objValidationState.bAA || !objValidationState.last_ball_mci)
			return callback();
	}
	if ("content_hash" in objUnit) { // messages already stripped off
		objValidationState.count_primary_aa_triggers = 0;
		return callback();
	}
	if (objUnit.max_aa_responses === 0 && (objValidationState.last_ball_mci >= constants.pemCurvesFixMci || !objValidationState.hasBall && storage.getMinRetrievableMci() >= constants.pemCurvesFixMci))
		return callback(`max_aa_responses=0 is not allowed`);
	let outputCounts = {};
	for (let m of objUnit.messages) {
		if (m.app === 'payment' && m.payload) {
			const asset = m.payload.asset || 'base';
			for (let o of m.payload.outputs) {
				if (!outputCounts[o.address])
					outputCounts[o.address] = {};
				if (!outputCounts[o.address][asset])
					outputCounts[o.address][asset] = 0;
				outputCounts[o.address][asset]++;
			}
		}
	}
	const arrOutputAddresses = Object.keys(outputCounts);
	if (arrOutputAddresses.length === 0)
		return callback("no output addresses found in payment messages");

	// Look for AA triggers
	// There might be actually more triggers due to AAs defined between last_ball_mci and our unit, so our validation of tps fee might require a smaller fee than the fee actually charged when the trigger executes
	const rows = await conn.query("SELECT address FROM aa_addresses WHERE address IN (?) AND mci<=?", [arrOutputAddresses, objValidationState.last_ball_mci]);
	if (rows.length === 0) {
		if ("max_aa_responses" in objUnit)
			return callback(`no outputs to AAs, max_aa_responses should not be there`);
		return callback();
	}
	objValidationState.count_primary_aa_triggers = rows.length;
	if (objValidationState.count_primary_aa_triggers > 1) {
		if (objValidationState.last_ball_mci >= constants.pemCurvesFixMci)
			return callback(`more than 1 primary AA trigger (${objValidationState.count_primary_aa_triggers})`);
		if (storage.getMinRetrievableMci() > constants.pemCurvesFixMci)
			return callback(createTransientError(`more than 1 primary AA trigger (${objValidationState.count_primary_aa_triggers})`));
	}
	if ((objValidationState.last_ball_mci >= constants.pemCurvesFixMci || !objValidationState.hasBall && storage.getMinRetrievableMci() >= constants.pemCurvesFixMci) && objValidationState.count_primary_aa_triggers === 1) {
		const address = rows[0].address;
		for (let asset in outputCounts[address]) {
			if (outputCounts[address][asset] > 1)
				return callback(`more than 1 output to the same AA ${address} for asset ${asset}`);
		}
	}
	callback();
```
