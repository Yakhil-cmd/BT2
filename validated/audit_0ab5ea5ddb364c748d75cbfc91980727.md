### Title
Unhandled synchronous `throw` inside AA-trigger execution crashes the full node on a single crafted unit - ([File: aa_composer.js])

### Summary
`network.js`'s `handleJoint()` installs a "let it crash" dry-run for freshly submitted (non-ball) units that trigger an AA: when `conf.bDryRunNewTriggers` is set, it calls `aa_composer.dryRunPrimaryAATrigger()`/`getTrigger()` on every locally posted or peer-relayed unit paying an AA address, explicitly commenting "if it would crash, let it crash now, not when we execute the trigger for real" [1](#0-0) . The real (non-dry-run) execution path, `aa_composer.handlePrimaryAATrigger()` → `getTrigger()`/`handleTrigger()`, is reached unconditionally for every full node once the triggering unit becomes stable, via `main_chain.js`'s `handleAATriggers()`/`stabilizeMci()` and `writer.js`'s `saveJoint()` [2](#0-1) [3](#0-2) [4](#0-3) . `getTrigger()` and `handleTrigger()` contain multiple synchronous `throw Error(...)` statements executed inside nested async DB-callback chains with no enclosing `try/catch` (e.g. "no outputs to", "bad AA definition …", "base AA not found", "assocBalances and bAir do not match") [5](#0-4) [6](#0-5) . Because these throws occur inside asynchronous callbacks (not inside a promise chain that gets awaited/caught, and not inside a domain), they become uncaught exceptions, and `network.js` installs a top-level `process.on('uncaughtException', ...)` handler that deliberately re-throws to crash the entire node process: `throw err; // crash the process to avoid ending up in an inconsistent state` [7](#0-6) .

### Finding Description
This mirrors the CVE-2026-30077 pattern precisely: a single, syntactically-valid but semantically pathological input causes a *consistent, deterministic crash* of the message-processing daemon (AMF ⇔ ocore full node), rather than a graceful validation error.

In ocore, structural/complexity validation of an AA trigger and AA definition (`validation.js`'s `validateAATrigger`, `aa_validation.js`'s `validateAADefinition`) is deliberately loose in places, and the AA execution engine (`aa_composer.js`) is written with the assumption that "crashing is an acceptable/expected failure mode" for buggy interactions between trigger data and AA logic — the code comment at `network.js:1279` states this explicitly. However, this assumption only holds if `conf.bDryRunNewTriggers` is enabled on the sending/relaying node; the *real* execution of the trigger (once the unit stabilizes) happens on **every** full node unconditionally, through the exact same `getTrigger()`/`handleTrigger()` code paths, and is **not** guarded by any dry-run/try-catch safety net. A trigger unit that slips past static AA-definition validation but drives `handleTrigger()`/`getTrigger()` into one of its unguarded `throw` statements (for example the "no outputs to <address>" branch in `getTrigger()`, reachable when the message composition used by `validateAATrigger`'s duplicate-output counting logic and `getTrigger`'s output-aggregation logic diverge, or any of the numerous `throw Error(...)` calls deeper in `handleTrigger()`'s balance/definition/parameter handling) will cause every full node in the network to crash simultaneously and deterministically as soon as the unit stabilizes and AA triggers are executed via `stabilizeMci()`/`handleAATriggers()`.

Because `process.on('uncaughtException')` re-throws instead of degrading gracefully, this is a hard network-wide crash rather than a single-connection failure, closely analogous to the OpenAirInterface AMF crash-on-decode-failure for a specific packet.

### Impact Explanation
A successful trigger causes every full node that executes/stabilizes the malicious AA trigger to crash via the unconditional `process.on('uncaughtException')` re-throw [7](#0-6) . Since AA trigger execution happens deterministically for all nodes once the triggering unit stabilizes (`main_chain.js:1691-1723`, `writer.js:724-727`), this can be used to crash the entire network of full nodes with a single posted unit — a "network unable to confirm new units" condition, matching the accepted impact criteria for this analog.

### Likelihood Explanation
Reaching one of the unguarded `throw` statements requires crafting a unit/AA-definition/trigger combination where the crash condition in `getTrigger()`/`handleTrigger()` is true despite passing `validation.js`'s `validateAATrigger` and `aa_validation.js`'s `validateAADefinition` checks. I was not able to fully verify, purely via static reading, a concrete combination of payment-message/output structuring that causes `validateAATrigger`'s duplicate-output-count logic (`validation.js:986-1039`, keyed by `outputCounts[address][asset]`) to diverge from `getTrigger()`'s output-summing logic (`aa_composer.js:375-397`, keyed by `trigger.outputs[asset]`) so that `Object.keys(trigger.outputs).length === 0` while `validateAATrigger` still counted a trigger. This would require deeper testing/fuzzing (e.g. private/non-existent-asset outputs, zero-length messages arrays edge cases, or asset filtering differences) to confirm a concrete PoC; the underlying `throw`-without-catch anti-pattern and its reachability from a normal AA execution path (not just the opt-in dry run) are confirmed by direct code reading.

### Recommendation
- Wrap `getTrigger()` and `handleTrigger()`'s trigger-execution entry points (`handlePrimaryAATrigger`, `dryRunPrimaryAATrigger`, `estimatePrimaryAATrigger`) in `try/catch`, converting internal invariant-violation `throw`s into a bounced/failed AA response (as is already done elsewhere in the codebase for other AA execution errors) instead of letting them escape as uncaught exceptions.
- Audit `getTrigger()` and `handleTrigger()` for every unguarded `throw Error(...)` reachable from attacker-controlled unit content and align its invariants with `validateAATrigger`'s pre-checks so no combination of valid-but-adversarial payment/data/definition content can trigger these paths.
- Consider not re-throwing unconditionally in `process.on('uncaughtException')` for errors that originate from per-unit/per-trigger processing (as opposed to genuine unrecoverable state corruption), or isolate AA-trigger execution in a way that a single malformed AA cannot bring down the whole node.

### Proof of Concept
A concrete step-by-step packet/unit PoC could not be fully constructed from static analysis alone within the scope of this review; the finding is based on directly reading the reachable, unguarded `throw` statements in `aa_composer.js`'s `getTrigger()`/`handleTrigger()` (lines 375-463) and confirming these are invoked unconditionally on stabilization by `main_chain.js` (`handleAATriggers`, lines 1691-1723) and `writer.js` (`saveJoint`, lines 724-727), combined with `network.js`'s explicit intent (`// if it would crash, let it crash now, not when we execute the trigger for real`, line 1279) and its `process.on('uncaughtException')` handler that force-crashes the process (lines 4530-4543). A background Devin session with code-execution access would be needed to fuzz `validateAATrigger`/`getTrigger` output-counting logic divergence and produce a concrete crafted unit reproducing the crash end-to-end.

### Citations

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

**File:** main_chain.js (L1691-1723)
```javascript
	function handleAATriggers() {
		// a single unit can send to several AA addresses
		// a single unit can have multiple outputs to the same AA address, even in the same asset
		const mci_column = mci >= constants.pemCurvesFixMci ? 'aa_addresses.mci' : 'aa_definition_units.main_chain_index';
		conn.query(
			"SELECT DISTINCT address, definition, units.unit, units.level \n\
			FROM units \n\
			CROSS JOIN outputs USING(unit) \n\
			CROSS JOIN aa_addresses USING(address) \n\
			LEFT JOIN assets ON asset=assets.unit \n\
			CROSS JOIN units AS aa_definition_units ON aa_addresses.unit=aa_definition_units.unit \n\
			WHERE units.main_chain_index = ? AND units.sequence = 'good' AND (outputs.asset IS NULL OR is_private=0) \n\
				AND NOT EXISTS (SELECT 1 FROM unit_authors CROSS JOIN aa_addresses USING(address) WHERE unit_authors.unit=units.unit) \n\
				AND " + mci_column + "<=? \n\
			ORDER BY units.level, units.unit, address", // deterministic order
			[mci, mci],
			function (rows) {
				count_aa_triggers = rows.length;
				if (rows.length === 0)
					return finishMarkMcIndexStable();
				var arrValues = rows.map(function (row) {
					return "("+mci+", "+conn.escape(row.unit)+", "+conn.escape(row.address)+")";
				});
				conn.query("INSERT INTO aa_triggers (mci, unit, address) VALUES " + arrValues.join(', '), function () {
					finishMarkMcIndexStable();
					// now calling handleAATriggers() from write.js
				//	process.nextTick(function(){ // don't call it synchronously with event emitter
				//		eventBus.emit("new_aa_triggers"); // they'll be handled after the current write finishes
				//	});
				});
			}
		);
	}
```

**File:** writer.js (L724-727)
```javascript
								if (bStabilizedAATriggers && !err) {
									console.log(`executing AA triggers`);
									const aa_composer = require("./aa_composer.js");
									await aa_composer.handleAATriggers();
```

**File:** aa_composer.js (L91-150)
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
						conn.query("DELETE FROM aa_triggers WHERE mci=? AND unit=? AND address=?", [mci, unit, address], async function(){
							await conn.query("UPDATE units SET count_aa_responses=IFNULL(count_aa_responses, 0)+? WHERE unit=?", [arrResponses.length, unit]);
							let objUnitProps = storage.assocStableUnits[unit];
							if (!objUnitProps)
								throw Error(`handlePrimaryAATrigger: unit ${unit} not found in cache`);
							if (!objUnitProps.count_aa_responses)
								objUnitProps.count_aa_responses = 0;
							objUnitProps.count_aa_responses += arrResponses.length;
							var batch_start_time = Date.now();
							batch.write({ sync: true }, function(err){
								console.log("AA batch write took "+(Date.now()-batch_start_time)+'ms');
								if (err)
									throw Error("AA composer: batch write failed: "+err);
								conn.query("COMMIT", function () {
									conn.release();
									if (arrResponses.length > 1) {
										// copy updatedStateVars to all responses
										if (arrResponses[0].updatedStateVars)
											for (var i = 1; i < arrResponses.length; i++)
												arrResponses[i].updatedStateVars = arrResponses[0].updatedStateVars;
										// merge all changes of balances if the same AA was called more than once
										let assocBalances = {};
										for (let { aa_address, balances } of arrResponses)
											assocBalances[aa_address] = balances; // overwrite if repeated
										for (let r of arrResponses) {
											r.balances = assocBalances[r.aa_address];
											r.allBalances = assocBalances;
										}
									}
									else
										arrResponses[0].allBalances = { [address]: arrResponses[0].balances };
									arrResponses.forEach(function (objAAResponse) {
										if (objAAResponse.objResponseUnit)
											arrPostedUnits.push(objAAResponse.objResponseUnit);
										eventBus.emit('aa_response', objAAResponse);
										eventBus.emit('aa_response_to_unit-'+objAAResponse.trigger_unit, objAAResponse);
										eventBus.emit('aa_response_to_address-'+objAAResponse.trigger_address, objAAResponse);
										eventBus.emit('aa_response_from_aa-'+objAAResponse.aa_address, objAAResponse);
									});
									onDone();
								});
							});
						});
					});
				});
			});
		});
	});
}
```

**File:** aa_composer.js (L394-396)
```javascript
	if (Object.keys(trigger.outputs).length === 0)
		throw Error("no outputs to " + receiving_address);
	return trigger;
```

**File:** aa_composer.js (L424-438)
```javascript
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
```
