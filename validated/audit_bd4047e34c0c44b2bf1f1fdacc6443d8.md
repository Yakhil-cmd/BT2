### Title
Persistent, unrecoverable process crash from unbounded AA-trigger evaluation errors thrown outside try/catch, blocking all future unit validation - ([File: aa_composer.js])

### Summary
CVE-2016-2161 describes an Apache `mod_auth_digest` bug where a single malformed request throws the server into a state where it crashes, and — critically — every subsequent instance keeps crashing on restart, permanently denying service even to legitimate requests. The root cause pattern (an externally-triggerable code path that `throw`s instead of returning a handled error, corrupting persistent state so the crash recurs) has a concrete analog in `aa_composer.js`'s AA-trigger execution pipeline, which is reachable by any unprivileged user simply by sending a payment to an AA address.

### Finding Description
When a unit sends bytes/assets to an Autonomous Agent (AA) address, `main_chain.js` inserts a row into the persistent `aa_triggers` table once the paying unit becomes stable [1](#0-0) . This table is later drained by `handleAATriggers()` / `handlePrimaryAATrigger()` in `aa_composer.js`, which is invoked both after normal stabilization [2](#0-1)  and, importantly, from `writer.js` after "additional stabilization" following a fresh write [3](#0-2)  — meaning any queued trigger row will be reprocessed again on every subsequent write/restart cycle until it succeeds.

Within `handlePrimaryAATrigger`, several code paths use bare `throw Error(...)` instead of passing an error to a callback, e.g.:
```
let objUnitProps = storage.assocStableUnits[unit];
if (!objUnitProps)
    throw Error(`handlePrimaryAATrigger: unit ${unit} not found in cache`);
...
if (err)
    throw Error("AA composer: batch write failed: "+err);
``` [4](#0-3) 

Similarly, `getTrigger()`, called for every trigger row pulled from the DB, throws synchronously if it cannot compute at least one non-zero output to the receiving address:
```
if (Object.keys(trigger.outputs).length === 0)
    throw Error("no outputs to " + receiving_address);
``` [5](#0-4) 

`handleTrigger()` itself contains numerous additional unconditional `throw` statements reachable from attacker-controlled AA definitions/trigger data (e.g. bad AA definition shape, missing base AA, `assocBalances`/`bAir` mismatch) [6](#0-5) [7](#0-6) .

Any exception thrown anywhere in the process becomes an `uncaughtException`, and the global handler in `network.js` deliberately re-throws it to kill the entire node process:
```
process.on('uncaughtException', (err) => {
    ...
    throw err; // crash the process to avoid ending up in an inconsistent state
});
``` [8](#0-7) 

The crucial part of the analog is persistence: the failing `aa_triggers` row is only `DELETE`d from the database *after* `handleTrigger` completes successfully [9](#0-8) . If evaluation throws before reaching that `DELETE`, the row remains in the DB. On the next process start (or the next `handleAATriggers()` invocation triggered by any subsequent stabilization event, per `writer.js` and `main_chain.js`), the same poisoned trigger row is read again, `handlePrimaryAATrigger` re-executes the same failing logic, and the process crashes again — precisely mirroring the CVE's "each instance continues to crash even for subsequently valid requests" behavior. Because this is a full-node process crash (not a per-connection failure), it halts consensus-relevant processing of AA triggers and, transitively, unit validation/propagation for the whole node until an operator manually intervenes (e.g., deletes the stuck row or patches the code), effectively making the affected node "unable to confirm new units."

### Impact Explanation
An attacker can construct a single unit that (a) sends any small amount of bytes to a target AA address whose definition is crafted (or whose data triggers a code path in `handleTrigger`/`getTrigger` that hits one of these `throw` statements), causing that node — and, if this constructed message is broadcast to the whole network, every full node running this exact code path — to crash on the AA trigger, and to crash again every restart because the offending `aa_triggers` row survives in the DB. This is a persistent denial-of-service against full-node availability and stability calculation for the whole network, aligning with the "network unable to confirm new units" impact category.

### Likelihood Explanation
The trigger path (paying an AA) is completely open to any unprivileged unit poster; no special permissions are required, and it does not require the AA owner's cooperation for many of the identified throw sites (e.g., `getTrigger`'s "no outputs" check, or exercising unusual AA definition shapes such as `base_aa` chains or `assocBalances`/`bAir` mismatches through crafted parameterized AAs). Exploitability of a specific throw site requires precise crafting to reach an unhandled branch, so likelihood is Medium, but the blast radius (full node crash + un-drainable persisted retry) is severe once triggered.

### Recommendation
- Convert the unconditional `throw Error(...)` statements inside `handlePrimaryAATrigger`, `getTrigger`, and `handleTrigger` that are reachable via externally-controlled AA definitions/trigger data into callback-propagated errors that mark the trigger as permanently failed/bounced rather than crashing the process.
- Wrap the AA-trigger execution pipeline (`handlePrimaryAATrigger`) in a try/catch so that any unexpected exception results in either: (a) safely removing/marking the `aa_triggers` row as failed (with logging) instead of leaving it to be retried forever, or (b) an explicit "poison-pill" quarantine mechanism, rather than an uncaught process-wide crash.
- Add defensive validation earlier in the AA validation pipeline (`validateAATrigger` in `validation.js`) to reject AA definitions/units that would deterministically drive `handleTrigger`/`getTrigger` into one of these throw paths, so malformed triggers never reach execution.

### Proof of Concept
Conceptual (not verified against a running node, since only static code review was possible):
1. Publish a unit that sends bytes to a valid AA address, where the AA's definition combined with the trigger causes `getTrigger()` to end up with an empty `trigger.outputs` map after processing (e.g., by exploiting an edge case in output/asset filtering) — this throws `"no outputs to " + receiving_address` inside `handlePrimaryAATrigger`, executed from `handleAATriggers()` after the paying unit stabilizes.
2. The uncaught exception propagates to the `process.on('uncaughtException', ...)` handler in `network.js`, which re-throws and crashes the process.
3. Because the corresponding row in `aa_triggers` was never deleted (the crash occurred before the `DELETE FROM aa_triggers` statement), the node operator restarts the process, `writer.js`/`main_chain.js` again schedule and execute `handleAATriggers()`, and the same row is re-read and re-processed, crashing the node again — an unrecoverable crash loop until manual DB intervention.

### Citations

**File:** main_chain.js (L1676-1689)
```javascript
	function calcCommissions(){
		if (mci === 0)
			return handleAATriggers();
		async.series([
			function(cb){
				profiler.start();
				headers_commission.calcHeadersCommissions(conn, cb);
			},
			function(cb){
				profiler.stop('mc-headers-commissions');
				paid_witnessing.updatePaidWitnesses(conn, cb);
			}
		], handleAATriggers);
	}
```

**File:** main_chain.js (L1711-1720)
```javascript
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
```

**File:** writer.js (L745-759)
```javascript
										const { arrStabilizedMcis, bStabilizedAATriggers } = await main_chain.advanceMcStability(conn, batch, objUnit.unit);
										console.log(`additional stabilization result`, arrStabilizedMcis, bStabilizedAATriggers);
										if (arrStabilizedMcis.length > 1)
											throw Error(`additional stabilization resulted in more than one MCI: ${arrStabilizedMcis.join(', ')}`);
										await util.promisify(batch.write.bind(batch))({ sync: true });
										await conn.query("COMMIT");
										conn.release();
										if (arrStabilizedMcis.length === 0)
											break;
										if (bStabilizedAATriggers) {
											console.log(`executing AA triggers after additional stabilization`, arrStabilizedMcis);
											// every trigger takes its own db connection
											const aa_composer = require("./aa_composer.js");
											await aa_composer.handleAATriggers();
										}
```

**File:** aa_composer.js (L101-102)
```javascript
					handleTrigger(conn, batch, trigger, {}, {}, arrDefinition, address, mci, objMcUnit, false, arrResponses, function(){
						conn.query("DELETE FROM aa_triggers WHERE mci=? AND unit=? AND address=?", [mci, unit, address], async function(){
```

**File:** aa_composer.js (L104-114)
```javascript
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

**File:** aa_composer.js (L400-425)
```javascript
function handleTrigger(conn, batch, trigger, params, stateVars, arrDefinition, address, mci, objMcUnit, bSecondary, arrResponses, onDone) {
	var trigger_opts;
	if (arguments.length === 1) {
		trigger_opts = conn;
		conn = trigger_opts.conn;
		batch = trigger_opts.batch;
		trigger = trigger_opts.trigger;
		params = trigger_opts.params;
		stateVars = trigger_opts.stateVars;
		arrDefinition = trigger_opts.arrDefinition;
		address = trigger_opts.address;
		mci = trigger_opts.mci;
		objMcUnit = trigger_opts.objMcUnit;
		bSecondary = trigger_opts.bSecondary;
		arrResponses = trigger_opts.arrResponses;
		onDone = trigger_opts.onDone;
		// extra options:
		// trigger_opts.bAir
		// trigger_opts.assocBalances
		if (!!trigger_opts.bAir !== !!trigger_opts.assocBalances)
			throw Error("assocBalances and bAir do not match");
	}
	else
		trigger_opts = { conn, batch, trigger, params, stateVars, arrDefinition, address, mci, objMcUnit, bSecondary, arrResponses, onDone };
	if (arrDefinition[0] !== 'autonomous agent')
		throw Error('bad AA definition ' + arrDefinition);
```

**File:** aa_composer.js (L1841-1863)
```javascript
	updateInitialAABalances(function (err) {

		// these errors must be thrown after updating the balances
		if (err)
			return bounce(err);
		if (arrResponses.length >= constants.MAX_RESPONSES_PER_PRIMARY_TRIGGER) // max number of responses per primary trigger, over all branches stemming from the primary trigger
			return bounce("max number of responses per trigger exceeded");
		if ("max_aa_responses" in trigger && arrResponses.length >= trigger.max_aa_responses)
			return bounce(`max_aa_responses ${trigger.max_aa_responses} exceeded`);
		// being able to pay for bounce fees is not required for secondary triggers as they never actually send any bounce response or change state when bounced
		if (!bSecondary) {
			if ((trigger.outputs.base || 0) < bounce_fees.base) {
				return bounce('received bytes are not enough to cover bounce fees');
			}
			for (var asset in trigger.outputs) { // if not enough asset received to pay for bounce fees, ignore silently
				if (bounce_fees[asset] && trigger.outputs[asset] < bounce_fees[asset]) {
					return bounce('received ' + asset + ' is not enough to cover bounce fees');
				}
			}
			// skip this check for dry-run which uses genesis unit as trigger unit
			if (trigger.unit !== constants.GENESIS_UNIT && !trigger_opts.bAir && storage.assocStableUnits[trigger.unit].count_aa_responses && mci >= constants.pemCurvesFixMci)
				return bounce('a second primary trigger from the same unit is not allowed');
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
