The strongest reachable analog to this "gas griefing that permanently freezes a processing queue" bug class is not a literal external call with unbounded gas (ocore/Obyte has no low-level value-transfer calls), but a structurally identical pattern: a **sequential, deterministic queue of pending work items (`aa_triggers`) that is drained item-by-item, where a single item that triggers an uncaught exception during processing is never removed from the queue and will deterministically crash every node that tries to process it — forever.**

### Title
Uncaught exceptions during AA trigger processing permanently stall the `aa_triggers` queue and crash all nodes reprocessing it - ([File: aa_composer.js])

### Summary
`handleAATriggers()` selects all pending rows from the `aa_triggers` table and processes them one-by-one with `async.eachSeries`, exactly like the reported `VUSD.processWithdrawals()` loop processes a `withdrawals` array sequentially from a `start` pointer. The row for a trigger is deleted from `aa_triggers` **only after** `handleTrigger()` finishes and calls back into `handlePrimaryAATrigger()`'s completion logic. If anything inside the trigger-processing call chain throws an uncaught `Error` (rather than calling `bounce()`/`cb(err)`), the deletion never happens, the DB transaction context is left inconsistent, and the process crashes. [1](#0-0) [2](#0-1) 

### Finding Description
`aa_composer.js`'s `handlePrimaryAATrigger()` only issues `DELETE FROM aa_triggers WHERE mci=? AND unit=? AND address=?` inside the `onDone` callback passed to `handleTrigger()`: [3](#0-2) 

`handleTrigger()` and the functions it calls (`sendUnit`, `validateAndSaveUnit`, `pickParents`, `getTrigger`, etc.) contain numerous `throw Error(...)` statements for conditions assumed to be "impossible", executed deep inside nested asynchronous callbacks with no surrounding `try/catch`. One concrete example is in `validateAndSaveUnit`, which throws if the final `writer.saveJoint()` call — performed only after the AA-generated response unit is fully composed — returns any error: [4](#0-3) 

Because JavaScript exceptions thrown inside async callback chains (not returned via a callback/promise) cannot be caught by any caller, this propagates all the way up through `handleAATriggers`'s `async.eachSeries` and out of the mutex-protected write path. `network.js` installs a global handler that explicitly turns any uncaught exception into a hard process crash: [5](#0-4) 

Trigger processing is also **awaited** as part of main-chain stabilization (`stabilizeMci` / `markMcIndexStable` → `handleAATriggers()`), so this is on the critical path for advancing the DAG, not an isolated side effect: [6](#0-5) 

Since the offending `aa_triggers` row is never deleted (the crash happens before the `DELETE`/commit), every node that restarts and reprocesses main-chain stabilization from that point will re-select the same trigger, re-execute the same deterministic code path, and crash again — a permanent, self-perpetuating halt, exactly analogous to the withdrawal queue that can never advance past a malicious entry because the `start` pointer is never incremented.

### Impact Explanation
Any unprivileged user can post a trigger unit to an existing (or self-defined) AA. If the crafted trigger data drives the AA composer/writer through a code path that reaches one of these "impossible" throws (e.g., an edge case in commission/oversize-fee accounting, tps-fee interaction, or a race between the composer's pre-checks and `writer.saveJoint`'s independent validation), the resulting uncaught exception crashes the node. Because trigger processing is mandatory, deterministic, and required before subsequent main-chain indices can stabilize, **every full node in the network** that reaches this MCI will crash the same way on restart, halting the network's ability to confirm any further units — a permanent freeze until an out-of-band software fix and re-sync/skip is deployed. This satisfies the "network unable to confirm new units" impact class.

### Likelihood Explanation
Likelihood depends on finding a concrete input that reaches one of the many unguarded `throw Error(...)` statements in the AA execution path that isn't already excluded by `aa_validation.js`'s static AA-definition checks. Given the sheer number of "should never happen" throws inside `handleTrigger`/`sendUnit`/`validateAndSaveUnit` guarding conditions that depend on live chain state (balances, fees, storage size, tps fees) rather than purely static definition content, the attack surface for triggering one via a crafted but formally valid AA + trigger combination is realistic, though it requires careful selection of AA logic and timing (e.g., interacting with tps-fee spikes or oversize-fee edge cases) rather than being trivially reproducible on any input.

### Recommendation
- Wrap the entire per-trigger processing pipeline (`handleTrigger` → `sendUnit` → `validateAndSaveUnit`) so that any thrown error is caught and converted into a `bounce()` (soft failure charged to the trigger, and the `aa_triggers` row is still deleted) rather than an uncaught exception that crashes the process.
- Audit every `throw Error(...)` reachable from `handleTrigger`'s call graph and replace "should never happen" assertions that are actually reachable via untrusted trigger/AA content with graceful bounces.
- Ensure `aa_triggers` rows are removed (or marked as permanently failed with a capped retry) even when processing fails unexpectedly, so a single bad trigger cannot indefinitely block the deterministic trigger queue for the whole network.

### Proof of Concept
Not directly reproducible without deeper investigation into which specific runtime state (tps fee timing, oversize fee calculation, or asset issuance race) can be manipulated by an attacker to make `writer.saveJoint()` (called from `validateAndSaveUnit`) return an error after the AA composer's own pre-checks pass. The exploitability hinges on finding one concrete discrepancy between the AA composer's optimistic pre-validation and `writer.saveJoint`'s independent validation of the AA-emitted unit; the structural flaw (uncaught throw → process crash → un-deleted queue entry → repeated crash on every node) is demonstrated directly by the code paths cited above.

### Citations

**File:** aa_composer.js (L59-89)
```javascript
function handleAATriggers(onDone) {
	if (!onDone)
		return new Promise(resolve => handleAATriggers(resolve));
	mutex.lock(['aa_triggers'], function (unlock) {
		db.query(
			"SELECT aa_triggers.mci, aa_triggers.unit, address, definition \n\
			FROM aa_triggers \n\
			CROSS JOIN units USING(unit) \n\
			CROSS JOIN aa_addresses USING(address) \n\
			ORDER BY aa_triggers.mci, level, aa_triggers.unit, address",
			function (rows) {
				var arrPostedUnits = [];
				async.eachSeries(
					rows,
					function (row, cb) {
						console.log('handleAATriggers', row.unit, row.mci, row.address);
						var arrDefinition = JSON.parse(row.definition);
						handlePrimaryAATrigger(row.mci, row.unit, row.address, arrDefinition, arrPostedUnits, cb);
					},
					function () {
						arrPostedUnits.forEach(function (objUnit) {
							eventBus.emit('new_aa_unit', objUnit);
						});
						unlock();
						onDone();
					}
				);
			}
		);
	});
}
```

**File:** aa_composer.js (L91-116)
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
```

**File:** aa_composer.js (L1800-1836)
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

**File:** main_chain.js (L1263-1276)
```javascript
async function stabilizeMci(mci) {
	const conn = await db.takeConnectionFromPool();
	await conn.query("BEGIN");
	const batch = kvstore.batch();
	const count_aa_triggers = await markMcIndexStable(conn, batch, mci);
	await util.promisify(batch.write.bind(batch))({ sync: true });
	await conn.query("COMMIT");
	conn.release();
	if (count_aa_triggers > 0) {
		console.log(`executing ${count_aa_triggers} AA triggers after stabilizing MCI ${mci}`);
		// every trigger takes its own db connection
		const aa_composer = require("./aa_composer.js");
		await aa_composer.handleAATriggers();
	}
```
