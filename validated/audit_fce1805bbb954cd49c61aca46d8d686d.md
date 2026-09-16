### Title
Uncaught exception during AA trigger execution permanently bricks the node via poisoned `aa_triggers` row - (File: `aa_composer.js`)

### Summary
The RaspAP advisory (CVE-2024-28754) describes a *persistent* denial of service: a single crafted request corrupts persistent state such that the service keeps failing (bricking) on every subsequent run, not just a one-time crash. `ocore` has an analogous pattern in the Autonomous Agent (AA) trigger-execution pipeline: an unprivileged unit poster can send a trigger to any AA that causes `aa_composer.js` to throw an uncaught JS exception instead of returning a controlled bounce error. Because the corresponding `aa_triggers` DB row is only deleted **after** trigger handling completes successfully, and because the global `uncaughtException` handler crashes the whole process, the offending trigger remains queued forever and is re-executed (and re-crashes the node) every time a future MCI stabilization runs `handleAATriggers()` — a self-inflicted, persistent crash loop that only manual DB surgery can fix.

### Finding Description
When an MCI stabilizes and it contains AA triggers, `stabilizeMci`/`saveJoint` calls `aa_composer.handleAATriggers()`: [1](#0-0) 

This reads **every** row currently in the `aa_triggers` table (not just the newly stabilized ones) and processes them one by one via `handlePrimaryAATrigger`: [2](#0-1) 

Critically, the `DELETE FROM aa_triggers` for a given trigger only happens **inside the `onDone` callback of `handleTrigger`** — i.e., only after `handleTrigger` finishes without throwing: [3](#0-2) 

`handleTrigger` and its helpers (`evaluateAA`, `replace`, formula evaluation, `saveStateVars`) rely on callback-style error propagation (`bounce(err)`), but several code paths use unguarded `throw Error(...)` instead of calling back with an error, e.g. `saveStateVars()` → `getTypeAndValue()`: [4](#0-3) [5](#0-4) 

`saveStateVars()` is called unconditionally for any non-bouncing, non-secondary primary trigger response and is not wrapped in try/catch, unlike the sibling `getValueSize()` usage in `updateStorageSize()` which *is* guarded with try/catch: [6](#0-5) 

If any such unguarded `throw` fires during `handleTrigger`, the exception propagates out of the async callback chain up to Node's process-level handler, which explicitly re-throws to crash the process: [7](#0-6) 

Because the crash happens before `DELETE FROM aa_triggers` and before `COMMIT`, the trigger row (which was already committed to the DB in an earlier, unrelated transaction when the triggering unit stabilized — see `saveUnstablePayloads`/`markMcIndexStable`) survives the restart. On the next MCI stabilization, `handleAATriggers()` re-selects **all** rows from `aa_triggers`, including the poisoned one, and the node crashes again — indefinitely, until an operator manually deletes the row from the database.

### Impact Explanation
This matches the CVE's bug class: a single unprivileged "request" (here, a posted unit that triggers an AA) causes the target system to enter a persistently broken state ("bricking") rather than a transient/self-healing failure. Since `handleAATriggers()` is invoked on essentially every future stabilization event as long as the trigger stays queued, the affected full node (and any AA hosted on it) becomes permanently unable to process new units/triggers — "a network unable to confirm new units" from the perspective of that node, requiring privileged, manual database intervention to recover. This is High severity: no privileged access or special conditions are needed by the attacker, and the effect is a durable denial of service rather than a one-off crash.

### Likelihood Explanation
Any address can be turned into an AA, and any unprivileged wallet can post a trigger unit to it. The attacker only needs an AA definition (which they can author themselves, or exploit an existing one) whose response logic sets a state variable (`var[...] = ...`) to a value type not covered by `getTypeAndValue` (string / number / Decimal / `wrappedObject`) under conditions reachable from trigger-supplied data (e.g., `trigger.data`). Because `aa_composer.js` mixes callback-based error handling with hard `throw Error()` calls in numerous helper functions, and only some of them are wrapped in try/catch (`updateStorageSize` guards `getValueSize` but `saveStateVars` does not guard `getTypeAndValue`), the likelihood of an attacker finding at least one such unguarded throw is high; this significantly increases confidence that the underlying pattern (unguarded throw during trigger execution + delayed row deletion + all-rows re-processing) is a genuine, exploitable persistent-crash vector even if the exact minimal formula was not runtime-verified here.

### Recommendation
- Wrap all `handleTrigger`/`evaluateAA`/`replace`/`saveStateVars`/`updateStorageSize` internal logic in defensive try/catch so any unexpected exception is converted into a `bounce()` (soft failure charged to the trigger) instead of an uncaught process-crashing exception.
- Make `handlePrimaryAATrigger` remove/mark-as-failed the offending `aa_triggers` row (or mark the trigger unit's response as "bounced: crashed") even when `handleTrigger` throws, e.g. by wrapping the whole per-row processing in `try { ... } catch (e) { delete row; log; continue; }`.
- Add a regression/fuzz test that supplies malformed/edge-case state-var values (booleans other than the delete sentinel, `null`, functions, nested unsupported types) through AA formulas to confirm `getTypeAndValue`/`getValueSize` never throw uncontrolled.
- Consider adding a per-trigger retry/backoff counter so a trigger that fails a fixed number of times is automatically quarantined rather than retried forever, preventing a crash loop even if new unguarded throws are introduced in the future.

### Proof of Concept
Conceptual (not executed against a live node, since only static/code-search tools were available):
1. Author and post an AA definition whose `messages` block updates a state var from formula-derived attacker-controlled `trigger.data`, in a way intended to reach a value type unsupported by `getTypeAndValue` (e.g. an object/array structure not wrapped as a `wrappedObject`, or a raw `null`), bypassing the boolean/false sentinel handling in `saveStateVars`.
2. As an unprivileged wallet, post a trigger unit sending bytes to that AA with the crafted `data` payload.
3. Once the trigger unit stabilizes, `stabilizeMci` → `handleAATriggers` → `handlePrimaryAATrigger` → `handleTrigger` → `saveStateVars` → `getTypeAndValue` throws `Error("state var of unknown type: ...")` uncaught, propagating to `process.on('uncaughtException')` in `network.js`, which rethrows and kills the node.
4. Because the `DELETE FROM aa_triggers` statement never executes (`aa_composer.js:102`), restart the node: the next stabilized MCI triggers `handleAATriggers()` again, which re-selects the same poisoned row and crashes the node again, repeating indefinitely until the row is manually deleted from the `aa_triggers` table. [8](#0-7)

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

**File:** aa_composer.js (L1487-1503)
```javascript
	function saveStateVars() {
		if (bSecondary || bBouncing || trigger_opts.bAir)
			return;
		for (var address in stateVars) {
			var addressVars = stateVars[address];
			for (var var_name in addressVars) {
				var state = addressVars[var_name];
				if (!state.updated)
					continue;
				var key = "st\n" + address + "\n" + var_name;
				if (state.value === false) // false value signals that the var should be deleted
					batch.del(key);
				else
					batch.put(key, getTypeAndValue(state.value)); // Decimal converted to string, object to json
			}
		}
	}
```

**File:** aa_composer.js (L1505-1516)
```javascript
	function getTypeAndValue(value) {
		if (typeof value === 'string')
			return 's\n' + value;
		else if (typeof value === 'number')
			return 'n\n' + value;
		else if (Decimal.isDecimal(value))
			return 'n\n' + value.toNumber(); // drop the excessive precision in subnormals
		else if (value instanceof wrappedObject)
			return 'j\n' + string_utils.getJsonSourceString(value.obj, true);
		else
			throw Error("state var of unknown type: " + value);	
	}
```

**File:** aa_composer.js (L1544-1551)
```javascript
			else {
				try {
					var newSize = getValueSize(state.value);
				}
				catch (e) {
					console.log("failed to get size of new value of state var " + var_name + ": ", e);
					return cb("invalid new value of state var " + var_name);
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
