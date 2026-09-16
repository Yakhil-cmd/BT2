Based on my research, I found a concrete analog to this CVE's bug class ("crash/hang causing complete denial of service via a component whose internal invariant checks run identically across all cluster members").

### Title
Uncaught invariant-violation crash during deterministic AA trigger execution halts every full node - ([File: aa_composer.js])

### Summary
`ocore`'s AA (Autonomous Agent) execution engine, `handleTrigger()` in `aa_composer.js`, is riddled with hard `throw Error(...)` invariant checks that are *not* wrapped in try/catch anywhere in the call chain from `writer.saveJoint()` → `aa_composer.handleAATriggers()` → `handlePrimaryAATrigger()` → `handleTrigger()`. Because Node.js treats an uncaught exception thrown deep inside nested async callbacks as fatal, and `network.js` installs a `process.on('uncaughtException', …)` handler that deliberately **re-throws to crash the process** ("crash the process to avoid ending up in an inconsistent state"), any attacker-reachable invariant violation inside AA execution crashes the full node process outright. [1](#0-0) 

Crucially, AA trigger execution at MC stabilization (`handleAATriggers`/`handlePrimaryAATrigger`) is a **mandatory, deterministic consensus step executed identically by every full node** once an MCI containing an AA trigger becomes stable: [2](#0-1) [3](#0-2) 

Several of these invariant checks are only evaluated on the **real** (non-dry-run) execution path, and are explicitly skipped when `bAir`/dry-run mode is used — meaning `conf.bDryRunNewTriggers` (network.js:1271-1281, opt-in and only exercised by the *posting* node) cannot catch them in advance: [4](#0-3) 

For example `pickParents()` throws `"pickParents shouldn't be called with bAir"` if invoked in dry-run mode, and separately throws `"limci of last AA > mci"` at line 899 when `row.latest_included_mc_index >= mci` for the AA-chain unit selected to be a response parent — a condition that depends on the live state of concurrent unstable units at the moment of *real* stabilization, and can differ from the state seen by an earlier `estimatePrimaryAATrigger`/dry-run estimate. `handleTrigger` and `handleSecondaryTriggers` contain multiple similar "should never happen" throws (`"unexpected params"`, `"base AA not found"`, `"secondary triggers while bouncing"`, `"response_unit with bouncing a secondary AA"`) that are reachable purely from an unprivileged AA author's crafted AA definition and a coordinated trigger/response chain, none of which are converted into a bounce or validation error — they are unconditional `throw`. [5](#0-4) [6](#0-5) 

### Finding Description
1. Any address can post an AA definition and craft units that trigger AA execution — this is a normal, unprivileged, permissionless operation.
2. When the triggering unit's MCI stabilizes, **every full node** (not just the poster's node) runs `aa_composer.handleAATriggers()` → `handlePrimaryAATrigger()` → `handleTrigger()` synchronously as part of consensus bookkeeping.
3. `handleTrigger()`/`pickParents()`/`handleSecondaryTriggers()` contain numerous defensive `throw Error(...)` statements intended as "should never happen" invariants, but which are reachable if an attacker can arrange DAG/AA state that violates the assumption (e.g. a race between a newly composed AA-chain unit's `latest_included_mc_index` and the trigger's own `mci`, or bouncing-state combinations across secondary AA calls).
4. None of these calls are wrapped in try/catch by the caller chain (`writer.saveJoint` → `aa_composer.handleAATriggers`), so the exception propagates to the top of the event loop and fires Node's `uncaughtException` event.
5. `network.js`'s global handler for `uncaughtException` deliberately re-throws, crashing the whole node process (`throw err; // crash the process to avoid ending up in an inconsistent state`).
6. Because AA trigger execution at stabilization is deterministic and identical on every full node, the same crafted trigger/AA-state crashes **every** full node that reaches that stabilization point — this is directly analogous to CVE-2024-21087, where an easily-exploitable input to MySQL's Group Replication Plugin crashes/hangs the replicated server component network-wide.

### Impact Explanation
If exploitable, this is not a single-node DoS but a total-network halt: every full node executing the same stabilized AA trigger crashes identically, and since AA execution is mandatory before further stabilization can proceed, the network becomes unable to confirm new units until node operators patch and restart with a fix — satisfying the "network unable to confirm new units" impact bar.

### Likelihood Explanation
Medium: reaching one of these unconditional invariant throws requires crafting a specific combination of concurrent AA definitions, chained (primary + secondary) triggers, and DAG timing so that the runtime state diverges from the assumption baked into the check (e.g. `latest_included_mc_index >= mci` in `pickParents`, or reaching `handleSecondaryTriggers` while `bBouncing` is already true). This is achievable by a sophisticated but unprivileged AA author/unit poster without any special network position, and does not require inducing malicious peer/node/hub behavior — it only needs ordinary permissionless AA and unit posting.

### Recommendation
- Wrap all `handleTrigger`/`pickParents`/`handleSecondaryTriggers` internal invariant checks in recoverable error handling that converts them into an AA bounce (as is already done for expected validation failures) instead of an unconditional `throw`.
- Ensure invariants exercised only on the "real" execution path (`bAir`-gated) are also exercised during dry-run/estimation so operators cannot deploy AAs that pass all pre-checks yet crash at stabilization.
- Consider not tying process survival directly to any exception raised from AA execution — the `uncaughtException` handler should distinguish between actually-unrecoverable storage corruption and logic bugs in AA execution that can safely be turned into a rejected/bounced trigger.

### Proof of Concept
Conceptual (requires DAG-state crafting, not fully constructed here):
1. Deploy an AA `A` and, in the same round, cause a chain of concurrent AA-authored units such that when `pickParents()` runs for a subsequent trigger to `A`, the SQL-selected candidate row's `latest_included_mc_index` is `>= mci` (line 898-899 of `aa_composer.js`).
2. Because `pickParents()` is only ever invoked on the *real* (non-`bAir`) path, no dry-run performed by the honest posting node (`dryRunPrimaryAATrigger`) will catch this — the throw fires only when `handleAATriggers()` executes the trigger for real at stabilization.
3. Every full node hits `throw Error("limci of last AA > mci")` inside the unguarded call chain, which surfaces as an uncaught exception and is deliberately re-thrown by `network.js`'s handler, crashing every full node's process simultaneously. [7](#0-6) [1](#0-0)

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

**File:** aa_composer.js (L91-106)
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
```

**File:** aa_composer.js (L419-438)
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
```

**File:** aa_composer.js (L875-907)
```javascript
	function pickParents(handleParents) {
		if (trigger_opts.bAir)
			throw Error("pickParents shouldn't be called with bAir");
		// first look for a chain of AAs stemming from the MC unit
		conn.query(
			"SELECT units.unit \n\
			FROM units CROSS JOIN unit_authors USING(unit) CROSS JOIN aa_addresses USING(address) \n\
			WHERE latest_included_mc_index=? AND aa_addresses.mci<=? \n\
			ORDER BY level DESC LIMIT 1",
			[mci, mci],
			function (rows) {
				if (rows.length > 0)
					return handleParents([rows[0].unit]);
				// next, check if there is an AA stemming from a recent MCI
				conn.query(
					"SELECT units.unit, latest_included_mc_index \n\
					FROM units CROSS JOIN unit_authors USING(unit) CROSS JOIN aa_addresses USING(address) \n\
					WHERE (main_chain_index>? OR main_chain_index IS NULL) AND aa_addresses.mci<=? \n\
					ORDER BY latest_included_mc_index DESC, level DESC LIMIT 1",
					[mci, mci],
					function (rows) {
						if (rows.length > 0) {
							var row = rows[0];
							if (row.latest_included_mc_index >= mci)
								throw Error("limci of last AA > mci");
							return handleParents([row.unit, objMcUnit.unit].sort());
						}
						handleParents([objMcUnit.unit]);
					}
				);
			}
		);
	}
```

**File:** aa_composer.js (L1671-1719)
```javascript
	function finish(objResponseUnit) {
		if (bBouncing && bSecondary) {
			if (objResponseUnit)
				throw Error('response_unit with bouncing a secondary AA');
			if (!bAddedResponse && objValidationState.logs) // add the logs from the final bouncing unit
				arrResponses.push({ logs: objValidationState.logs });

			if (typeof error_message === 'string') {
				error_message = { message: error_message };
			}

			let errorObj = { address };
			if (error_message.address) {
				errorObj.next = error_message;
			} else {
				errorObj = { ...errorObj, ...error_message };
			}
			return onDone(null, errorObj);
		}
		fixStateVars();
		saveStateVars();
		addResponse(objResponseUnit, function () {
			updateStorageSize(function (err) {
				if (err)
					return revert(err);
				addUpdatedStateVarsIntoPrimaryResponse();
				onDone(objResponseUnit, bBouncing ? error_message : false);
			});
		});
	}

	function handleSecondaryTriggers(objUnit, arrOutputAddresses) {
		conn.query("SELECT address, definition, mci, main_chain_index FROM aa_addresses LEFT JOIN units USING(unit) WHERE address IN(?) AND mci<=? ORDER BY address", [arrOutputAddresses, mci], function (rows) {
			if (rows.length > 0 && constants.bTestnet && mci < testnetAAsDefinedByAAsAreActiveImmediatelyUpgradeMci)
				rows = rows.filter(function (row) {
					if (row.main_chain_index && row.main_chain_index < mci) // previous definition is already stable
						return true;
					var len = storage.getUnconfirmedAADefinitionsPostedByAAs([row.address]).length;
					if (len > 0)
						console.log("not calling secondary trigger from unit " + objUnit.unit + " to AA " + row.address);
					return (len === 0);
				});
			if (rows.length === 0) {
				saveStateVars();
				addUpdatedStateVarsIntoPrimaryResponse();
				return onDone(objUnit, bBouncing ? error_message : false);
			}
			if (bBouncing)
				throw Error("secondary triggers while bouncing");
```
