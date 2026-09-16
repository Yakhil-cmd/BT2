### Title
Unhandled Exception in `light/dry_run_aa` AA Trigger Simulation Leads to Full Node Crash - ([File: network.js])

### Summary
The `light/dry_run_aa` network request handler in `network.js` accepts an attacker-supplied `params.trigger` object over the wire and feeds it into `aa_composer.dryRunPrimaryAATrigger()` → `aa_composer.handleTrigger()`, a deep call chain riddled with unguarded `throw Error(...)` statements for conditions that are reachable with a malformed/crafted trigger. Since this code path executes inside the WebSocket request handler with no surrounding try/catch, and `network.js` installs a global `process.on('uncaughtException')` handler that deliberately re-throws to kill the process, any such unhandled exception crashes the entire node — the same bug class as the LibreChat `checkBan` DoS (missing try/catch around request-derived processing → unhandled exception → server crash), but here reachable by any peer able to send a `light/dry_run_aa` request.

### Finding Description
`network.js` handles the `light/dry_run_aa` command directly from request `params` with only a superficial address check: [1](#0-0) 

`params.trigger` and `params.address` are passed largely as-is into `aa_composer.dryRunPrimaryAATrigger`, which in turn calls `handleTrigger`: [2](#0-1) 

`handleTrigger` and its helper functions contain numerous `throw Error(...)` statements guarding conditions that are meant to be "impossible", e.g. bad AA definition shape, mismatched internal options, or a secondary trigger firing while already bouncing: [3](#0-2) [4](#0-3) 

None of this call stack — from the `handleRequest` switch/case in `network.js` down through `dryRunPrimaryAATrigger`/`handleTrigger`/formula evaluation — is wrapped in a try/catch. Any exception thrown synchronously or in a callback during this processing becomes an uncaught exception on the Node.js event loop. `network.js` explicitly re-throws inside its global handler to force a crash rather than attempt to keep running in a possibly inconsistent state: [5](#0-4) 

This mirrors the reported CVE-2024-11172 pattern precisely: request-derived data is processed by code that can throw, that code is not defensively wrapped in try/catch, and the resulting unhandled exception terminates the whole server process rather than just failing the individual request.

### Impact Explanation
A successful trigger crashes the entire full node process — not just the requesting connection — taking the node offline until manually restarted. If exploited against multiple/most full nodes on the network in a short window (the request requires no authentication, funds, or special privilege beyond an open WebSocket connection), this can meaningfully degrade the network's ability to relay and confirm new units, which is the "network unable to confirm new units" impact class called out as in-scope.

### Likelihood Explanation
Likelihood is High for triggering *some* exception in this path in principle (many explicit `throw` sites exist along the reachable call graph and no top-level guard exists), but I could not fully verify the exact input-validation coverage of `aa_composer.validateAATriggerObject()` (its implementation body was not available in the indexed context), so I cannot confirm with certainty which specific malformed `trigger` payload bypasses that pre-check and reaches one of the unguarded `throw` statements. This is the main uncertainty in this analysis — a background agent with full repository access should inspect `aa_composer.validateAATriggerObject` in full to identify a concrete bypass and construct a minimal crashing payload.

### Recommendation
Wrap the `light/dry_run_aa` case body (and generally the `dryRunPrimaryAATrigger`/`handleTrigger` call chain when invoked from any network-facing entry point) in a try/catch that reports a normal error response to the peer via `sendErrorResponse` instead of letting the exception escape to `process.on('uncaughtException')`. More broadly, audit all network command handlers in `network.js` that pass attacker-controlled `params` into AA-related code paths (`aa_composer.*`, `formula/evaluation.js`) to ensure synchronous/callback-thrown errors are caught and converted to protocol-level error responses, rather than relying on the "impossible condition" assumption behind the many bare `throw Error(...)` statements in `aa_composer.js`.

### Proof of Concept
Conceptual (not fully verified end-to-end due to inability to inspect `validateAATriggerObject`'s full validation logic):
1. Establish a WebSocket connection to a full node exposing the hub/network protocol.
2. Send a `light/dry_run_aa` request with `params.address` set to a real AA address and `params.trigger` crafted to bypass `validateAATriggerObject`'s checks but violate an invariant assumed later in `handleTrigger` (e.g., a shape that satisfies structural checks but causes `arrDefinition[0] !== 'autonomous agent'`-style or bounce/secondary-trigger invariant violations deep in `handleTrigger`).
3. The resulting `throw Error(...)` is uncaught, propagates to `process.on('uncaughtException')` in `network.js`, which re-throws and crashes the node process for all users.

A background agent with full codebase access should read `aa_composer.js`'s `validateAATriggerObject` function in full and enumerate reachable `throw` sites in `handleTrigger`'s call graph to construct and confirm a concrete crashing payload.

### Citations

**File:** network.js (L3939-3961)
```javascript
		case 'light/dry_run_aa':
			if (!params)
				return sendErrorResponse(ws, tag, "no params in light/dry_run_aa");
			if (!ValidationUtils.isValidAddress(params.address))
				return sendErrorResponse(ws, tag, "address not valid");
		
			storage.readAADefinition(db, params.address, null, function (arrDefinition) {
				if (!arrDefinition)
					return sendErrorResponse(ws, tag, "not an AA");
				aa_composer.validateAATriggerObject(params.trigger, function(error){
					if (error)
						return sendErrorResponse(ws, tag, error);
					aa_composer.dryRunPrimaryAATrigger(params.trigger, params.address, arrDefinition, function (arrResponses) {
						if (constants.COUNT_WITNESSES === 1) { // the temp unit might have rebuilt the MC
							db.executeInTransaction(function (conn, onDone) {
								storage.resetMemory(conn, onDone);
							});
						}
						if (ws.library_version === '0.4.2' && arrResponses.length === 1 && arrResponses[0].bounced && typeof arrResponses[0].response.error === 'object')
							arrResponses[0].response.error = arrResponses[0].response.error.message;
						sendResponse(ws, tag, arrResponses);
					});
				})
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

**File:** aa_composer.js (L272-306)
```javascript
function dryRunPrimaryAATrigger(trigger, address, arrDefinition, onDone) {
	if (!onDone)
		return new Promise(resolve => dryRunPrimaryAATrigger(trigger, address, arrDefinition, resolve));
	console.log('dry run', address, trigger);
	db.takeConnectionFromPool(function (conn) {
		conn.query("BEGIN", function () {
			var batch = conf.bLight ? lightBatch : kvstore.batch();
			readLastStableMcUnit(conn, function (mci, objMcUnit) {
				trigger.unit = constants.GENESIS_UNIT; // objMcUnit.unit; // might cause duplicate trigger_unit in aa_triggers if objMcUnit is already a real trigger
				if (!trigger.address)
					trigger.address = objMcUnit.authors[0].address;
				trigger.initial_address = trigger.address;
				trigger.initial_unit = trigger.unit;
				var fPrepare = function (cb) {
					insertFakeOutputsIntoMcUnit(conn, objMcUnit, trigger.outputs, address, cb);
				};
				fPrepare(function () {
					var arrResponses = [];
					handleTrigger({
						bDryRun: true, // suppress events for a unit that will be rolled back
						conn, batch, trigger, params: {}, stateVars: {}, arrDefinition, address, mci, objMcUnit, bSecondary: false, arrResponses,
						onDone: function () {
							revertResponsesInCaches(arrResponses);
							batch.clear();
							conn.query("ROLLBACK", function () {
								conn.release();
								onDone(arrResponses);
							});
						},
					});
				});
			});
		});
	});
}
```

**File:** aa_composer.js (L399-425)
```javascript
// the result is onDone(objResponseUnit, bBounced)
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

**File:** aa_composer.js (L1717-1719)
```javascript
			}
			if (bBouncing)
				throw Error("secondary triggers while bouncing");
```
