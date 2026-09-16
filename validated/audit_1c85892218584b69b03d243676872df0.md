## Title
Node-crashing uncaught exception via a `definition template` reference whose target becomes non-serial after use — Address Definitions / Authentifiers - (File: definition.js)

### Summary
`validateAuthentifiers()` in `definition.js` evaluates an address's definition tree to check signatures. When the tree contains a `['definition template', [unit, params]]` node, it fetches the referenced `definition_template` message with a query that requires `sequence='good' AND is_stable=1`, and assumes exactly one row will always be returned. If that assumption is violated, the code path does not return a normal validation error — it unconditionally `throw`s, which is not caught anywhere up the async call chain and is caught only by the global `process.on('uncaughtException')` handler in `network.js`, which deliberately re-throws to crash the whole node process.

### Finding Description
In `definition.js`, the *structural* validation of an address definition (`validateDefinition` → case `'definition template'`) safely handles a missing/duplicate template by calling the error callback: [1](#0-0) 

But the corresponding *authentication-time* evaluation (`validateAuthentifiers` → case `'definition template'`), which runs later whenever any unit spends from/authenticates as that address, uses the identical query filtered on `sequence='good' AND is_stable=1` yet throws an uncaught `Error` instead of returning a callback error if the row count isn't exactly 1: [2](#0-1) 

The `sequence` of the referenced template-carrying unit is not immutable: it starts as `'good'` while unstable and can be finalized to `'final-bad'` once the DAG stabilizes and a conflicting (double-spend) unit wins, as done in `markMcIndexStable`'s non-serial handling: [3](#0-2) 

Consequently, an address whose definition was accepted while the template unit was still `sequence='good'` can later have that template unit resolve to `final-bad`. Any subsequent unit that needs to authenticate against that address (e.g., spending its outputs) will re-run `validateAuthentifiers`, the template query will return 0 rows, and the process will `throw Error("not 1 template")` deep inside an async `conn.query` callback with no surrounding try/catch. This propagates as a Node.js `uncaughtException`, and the handler explicitly crashes the process: [4](#0-3) 

This is reached directly from `handlePostedJoint` → `handleJoint` → `validation.validate` → `validateAuthors` → `validateAuthentifiers`, i.e. from an ordinary unit posted by any unprivileged user (light client `post_joint` or full-node gossip), fully matching the CVE's "network access... crash of the server" bug class but with a stronger, deterministic full-process crash instead of a database hang.

### Impact Explanation
Triggering this throws an uncaught exception that crashes the entire hub/full node process (`process.on('uncaughtException')` intentionally re-throws "to avoid ending up in an inconsistent state"). Because the trigger condition (an address definition referencing a template unit, later made non-serial) is deterministic and attacker-controlled, an attacker can reliably and repeatedly crash any full node/hub that processes the resulting spending unit, halting that node's ability to validate/confirm further units — a network-wide availability impact matching "network unable to confirm new units."

### Likelihood Explanation
The attacker fully controls all the pieces needed:
1. Create an address whose definition uses `['definition template', [template_unit, params]]`.
2. Post the `template_unit` (own unit) and immediately post a conflicting double-spend of the same inputs so the template unit is guaranteed to lose the double-spend race and become `sequence='final-bad'` once stable.
3. Once stabilized, post (or have anyone post) a unit that requires authenticating the address from step 1.

All actions are available to an ordinary, unprivileged unit poster; no special network position or privileged role is required, making this reliably repeatable.

### Recommendation
In `validateAuthentifiers`'s `'definition template'` case (`definition.js` ~line 810), replace the `throw Error("not 1 template")` with a graceful authentication failure (`return cb2(false)` or an equivalent controlled rejection), mirroring how `validateDefinition`'s structural check already handles the 0/duplicate-row case via `cb(...)` instead of throwing. More generally, audit other `throw Error(...)` calls inside async DB-query callbacks that are reachable from unit validation/authentication paths (as opposed to internal invariant-only code) and convert attacker-reachable ones into normal validation-error returns.

### Proof of Concept
1. Author address `A` with a definition `['definition template', [T, {}]]` where `T` is a unit you control that carries a `definition_template` message.
2. Post unit `T` and, before it stabilizes, post a conflicting unit `T'` spending the same input(s), engineered to make `T` lose the double-spend and become `sequence='final-bad'` when the DAG stabilizes.
3. After stabilization, post any unit spending an output belonging to address `A` (or otherwise triggering authentication of `A`). During `validateAuthentifiers`, the `definition_template` lookup filtered by `sequence='good'` returns 0 rows, hitting `throw Error("not 1 template")` in `definition.js` line 812, which is uncaught and crashes the processing node via the global `uncaughtException` handler in `network.js`.

### Citations

**File:** definition.js (L321-328)
```javascript
				conn.query(
					"SELECT payload FROM messages JOIN units USING(unit) \n\
					WHERE unit=? AND app='definition_template' AND main_chain_index<=? AND +sequence='good' AND is_stable=1",
					[unit, objValidationState.last_ball_mci],
					function(rows){
						if (rows.length !== 1)
							return cb("template not found or too many");
						var template = rows[0].payload;
```

**File:** definition.js (L802-819)
```javascript
			case 'definition template':
				// ['definition template', ['unit', {param1: 'value1'}]]
				var unit = args[0];
				var params = args[1];
				conn.query(
					"SELECT payload FROM messages JOIN units USING(unit) \n\
					WHERE unit=? AND app='definition_template' AND main_chain_index<=? AND +sequence='good' AND is_stable=1",
					[unit, objValidationState.last_ball_mci],
					function(rows){
						if (rows.length !== 1)
							throw Error("not 1 template");
						var template = rows[0].payload;
						var arrTemplate = JSON.parse(template);
						var arrFilledTemplate = replaceInTemplate(arrTemplate, params);
						evaluate(arrFilledTemplate, path, cb2);
					}
				);
				break;
```

**File:** main_chain.js (L1318-1351)
```javascript
	function handleNonserialUnits(){
	//	console.log('handleNonserialUnits')
		conn.query(
			"SELECT * FROM units WHERE main_chain_index=? AND sequence!='good' ORDER BY unit", [mci], 
			function(rows){
				var arrFinalBadUnits = [];
				async.eachSeries(
					rows,
					function(row, cb){
						if (row.sequence === 'final-bad'){
							arrFinalBadUnits.push(row.unit);
							return row.content_hash ? cb() : setContentHash(row.unit, cb);
						}
						// temp-bad
						if (row.content_hash)
							throw Error("temp-bad and with content_hash?");
						findStableConflictingUnits(row, function(arrConflictingUnits){
							var sequence = (arrConflictingUnits.length > 0) ? 'final-bad' : 'good';
							console.log("unit "+row.unit+" has competitors "+arrConflictingUnits+", it becomes "+sequence);
							conn.query("UPDATE units SET sequence=? WHERE unit=?", [sequence, row.unit], function(){
								if (sequence === 'good')
									conn.query("UPDATE inputs SET is_unique=1 WHERE unit=?", [row.unit], function(){
										storage.assocStableUnits[row.unit].sequence = 'good';
										cb();
									});
								else{
									arrFinalBadUnits.push(row.unit);
									// treat this unit as a non-existent competitor from now on
									conn.query("UPDATE inputs SET is_unique=NULL WHERE unit=?", [row.unit], function(){
										setContentHash(row.unit, cb);
									});
								}
							});
						});
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
