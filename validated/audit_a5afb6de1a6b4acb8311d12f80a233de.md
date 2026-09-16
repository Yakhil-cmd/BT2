### Title
Uncaught Exception in Address "definition template" Authentifier Evaluation Crashes Node - (File: definition.js)

### Summary
`validateAuthentifiers()` in `definition.js` evaluates the `'definition template'` operator by querying the `messages` table for the referenced unit and asserting that exactly one matching `definition_template` row exists. If that assumption is violated, the code path throws a raw, uncaught `Error` instead of returning a graceful validation failure, and that throw escapes into an unhandled JS exception that the node's global handler is configured to convert into a full process crash.

### Finding Description
When any unit's author uses a "definition template" reference inside its address definition, every subsequent unit spending from (or otherwise authenticating with) that address is checked in `validateAuthentifiers()`. Inside its inner `evaluate()` function, the `'definition template'` case does: [1](#0-0) 
```
if (rows.length !== 1)
    throw Error("not 1 template");
```
This throw fires synchronously inside a `conn.query(...)` callback — i.e., inside the Node.js event loop, outside of any surrounding `try/catch`. Contrast this with the parallel logic used when the definition is *first* validated (`validateDefinition()`), which handles the exact same condition gracefully via a normal error callback instead of throwing: [2](#0-1) 

`validateAuthentifiers` is invoked for every unit whose author signs using a definition containing this operator, as part of the standard per-unit `validateAuthors` step called from the core `validate()` pipeline: [3](#0-2) 

Since the throw happens deep inside an async callback chain, it is not caught by `validate()`'s own limited `try/catch` (which only wraps the unit-hash calculation): [4](#0-3) 

It propagates all the way up as an uncaught exception. `network.js` installs a global handler that explicitly converts any uncaught exception into a full process crash: [5](#0-4) 

This is the same bug class as CVE-2020-2762: a database-engine query-processing condition that an attacker can influence causes the engine (here, every ocore full node/hub/wallet that validates the crafted unit) to hang or repeatedly crash — pure availability impact, no confidentiality/integrity loss.

### Impact Explanation
Any node (hub, full node, or light-serving node with a local DB) that validates a unit signed by an address whose definition contains a `'definition template'` reference will hit this code path. If the referenced template unit's matching-row condition (`main_chain_index<=last_ball_mci AND sequence='good' AND is_stable=1`, filtered by unit hash and `app='definition_template'`) ever evaluates to something other than exactly one row at authentifier-check time — even though it evaluated to exactly one row when the definition itself was originally validated — the process crashes via the `uncaughtException` handler. Because the crash is triggered purely by broadcasting/relaying the spending unit, an attacker can force this condition on every node in the network that processes the unit, producing a network-wide, repeatable denial of service (nodes crash and, if auto-restarted, can crash again on re-validating the same unit from disk/mempool).

### Likelihood Explanation
Reaching the `validateAuthentifiers` code path only requires posting/relaying an ordinary unit signed by an address defined with a `'definition template'` clause — this is fully reachable by an unprivileged unit poster and does not require special privileges, matching the report's "high privileged... via network access" analog (here, "privilege" is simply owning/controlling such an address, which any user can create). I was not able to fully verify, within the available indexed context and remaining iterations, the exact conditions under which the row count can differ between the initial `validateDefinition()` check and a later `validateAuthentifiers()` check (e.g., timing/catch-up edge cases, or whether a single unit can carry more than one `app='definition_template'` message affecting the row count). This means the precise reproduction trigger is not fully confirmed from static analysis alone, and should be verified with runtime/unit testing before treating this as fully proven; the root-cause code asymmetry (throw vs. graceful error for the identical invariant) is, however, clearly present and is inherently unsafe regardless of how easy it is to trigger the mismatch.

### Recommendation
Change the `'definition template'` branch in `validateAuthentifiers()`'s `evaluate()` (definition.js, case `'definition template'`) to handle `rows.length !== 1` the same way `validateDefinition()` does: return a normal validation failure (e.g., `cb2(false)` or a proper error) instead of `throw Error(...)`. Audit `definition.js` for any other `throw Error(...)` statements inside async DB-query callbacks reachable from unit/authentifier validation (e.g., `throw Error("more than 1 address definition")` at line 795) and convert them to callback-based errors so that attacker-influenced data can never produce a raw process-crashing exception during unit validation.

### Proof of Concept
1. Create address `A` whose spending definition includes `['definition template', [T, {...}]]`, where `T` is a unit that currently has exactly one `app='definition_template'` message, stable and with `sequence='good'` at the mci used for validating `A`'s definition. This passes `validateDefinition()`.
2. Post a new unit `U` authored/signed by `A` (a normal payment or any message), which is entirely within reach of any unprivileged unit poster.
3. When any node validates `U`, `validateAuthentifiers()` re-runs the same `'definition template'` lookup for `T` at `U`'s (possibly different) `last_ball_mci`/DB state. If that lookup returns anything other than exactly one row (row-count divergence from step 1), the node hits `throw Error("not 1 template")` inside the DB callback.
4. The exception is uncaught, hits `process.on('uncaughtException', ...)` in `network.js`, and crashes the node process on every peer that validates `U`. [6](#0-5) [5](#0-4)

### Citations

**File:** definition.js (L321-339)
```javascript
				conn.query(
					"SELECT payload FROM messages JOIN units USING(unit) \n\
					WHERE unit=? AND app='definition_template' AND main_chain_index<=? AND +sequence='good' AND is_stable=1",
					[unit, objValidationState.last_ball_mci],
					function(rows){
						if (rows.length !== 1)
							return cb("template not found or too many");
						var template = rows[0].payload;
						var arrTemplate = JSON.parse(template);
						try{
							var arrFilledTemplate = replaceInTemplate(arrTemplate, params);
							console.log(require('util').inspect(arrFilledTemplate, {depth: null}));
						}
						catch(e){
							if (e instanceof NoVarException)
								return cb(e.toString());
							else
								throw e;
						}
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

**File:** validation.js (L131-138)
```javascript
	try{
		// UnitError is linked to objUnit.unit, so we need to ensure objUnit.unit is true before we throw any UnitErrors
		if (objectHash.getUnitHash(objUnit) !== objUnit.unit)
			return callbacks.ifJointError("wrong unit hash: "+objectHash.getUnitHash(objUnit)+" != "+objUnit.unit);
	}
	catch(e){
		return callbacks.ifJointError("failed to calc unit hash: "+e);
	}
```

**File:** validation.js (L435-438)
```javascript
				function(cb){
					profiler.start();
					validateAuthors(conn, objUnit.authors, objUnit, objValidationState, cb);
				},
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
