### Title
Unhandled exception in address-definition signature evaluation (`definition template` operator) causes node crash - (File: `definition.js`)

### Summary
The MCP advisory describes an unhandled exception thrown during validation of malformed/edge-case input that is not caught anywhere, causing the process to become unavailable until restarted. `ocore` has an analogous defect in the `'definition template'` operator handling inside `validateAuthentifiers()` in `definition.js`. Unlike the sibling implementation of the same operator in `validateDefinition()`, which reports the error through the normal callback chain, the `validateAuthentifiers()` version throws a bare `Error` on an unexpected row count, and that throw is not caught by any surrounding try/catch in the unit-validation call chain, so it becomes an uncaught exception that crashes the full node.

### Finding Description
When an address definition uses the `'definition template'` operator (`['definition template', [unit, params]]`), the referenced unit's stored `definition_template` payload is looked up with: [1](#0-0) 

If the query does not return exactly one row, this code path throws synchronously: [2](#0-1) 

Compare this to the analogous branch used when a definition is first being *declared* (`validateDefinition()`), which handles the very same "not found or too many" condition safely by invoking the callback with an error string instead of throwing: [3](#0-2) 

`validateAuthentifiers()` is the function used every time a unit is authored/spends from an address whose definition contains this operator — i.e., on every subsequent signature check, not just once at definition time: [4](#0-3) 

This function is invoked from `validateAuthor()`/`validateAuthentifiers()` in the main `validation.js` unit-validation pipeline, which has no try/catch around the call and instead relies entirely on the callback style; a thrown exception here is not intercepted: [5](#0-4) 

Because `validation.validate()` runs inside `network.js`'s `handleOnlineJoint`, and the process has a deliberate top-level "crash-on-uncaught-exception" handler, any uncaught throw anywhere in the validation call graph brings the whole node down: [6](#0-5) 

### Impact Explanation
Once an address's definition includes a `'definition template'` reference, every future signature verification for a unit authored by (or spending from) that address re-executes the SQL lookup and re-evaluates the throw condition. If the row count is ever not exactly 1 — for example due to node-state differences, stale/duplicated `definition_template` rows, database inconsistency, or a crafted template reference designed to hit this edge case — every full node that validates such a unit hits the uncaught `throw Error("not 1 template")`, which the global `uncaughtException` handler re-throws to crash the process. This matches the "network unable to confirm new units" / node-availability class of impact called out in the validation rules: a landmine address definition can be created once and then reliably crash any node (or all nodes) that later attempt to validate a spend referencing it, producing a persistent denial of service until manual restart, mirroring the MCP SDK's "500 until manually restarted" behavior.

### Likelihood Explanation
Reachability requires only that: (1) an attacker defines/uses an address whose definition contains a `'definition template'` operator pointing at a `definition_template` unit, and (2) a later validation of any unit signed by that address re-queries the template and gets other than exactly one matching row. The asymmetric handling (`cb(...)` in `validateDefinition` vs `throw` in `validateAuthentifiers`) is direct code evidence that this exact edge case was anticipated as a normal validation failure in one place but not safely handled in the other, making it a realistic, reachable landmine rather than a purely theoretical invariant violation. I was not able to fully verify, within the available tool budget, every precondition needed to force the row count away from exactly 1 (e.g., whether the base unit-message validation restricts the number of `definition_template`-app messages per unit or otherwise guarantees uniqueness at write time) — this would need to be confirmed with a live Devin session before treating this as fully proven end-to-end.

### Recommendation
Change the `'definition template'` branch in `validateAuthentifiers()` (`definition.js`, the `evaluate()` closure) to handle `rows.length !== 1` the same way `validateDefinition()` does — set `fatal_error` and/or call `cb2(false)`/propagate an error through the callback — instead of throwing. More broadly, audit `definition.js` and `validation.js` for other `throw Error(...)` statements inside callback-based validation flows that are reachable from externally-supplied unit content (as opposed to true "should never happen" internal invariants), and convert genuinely input-dependent conditions to callback-based error returns so a single crafted unit cannot crash a node via an uncaught exception.

### Proof of Concept
1. Post/stabilize a unit containing a `definition_template` app message defining a template.
2. Create (or redefine) an address whose definition includes `['definition template', [<template_unit>, {params}]]`, referencing the unit from step 1.
3. Arrange for the state seen by a validating node to no longer match "exactly one row" for that template lookup (e.g., through duplicate/absent rows caused by node-specific state, forks, or database inconsistency) at the time a spend from that address is validated.
4. Any node that validates a unit signed by that address executes `evaluate()`'s `'definition template'` case in `validateAuthentifiers()` [1](#0-0) , hits `rows.length !== 1`, throws `Error("not 1 template")`, which is uncaught and triggers `process.on('uncaughtException')` to crash the node [6](#0-5) .

Full confirmation of the exact steps to force the row-count mismatch under attacker control requires further investigation with direct code/database access, which is outside the scope of this static analysis.

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

**File:** definition.js (L1443-1454)
```javascript
	if (bAssetCondition && address || !bAssetCondition && this_asset)
		throw Error("incompatible params");
	var arrAuthentifierPaths = bAssetCondition ? null : Object.keys(assocAuthentifiers);
	var fatal_error = null;
	var arrUsedPaths = [];
	
	// we need to re-validate the definition every time, not just the first time we see it, because:
	// 1. in case a referenced address was redefined, complexity might change and exceed the limit
	// 2. redefinition of a referenced address might introduce loops that will drive complexity to infinity
	// 3. if an inner address was redefined by keychange but the definition for the new keyset not supplied before last ball, the address
	// becomes temporarily unusable
	validateDefinition(conn, arrDefinition, objUnit, objValidationState, arrAuthentifierPaths, bAssetCondition, function(err){
```

**File:** validation.js (L1443-1466)
```javascript
							function(row, cb){
								graph.determineIfIncludedOrEqual(conn, row.unit, objUnit.parent_units, function(bIncluded){
									if (bIncluded)
										console.log("checkNoPendingOrRetrievableNonserialIncluded: unit "+row.unit+" is included");
									bIncluded ? cb("found") : cb();
								});
							},
							function(err){
								(err === "found") 
									? callback("you can't send anything before all your included nonserial units are stable \
											   and lie before last ball of last ball (self is nonserial)") 
									: next();
							}
						);
					}
				);
			}
		);
	}
	*/
	
	function validateDefinition(){
		if (!("definition" in objAuthor))
			return callback();
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
