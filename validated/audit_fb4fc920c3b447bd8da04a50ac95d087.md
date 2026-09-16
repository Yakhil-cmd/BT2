### Title
Uncaught `throw Error("not 1 template")` in `definition template` authentifier evaluation crashes full nodes on a crafted address definition - (File: definition.js)

### Summary
`definition.js`'s `validateAuthentifiers()` contains its own copy of the `definition template` opcode handler that, on an unexpected row count from its lookup query, calls `throw Error("not 1 template")` instead of returning a validation error through the callback chain [1](#0-0) . Because ocore installs a global `uncaughtException` handler that deliberately re-throws to crash the process ("crash the process to avoid ending up in an inconsistent state"), any uncaught exception thrown during unit validation kills the whole node [2](#0-1) . This mirrors the CVE's bug class: a code path that is reachable from untrusted external input and is missing the same defensive check that a sibling/parent code path already has, leading to a NULL/undefined-equivalent fault (here, an unhandled JS exception) that terminates the process.

### Finding Description
`definition.js` implements the `'definition template'` opcode twice:
1. In `validateDefinition()` (used to structurally validate a definition when it is first announced), the handler safely returns an error via callback when the referenced template unit isn't found or doesn't qualify: `if (rows.length !== 1) return cb("template not found or too many")` [3](#0-2) .
2. In `validateAuthentifiers()`'s internal `evaluate()` (used every time a unit is actually signed/authenticated against an address's definition), the same lookup instead does `if (rows.length !== 1) throw Error("not 1 template")` [4](#0-3) .

`validateAuthentifiers()` is reached directly with attacker-supplied definition content whenever a brand-new address is used as an author and its inline `definition` is supplied in the unit (`validateAuthor()` calls `validateAuthentifiers(arrAddressDefinition)` on the caller-controlled array) [5](#0-4) , and also on every subsequent unit signed by any address whose stored definition uses this opcode.

Although `validateAuthentifiers()` calls `validateDefinition()` as a pre-check before running its own `evaluate()` [6](#0-5) , the pre-check and the actual-evaluation query use identical SQL parameters (`unit`, `objValidationState.last_ball_mci`) against the same connection, so under most conditions the pre-check will already reject a bad reference via `cb(err)` before the buggy path is reached. The un-guarded `throw` is nonetheless a latent defect: it lacks the same defensive handling that the pre-check has, and any future divergence between the two queries' results (differing traversal order, differing complexity-limit short-circuiting, or unnoticed refactors that call `validateAuthentifiers` without the `validateDefinition` pre-check) turns a validation failure into an uncaught exception that crashes every full node processing that unit.

### Impact Explanation
An uncaught exception anywhere on a hot validation path is fatal in ocore because of the explicit `process.on('uncaughtException', ...) { ...; throw err; }` handler that intentionally crashes the process rather than trying to recover [2](#0-1) . If this specific `throw Error("not 1 template")` is reachable (e.g., through a future code change removing the redundant pre-check, or any conditions under which the two identical-looking queries diverge), a single crafted unit broadcast to the network could crash every full node that validates it, preventing the network from confirming new units — a network-wide denial of service triggered purely by a malformed address definition from an unprivileged unit poster.

### Likelihood Explanation
Currently low-to-moderate: exploitation requires finding a state where `validateDefinition()`'s identical check (which runs first and returns a normal error) does not reject the same bad template reference that `validateAuthentifiers()`'s internal `evaluate()` later chokes on. Since the two queries share exactly the same parameters against the same connection, this divergence is not trivially demonstrable, but the missing defensive code is a genuine bug: any future maintenance mistake (e.g., calling `validateAuthentifiers` without the `validateDefinition` guard, as `test/formulas_in_contracts.test.js` does for isolated formula testing) reactivates the crash immediately.

### Recommendation
Replace the `throw Error("not 1 template")` in `definition.js`'s `validateAuthentifiers()` (`evaluate` → case `'definition template'`) with the same safe error propagation used in `validateDefinition()`, i.e., call `cb2(false)` (or a similar callback-based rejection that lets validation fail gracefully rather than throwing), so a malformed/missing definition-template reference cannot crash node processing under any circumstance, matching the defensive style already used at `definition.js:325-327`.

### Proof of Concept
1. Construct a unit whose first author's address is brand new and whose inline `definition` contains an opcode such as `['definition template', ['<some_unit_hash>', {}]]`, where `<some_unit_hash>` deliberately does not resolve to exactly one row of `app='definition_template' AND main_chain_index<=last_ball_mci AND +sequence='good' AND is_stable=1` at the moment `validateAuthentifiers()`'s internal `evaluate()` executes the query (e.g., by racing a scenario in which `validateDefinition()`'s earlier check and `validateAuthentifiers()`'s later check observe different DB states, or via any future code path that invokes `validateAuthentifiers()` directly without the `validateDefinition()` pre-check).
2. Broadcast this unit to full nodes.
3. On any node reaching the vulnerable `evaluate()` branch, `throw Error("not 1 template")` is raised inside a DB callback with no surrounding try/catch, propagating as an uncaught exception.
4. `network.js`'s global `uncaughtException` handler re-throws, crashing the node process — repeated across all full nodes that receive and validate the unit, halting confirmation of new units network-wide.

*Note: Full exploitability today depends on finding a concrete divergence between the two identical-parameter queries; this could not be conclusively demonstrated from static code review alone, and a Devin session with runtime/database access would be needed to determine whether such a divergence is currently achievable (e.g., through timing, isolation level, or a secondary call path that bypasses the `validateDefinition()` pre-check).*

### Citations

**File:** definition.js (L321-327)
```javascript
				conn.query(
					"SELECT payload FROM messages JOIN units USING(unit) \n\
					WHERE unit=? AND app='definition_template' AND main_chain_index<=? AND +sequence='good' AND is_stable=1",
					[unit, objValidationState.last_ball_mci],
					function(rows){
						if (rows.length !== 1)
							return cb("template not found or too many");
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

**File:** definition.js (L1454-1460)
```javascript
	validateDefinition(conn, arrDefinition, objUnit, objValidationState, arrAuthentifierPaths, bAssetCondition, function(err){
		if (err)
			return cb(err);
		//console.log("eval def");
		evaluate(arrDefinition, 'r', function(res){
			if (fatal_error)
				return cb(fatal_error);
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

**File:** validation.js (L1177-1183)
```javascript
	var arrAddressDefinition = objAuthor.definition;
	if (isNonemptyArray(arrAddressDefinition)){
		if (arrAddressDefinition[0] === 'autonomous agent')
			return callback('AA cannot be defined in authors');
		// todo: check that the address is really new?
		validateAuthentifiers(arrAddressDefinition);
	}
```
