## Analysis

The libsass bug is a NULL-pointer dereference reached during recursive parsing/evaluation of user-supplied structured input, causing an unhandled crash (DoS). The closest reachable analog in `ocore--013` is an **unconditional, uncaught `throw`** reached while evaluating a user-supplied address-definition tree during signature validation, before that tree has been structurally validated — i.e., a crafted unit can deterministically crash every node that validates it.

### Title
Unauthenticated crash of validating nodes via crafted `definition template` op evaluated before structural validation - (File: definition.js)

### Summary
`Definition.validateAuthentifiers()` (used to check signatures against a **newly declared** address definition supplied in `objAuthor.definition`) evaluates the definition tree *before* `Definition.validateDefinition()` has structurally validated it. Inside `evaluate()`, the `definition template` op destructures `args[0]`/`args[1]` without checking `args` is an array, then issues a DB query and unconditionally `throw`s if the query does not return exactly one row. This throw is never caught, and per `network.js`'s global `uncaughtException` handler, it crashes the whole node process.

### Finding Description
For a first-time address definition, `validateAuthor()` calls `Definition.validateAuthentifiers(arrAddressDefinition)` ( [1](#0-0) ) whose success callback runs `checkSerialAddressUse()`, which only later invokes `validateDefinition` as `next()` ( [2](#0-1) ). This means `Definition.validateAuthentifiers`'s `evaluate()` runs on **raw, attacker-controlled** definition JSON, with no prior structural checks.

Inside that `evaluate()`, the `definition template` case does:
```
var unit = args[0];
var params = args[1];
conn.query(..., function(rows){
    if (rows.length !== 1)
        throw Error("not 1 template");
    ...
});
``` [3](#0-2) 

There is no `isArrayOfLength(args, 2)` check (unlike the sibling code path in `validateDefinition`'s own `definition template` handler, which validates `args` and returns a normal callback error instead of throwing: [4](#0-3) ). An attacker only needs to reference a `unit` hash for which the template-lookup query returns 0 (or >1) rows — trivially achieved by pointing to any unit that is not a stable `definition_template` message, or a nonexistent unit — to hit `throw Error("not 1 template")`.

This throw occurs asynchronously inside a `conn.query` callback, several stack frames removed from any `try/catch` in `validateAuthor`/`validateMessages`/`validate()`. It propagates to Node's event loop and is caught only by the process-wide handler in `network.js`, which re-throws to intentionally crash the process: [5](#0-4) 

### Impact Explanation
Any node (light-agnostic; applies to every full node, since this runs inside the common `validation.js` `validate()` path used for all broadcast/posted units) that receives and validates a unit whose author defines a new address with such a crafted definition will crash. Because units are broadcast/gossiped, a single malicious unit can crash multiple/all full nodes that attempt to validate it — a network-wide denial of service preventing confirmation of new units, matching the "network unable to confirm new units" impact bar.

### Likelihood Explanation
The trigger requires no privileges beyond being an ordinary unit poster defining a new address for the first time (`objAuthor.definition` with no prior definition on record) and embedding a `['definition template', [bad_unit, {...}]]` op anywhere reachable in the boolean tree (including nested via `or`/`and`/`r of set`, or via the `address` op referencing another author's un-yet-validated definition in the same unit, which recurses into the same vulnerable `evaluate()`: [6](#0-5) ). No cryptographic material or race condition is needed — the crash path is deterministic once the unit reaches validation on any node.

### Recommendation
In `Definition.validateAuthentifiers`'s `definition template` case:
- Validate `args` is a 2-element array before destructuring (mirror the check already present in `validateDefinition`: `isArrayOfLength(args, 2)`, `isValidBase64(unit, ...)`, `isNonemptyObject(params)`).
- Replace the unconditional `throw Error("not 1 template")` with a normal validation failure (`return cb2(false)` or equivalent), consistent with how `validateDefinition`'s counterpart handles the same condition (`return cb("template not found or too many")`, [7](#0-6) ).
- More generally, ensure `Definition.validateAuthentifiers` never executes on a definition tree that hasn't first passed `Definition.validateDefinition`'s structural checks, or make `evaluate()` defensive against malformed nodes regardless of call order.

### Proof of Concept
1. Attacker posts a new unit whose sole author `objAuthor.address` has never had a definition before, with:
```json
"definition": ["definition template", ["oXGOcA9TQx8Tl5Syjp1d5+mB4xicsRk3kbcE82YQAS0=", {"p":"v"}]]
```
where the referenced unit hash is any 44-byte base64 string that is not a stable `definition_template` message app (e.g. an arbitrary but well-formed hash, or the genesis unit).
2. `objAuthor.authentifiers` need not even be correct for the throw to be reached, since the crash happens inside `evaluate()` before/independent of signature comparison, as `evaluate()` walks the whole tree.
3. Node receives/broadcasts the unit, `validateAuthor` → `validateAuthentifiers(arrAddressDefinition)` → `Definition.validateAuthentifiers` → `evaluate()` hits `case 'definition template'`, queries for the template, gets 0 rows, executes `throw Error("not 1 template")`.
4. The uncaught exception bubbles to `process.on('uncaughtException', ...)` in `network.js`, which logs and re-throws, terminating the node process. [3](#0-2) [2](#0-1) [5](#0-4)

### Citations

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

**File:** validation.js (L1304-1310)
```javascript
	function checkSerialAddressUse(){
		var next = (objValidationState.last_ball_mci >= constants.pemCurvesFixMci || !objValidationState.hasBall && storage.getMinRetrievableMci() >= constants.pemCurvesFixMci) ? validateDefinition : checkNoPendingChangeOfDefinitionChash;
		findConflictingUnits(function(arrConflictingUnitProps){
			if (arrConflictingUnitProps.length === 0){ // no conflicting units
				// we can have 2 authors. If the 1st author gave bad sequence but the 2nd is good then don't overwrite
				objValidationState.sequence = objValidationState.sequence || 'good';
				return next();
```

**File:** definition.js (L306-327)
```javascript
			case 'definition template':
				// ['definition template', ['unit', {param1: 'value1'}]]
				if (objValidationState.bNoReferences)
					return cb("no references allowed in address definition");
				if (!isArrayOfLength(args, 2))
					return cb("2-element array expected in "+op);
				var unit = args[0];
				var params = args[1];
				if (!isValidBase64(unit, constants.HASH_LENGTH))
					return cb("unit must be a valid base64 string 44 bytes long");
				if (!isNonemptyObject(params))
					return cb("params must be non-empty object");
				for (var key in params)
					if (typeof params[key] !== "string" && typeof params[key] !== "number")
						return cb("each param must be string or number");
				conn.query(
					"SELECT payload FROM messages JOIN units USING(unit) \n\
					WHERE unit=? AND app='definition_template' AND main_chain_index<=? AND +sequence='good' AND is_stable=1",
					[unit, objValidationState.last_ball_mci],
					function(rows){
						if (rows.length !== 1)
							return cb("template not found or too many");
```

**File:** definition.js (L774-800)
```javascript
			case 'address':
				// ['address', 'BASE32']
				if (!pathIncludesOneOfAuthentifiers(path, arrAuthentifierPaths, bAssetCondition))
					return cb2(false);
				var other_address = args;
				storage.readDefinitionByAddress(conn, other_address, objValidationState.last_ball_mci, {
					ifFound: function(arrInnerAddressDefinition){
						evaluate(arrInnerAddressDefinition, path, cb2);
					},
					ifDefinitionNotFound: function(definition_chash){
						try {
							var arrDefiningAuthors = objUnit.authors.filter(function(author){
								return (author.address === other_address && author.definition && objectHash.getChash160(author.definition) === definition_chash);
							});
						}
						catch (e) {
							return cb2(false);
						}
						if (arrDefiningAuthors.length === 0) // no definition in the current unit
							return cb2(false);
						if (arrDefiningAuthors.length > 1)
							throw Error("more than 1 address definition");
						var arrInnerAddressDefinition = arrDefiningAuthors[0].definition;
						evaluate(arrInnerAddressDefinition, path, cb2);
					}
				});
				break;
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
