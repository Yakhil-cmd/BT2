### Title
Uncaught exception in `definition template` re-evaluation crashes the node process — DoS analog of vLLM's guided-JSON crash - ([File: definition.js])

### Summary
Like the vLLM bug, where a malformed/mismatched user-supplied JSON schema caused an uncaught exception deep in a compiler call that killed the whole server process, ocore's `definition template` opcode handling in `Definition.validateAuthentifiers`'s inner `evaluate()` (used every time signatures are checked against an address definition) contains a code path that `throw`s inside an asynchronous `conn.query` callback instead of passing an error through the `cb` chain. Because the throw happens inside a DB callback (a new tick), no surrounding `try/catch` (including the one in `signed_message.js`) can catch it, so it becomes an uncaught exception that crashes the entire Node.js process.

### Finding Description
`Definition.validateAuthentifiers` re-validates and re-evaluates an address's definition on every signature check (comment at [1](#0-0) ). Its `evaluate()` function handles the `'definition template'` op by looking up the referenced `definition_template` message and expanding it with `replaceInTemplate`: [2](#0-1) 

Two problems make this reachable and fatal:

1. `if (rows.length !== 1) throw Error("not 1 template");` — a bare `throw` inside the `conn.query` async callback.
2. `replaceInTemplate` itself throws on unexpected structure/recursion (`NoVarException` for missing `$var`, `Error("unknown type")` for unsupported types, or a `RangeError: Maximum call stack size exceeded` for deep nesting), all raised from a recursive walker with no depth limit: [3](#0-2) 

Compare this to the *initial* definition-validation path (`validateDefinition`), which performs the same lookup/expansion but is careful to return errors via callback instead of throwing, and only re-throws exceptions that are not `NoVarException`: [4](#0-3) 

That `else throw e;` branch (line 337-338) shows the code is aware that unexpected exceptions can occur here — but it deliberately re-raises them rather than converting to a validation error, and it does so **inside an async DB callback**, defeating any enclosing `try/catch`.

The `evaluate()` variant used for authentifier verification (line 802-819) does not even have this partial protection — any exception from `replaceInTemplate`, or the `rows.length !== 1` case, is thrown raw inside the query callback.

This function is reachable from ordinary unit validation. `validateAuthor()` in `validation.js` invokes `Definition.validateAuthentifiers` directly (no try/catch around the call) whenever an author signs with an address definition containing a `'definition template'` reference at any nesting depth (including nested `'address'` references that pull in another address's definition): [5](#0-4) [6](#0-5) 

Even the wrapping `try/catch` present in `signed_message.js` (used by `is_valid_signed_package` in oscript, another unprivileged AA-reachable path) cannot help, because the exception fires asynchronously inside the DB callback, after the synchronous `try` block has already returned: [7](#0-6) 

### Impact Explanation
An uncaught exception thrown from inside an async DB callback in Node.js is not recoverable by any caller-side `try/catch`; by default it aborts the process (or is only caught by a top-level `process.on('uncaughtException')` handler, if any, which for a partially-completed unit/AA-trigger validation flow leaves the node in an undefined state). Since `evaluate()`'s `'definition template'` case is invoked on **every** signature verification of any unit whose (possibly nested/inner) address definition uses `'definition template'`, a single crafted unit or `is_valid_signed_package()` evaluation inside an AA trigger can crash every full node, hub, or witness that attempts to validate it — a "node unable to confirm new units" outcome (per the task's accepted-impact list). This affects availability network-wide, not just the attacker's own client, because every node re-validates signatures independently.

### Likelihood Explanation
Reaching the vulnerable `evaluate()` path only requires:
1. An on-chain, previously-accepted address whose definition contains `['definition template', [template_unit, params]]` — attainable because the initial `validateDefinition` check (line 306-343) will *accept* such a definition as long as the FIRST expansion attempt succeeds (no `NoVarException`, no stack overflow at validation time), or an attacker relies on the `throw Error("not 1 template")` race if the referenced template unit becomes non-existent/unstable relative to the mci used during signature re-checking versus initial definition acceptance (different `last_ball_mci` snapshots are used across validations, per the very comment in the code explaining why re-validation is necessary at 1449-1453 — i.e., the code's own justification for re-checking implies the result CAN differ between validations).
2. Alternatively, an attacker who controls their own address (a first-use address, defined inline in `objAuthor.definition`) can craft a definition, referencing a template designed so it validates once (or is deliberately made to fail differently) then subsequently trips the throw during actual signature verification (`validateAuthentifiers`), since `validateDefinition` and `evaluate()` perform their template lookups as two independent DB queries.

This is unprivileged: any unit poster can define new addresses and any AA trigger sender can invoke `is_valid_signed_package()` with attacker-supplied `authors[].definition`, matching the "unprivileged unit poster / AA trigger sender" reachability requirement. Exact preconditions for guaranteeing the discrepancy between the two lookups were not fully verifiable without live DB semantics/testing, so likelihood is assessed as plausible but not empirically confirmed here.

### Recommendation
- In `definition.js`, wrap the body of the `'definition template'` query callback (both occurrences, in `validateDefinition` and in `validateAuthentifiers`'s `evaluate()`) in `try { ... } catch (e) { return cb(...error...) }` and never `throw` inside an async DB callback.
- Change `if (rows.length !== 1) throw Error("not 1 template");` to `return cb("not 1 template");` at line 812.
- Harden `replaceInTemplate` with an explicit depth/size limit (similar to `MAX_DEPTH` used elsewhere, e.g. in `aa_validation.js` line 486-490) instead of relying on JS call-stack exhaustion, and ensure any exception it throws is converted into a validation failure rather than propagated.
- Audit all other `conn.query(...)` callbacks in `definition.js`/`validation.js` that contain bare `throw` statements reachable from untrusted unit content for the same async-uncaught-exception hazard.

### Proof of Concept
1. Post a `definition_template` message containing a very deeply nested array (e.g. `[[[[...]]]]]` nested ~50,000+ levels, JSON-serialized) — a standard, permitted message payload for app `definition_template`.
2. Define (or arrange for validation of) an address whose spending/signing condition is `['definition template', ['<template_unit>', {}]]`.
3. Have any node validate a unit (or evaluate `is_valid_signed_package()` in an AA trigger) that signs with this address/definition.
4. `Definition.validateAuthentifiers`'s `evaluate()` calls `replaceInTemplate` on the deeply nested template; the recursive `replaceInVar` walker overflows the JS call stack, throwing a `RangeError` inside the `conn.query` callback at definition.js line 802-819, which is uncaught and crashes the validating node process — mirroring the vLLM `RuntimeError` inside `xgrammar` crashing the vLLM engine core on a single malformed request.

### Citations

**File:** definition.js (L306-343)
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
						evaluate(arrFilledTemplate, path, bInNegation, cb);
					}
				);
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

**File:** definition.js (L1449-1453)
```javascript
	// we need to re-validate the definition every time, not just the first time we see it, because:
	// 1. in case a referenced address was redefined, complexity might change and exceed the limit
	// 2. redefinition of a referenced address might introduce loops that will drive complexity to infinity
	// 3. if an inner address was redefined by keychange but the definition for the new keyset not supplied before last ball, the address
	// becomes temporarily unusable
```

**File:** definition.js (L1468-1502)
```javascript
function replaceInTemplate(arrTemplate, params){
	function replaceInVar(x){
		switch (typeof x){
			case 'number':
			case 'boolean':
				return x;
			case 'string':
				// searching for pattern "$name"
				if (x.charAt(0) !== '$')
					return x;
				var name = x.substring(1);
				if (!ValidationUtils.hasOwnProperty(params, name))
					throw new NoVarException("variable "+name+" not specified, template "+JSON.stringify(arrTemplate)+", params "+JSON.stringify(params));
				return params[name]; // may change type if params[name] is not a string
			case 'object':
				if (Array.isArray(x))
					for (var i=0; i<x.length; i++)
						x[i] = replaceInVar(x[i]);
				else
					for (var key in x)
						assignField(x, key, replaceInVar(x[key]));
				return x;
			default:
				throw Error("unknown type");
		}
	}
	return replaceInVar(_.cloneDeep(arrTemplate));
}

function NoVarException(error){
	this.error = error;
	this.toString = function(){
		return this.error;
	};
}
```

**File:** validation.js (L1177-1211)
```javascript
	var arrAddressDefinition = objAuthor.definition;
	if (isNonemptyArray(arrAddressDefinition)){
		if (arrAddressDefinition[0] === 'autonomous agent')
			return callback('AA cannot be defined in authors');
		// todo: check that the address is really new?
		validateAuthentifiers(arrAddressDefinition);
	}
	else if (!("definition" in objAuthor)){
		if (objUnit.content_hash){ // nothing else to check
			objValidationState.sequence = 'final-bad';
			return callback();
		}
		// we check signatures using the latest address definition before last ball
		storage.readDefinitionByAddress(conn, objAuthor.address, objValidationState.last_ball_mci, {
			ifDefinitionNotFound: function(definition_chash){
				storage.readAADefinition(conn, objAuthor.address, objValidationState.last_ball_mci, function (arrAADefinition) {
					if (arrAADefinition)
						return callback(createTransientError("will not validate unit signed by AA"));
					if (objValidationState.last_ball_mci >= constants.pemCurvesFixMci || !objValidationState.hasBall && storage.getMinRetrievableMci() >= constants.pemCurvesFixMci)
						return callback("definition " + definition_chash + " bound to address " + objAuthor.address + " not found before last ball");
					findUnstableInitialDefinition(definition_chash, function (arrDefinition) {
						if (!arrDefinition)
							return callback("definition " + definition_chash + " bound to address " + objAuthor.address + " is not defined");
						bInitialDefinition = true;
						validateAuthentifiers(arrDefinition);
					});
				});
			},
			ifFound: function(arrAddressDefinition){
				validateAuthentifiers(arrAddressDefinition);
			}
		});
	}
	else
		return callback("bad type of definition");
```

**File:** validation.js (L1243-1254)
```javascript
	function validateAuthentifiers(arrAddressDefinition){
		Definition.validateAuthentifiers(
			conn, objAuthor.address, null, arrAddressDefinition, objUnit, objValidationState, objAuthor.authentifiers, 
			function(err, res){
				if (err) // error in address definition
					return callback(err);
				if (!res) // wrong signature or the like
					return callback("authentifier verification failed");
				checkSerialAddressUse();
			}
		);
	}
```

**File:** signed_message.js (L277-294)
```javascript
				try {
					// passing db as null
					Definition.validateAuthentifiers(
						conn, objAuthor.address, null, arrAddressDefinition, objUnit, objValidationState, objAuthor.authentifiers,
						function (err, res) {
							if (err) // error in address definition
								return cb(err);
							if (!res) // wrong signature or the like
								return cb("authentifier verification failed");
							complexity = objValidationState.complexity;
							cb();
						}
					);
				}
				catch (e) {
					console.log("exception while validating signed message:", e);
					return cb("exception while validating: " + e);
				}
```
