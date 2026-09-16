### Title
Uncaught `throw Error("not 1 template")` in async DB callback crashes validating node on address definitions using `definition template` - ([File: definition.js])

### Summary
CVE-2016-3071 is a case where an unauthenticated protocol field (an IKEv2 `aes_xcbc` transform) reaches a code path that raises an unhandled assertion/exception, crashing (and restarting) the daemon. Ocore has an analogous pattern in `Definition.validateAuthentifiers`'s handling of the `'definition template'` opcode: a re-evaluation of an address definition can hit a synchronous `throw` inside an asynchronous DB callback, which cannot be caught by any surrounding `try/catch`, crashing the whole node process.

### Finding Description
`validateAuthentifiers`'s inner `evaluate()` function implements `'definition template'` by re-querying the DB for the referenced template unit and then calling `replaceInTemplate`/`evaluate` on the result: [1](#0-0) 

Note that unlike the structural check performed once in `validateDefinition` for the same opcode, which fails *gracefully* via callback: [2](#0-1) 

the `validateAuthentifiers` copy of this logic does `throw Error("not 1 template")` directly inside the `conn.query` callback instead of calling `cb(...)`. Because `conn.query`'s callback executes asynchronously (on a future tick), this `throw` cannot be caught by any `try/catch` that wraps the *call* to `evaluate`/`validateAuthentifiers` — JavaScript's synchronous exception handling does not span asynchronous callback boundaries. This is confirmed by the caller pattern in `validateAuthor`, which invokes `Definition.validateAuthentifiers` with no wrapping `try/catch` at all: [3](#0-2) 

and even where callers do wrap the *call* in `try/catch` (e.g., `signed_message.js`), that only catches synchronous exceptions during the call itself, not exceptions thrown later inside the DB callback: [4](#0-3) 

The comment above the top-level `validateAuthentifiers` entry point explicitly states that address definitions are **re-evaluated on every validation**, not just the first time, precisely because redefinitions/DAG changes can alter validity: [5](#0-4) 

This means the `'definition template'` branch is re-run every time any unit signed/authenticated by that address (or any asset condition referencing it) is (re-)validated. If the state of the referenced `definition_template` unit changes between the first successful validation and a later re-validation — e.g. it becomes non-stable, gets excluded from the main chain, or its `sequence` flips to `final-bad` due to resolution of a conflicting double-spend — the query `WHERE unit=? AND app='definition_template' AND main_chain_index<=? AND +sequence='good' AND is_stable=1` can return 0 rows on the second pass even though it returned 1 row earlier and the definition was accepted. This drives execution into the unguarded `throw Error("not 1 template")`.

### Impact Explanation
An unauthenticated exception thrown inside an async DB callback, with no enclosing try/catch able to intercept it (because JS try/catch does not span the event loop boundary), becomes a Node.js `uncaughtException`. Absent a global handler that safely no-ops on this specific error, the process terminates/restarts — a direct daemon-crash denial of service reachable simply by any unit poster who defines a multi-signature/complex address using the `'definition template'` opcode and whose validation is later re-triggered under normal, permissionless DAG evolution (conflict resolution, stabilization). Every full node that re-validates a unit/message signed by such an address is affected, which can degrade or halt the network's ability to confirm new units involving that address until node operators patch/restart with mitigations — matching the "network unable to confirm new units" / "node crash" impact classes.

### Likelihood Explanation
Reachability requires only posting a unit whose address definition contains a `['definition template', [unit, params]]` clause referencing a template unit — an entirely normal, documented oscript feature usable by any unprivileged unit poster. No privileged, hub, or peer-trust position is needed. The trigger condition (template-defining unit later losing `is_stable=1`/`sequence='good'` status due to standard conflict handling) is a naturally occurring DAG event, not a contrived edge case, making this reasonably likely to occur in a live network over time, though it does depend on the templated unit's fate diverging between two validation passes.

### Recommendation
Change the `'definition template'` handling in `validateAuthentifiers`'s `evaluate()` (definition.js, the block around line 811) to fail gracefully via the callback (`cb2(false)` or an equivalent "fatal_error" path), mirroring the safe pattern already used in `validateDefinition` (`return cb("template not found or too many")`), instead of `throw Error("not 1 template")`. More broadly, audit all `throw`/`throw Error` statements located inside asynchronous `conn.query`/callback bodies throughout `definition.js` (and similar validation modules) and convert them to callback-based error propagation, since none of these can be safely caught by calling code.

### Proof of Concept
1. Address `A` is defined with a definition containing `['definition template', ['<template_unit>', {param1:'value1'}]]`, where `<template_unit>` carries a `definition_template` message.
2. A unit is posted and validated normally while `<template_unit>` is `is_stable=1` and `sequence='good'` — `validateDefinition` and `validateAuthentifiers` both succeed, and the address/definition is accepted and cached/used by the network.
3. Later, `<template_unit>` becomes non-stable, gets excluded from the main chain, or its `sequence` becomes `final-bad` as a result of a conflicting unit winning tie-break (normal, permissionless DAG behavior).
4. Any subsequent re-validation of a unit/message authenticated by address `A` (as required by the "re-validate every time" contract in `definition.js:1448-1454`) re-runs `evaluate()` on the `'definition template'` opcode; the `conn.query` callback now finds `rows.length === 0` and executes `throw Error("not 1 template")` inside the async callback in `definition.js:811-812` (unguarded, unlike the safe check at `definition.js:326-327`), producing an uncaught exception that is not caught by any calling `try/catch` (see `validation.js:1243-1254`, `signed_message.js:277-294`), crashing the validating node process.

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

**File:** definition.js (L1448-1454)
```javascript
	
	// we need to re-validate the definition every time, not just the first time we see it, because:
	// 1. in case a referenced address was redefined, complexity might change and exceed the limit
	// 2. redefinition of a referenced address might introduce loops that will drive complexity to infinity
	// 3. if an inner address was redefined by keychange but the definition for the new keyset not supplied before last ball, the address
	// becomes temporarily unusable
	validateDefinition(conn, arrDefinition, objUnit, objValidationState, arrAuthentifierPaths, bAssetCondition, function(err){
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
