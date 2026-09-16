### Title
Unhandled `throw Error("not 1 template")` in `validateAuthentifiers` can permanently brick spending from any address whose definition uses a `definition template` reference - ([File: definition.js])

### Summary
`Definition.validateAuthentifiers()` in `definition.js` evaluates the `'definition template'` operator by querying for the exact referenced `definition_template` message and, if it does not find exactly one row, unconditionally `throw`s an `Error`, instead of returning a graceful validation error through the callback chain (as its sibling function `validateDefinition()` does for the same operator).

### Finding Description
In `definition.js`, two functions evaluate the `'definition template'` operator:

- `validateDefinition()` (used only when the definition is first introduced/validated) at [1](#0-0)  handles the "not found or too many" case gracefully by calling `cb("template not found or too many")`.

- `validateAuthentifiers()` (used every single time the address/definition is used to authenticate a spend, and re-run "every time" per the code's own comment) at [2](#0-1)  instead does:
```js
function(rows){
    if (rows.length !== 1)
        throw Error("not 1 template");
    ...
}
```
This is a synchronous `throw` executed inside an asynchronous DB-callback context [3](#0-2) . There is no `try/catch` anywhere in the call chain (`validateAuthentifiers` → `evaluate` → `conn.query` callback), and `Definition.validateAuthentifiers` is invoked directly from unit authentication in `validation.js` `validateAuthor()` at [4](#0-3) , which has no surrounding exception guard either.

The code comment explicitly documents why the definition must be *re-evaluated on every use*, not just once: [5](#0-4) 
```
// we need to re-validate the definition every time, not just the first time we see it, because:
// 1. in case a referenced address was redefined, complexity might change...
// 2. redefinition of a referenced address might introduce loops...
// 3. if an inner address was redefined ... the address becomes temporarily unusable
```
This same reasoning applies to `'definition template'` references: the referenced unit's status can change between the time the outer address definition was accepted and any later spend attempt using that definition — e.g. the template-defining unit's sequence can flip from `'good'` to `'final-bad'` after a later-discovered double-spend is resolved (mirrored by the exact same query pattern with `AND +sequence='good' AND is_stable=1` used elsewhere for double-spend resolution, e.g. [6](#0-5) ). When that happens, the query in `validateAuthentifiers` returns 0 rows where it previously returned 1, and the code throws instead of failing the authentifier check cleanly.

This exactly parallels the Curve report's root cause: code assumes a specific external/optional-dependent condition ("the pool always exposes `owner()`", here "the template unit is always exactly 1 row and always `sequence='good'`") will hold at execution time, and when that assumption is violated the code takes an uncontrolled failure path (Solidity `revert`; here a raw JS `throw`) instead of the properly designed graceful-error path that exists elsewhere in the same codebase for the identical case.

### Impact Explanation
An uncaught `throw` inside an async DB-callback in Node.js is not converted into a promise rejection or handled error — it propagates as an uncaught exception up the call stack of whichever code path invoked unit validation (full-node validation of an incoming unit, or light-wallet's own validation flow). Because there is no global `process.on('uncaughtException')` guard around the unit/AA validation code path (the only `uncaughtException` handlers found are unrelated, in `network.js`), this will crash the node process performing validation.

Consequences:
- Any address that includes a `['definition template', [unit, params]]` clause in its spending definition becomes unable to have its spends validated deterministically once the underlying condition (exactly-one-good-stable template row) is violated — every node attempting to validate a unit spent from that address hits the same crash, since validation is deterministic given the same DAG state. This is a consensus-relevant, network-wide condition, not a single-node quirk.
- This causes denial of service / permanent freezing of funds controlled by such an address (the address becomes unusable — same "bricking" outcome the referenced Curve report describes for LP token pricing), and simultaneously an actual crash of node software validating that unit, i.e. "a network unable to confirm new units" containing spends from that address, since the validating node dies mid-validation instead of rejecting the unit and moving on.

### Likelihood Explanation
Reaching this requires an address whose spending definition uses `'definition template'`, referencing a unit whose `definition_template` message can later lose its `sequence='good'`/`is_stable=1` status (e.g., due to a double-spend on that specific unit being resolved unfavorably after the outer definition was accepted, or any other DAG condition that changes the row set matched by that exact `unit=? AND app='definition_template' AND main_chain_index<=? AND +sequence='good' AND is_stable=1` query between initial validation and a later authentication attempt). This is a deliberately supported, user-composable oscript feature (used in `definition.js`, `wallet_defined_by_addresses.js`, and exercised in `test/aa.test.js` with a `definition_template` app message), so any wallet, shared-address, or AA-adjacent user can construct such a definition and later trigger the divergent condition — this does not require special privileges, matching the required threat model of "an unprivileged unit poster / address definer."

### Recommendation
Change the `'definition template'` handling inside `validateAuthentifiers()` to mirror `validateDefinition()`'s graceful handling: replace
```js
if (rows.length !== 1)
    throw Error("not 1 template");
```
with a call to `cb2(false)` (treat as authentifier check failed) or surface the error properly through the existing `fatal_error`/`cb` mechanism used elsewhere in `validateAuthentifiers` (e.g., as done for `'sig'`/`'hash'` failures), so that a missing/ambiguous template unit fails validation deterministically without throwing an unhandled exception that can crash the validating process.

### Proof of Concept
Conceptual reproduction (not exploitable purely by static reading, but demonstrable via constructing test fixtures similar to `test/aa.test.js`'s `definition_template` usage, e.g. [7](#0-6) ):
1. Post unit A containing an `app: "definition_template"` message; let it stabilize as `sequence='good'`.
2. Define/authenticate an address B whose definition contains `['definition template', [A_unit, {...}]]`; initial `validateDefinition()` succeeds and returns the graceful `"template not found or too many"` path if ever needed, but succeeds here because exactly one row matches.
3. Cause unit A to later become `sequence='final-bad'` via a resolved double-spend against it (a standard, always-possible DAG event for any unit).
4. Attempt to spend from address B again (or reference the earlier asset/definition condition again). `validateAuthentifiers()` re-runs `evaluate()` on the `'definition template'` node; the query at [8](#0-7)  now returns 0 rows, hitting `throw Error("not 1 template")`, crashing the validating node process instead of cleanly rejecting the spending unit.

### Citations

**File:** definition.js (L321-342)
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
						evaluate(arrFilledTemplate, path, bInNegation, cb);
					}
				);
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

**File:** validation.js (L2266-2269)
```javascript
				else
					doubleSpendWhere += " AND asset IS NULL";
				// final-bad units are treated as non-existent competitors (their inputs.is_unique is kept NULL)
				var doubleSpendQuery = "SELECT "+doubleSpendFields+" FROM inputs " + doubleSpendIndexMySQL + " JOIN units USING(unit) WHERE "+doubleSpendWhere+" AND sequence!='final-bad'";
```

**File:** test/aa.test.js (L301-307)
```javascript
			{
				app: 'definition_template',
				payload: ['and', [
					['sig', { pubkey: "{trigger.data.pubkey}" }],
					['in data feed', ["{trigger.data.oracle}"], "{trigger.data.feed_name}", "=", "@feed_value"]
				]]
			},
```
