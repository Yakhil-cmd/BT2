### Title
Uncaught `throw Error` in `definition template` authentifier check crashes every validating node - ([File: definition.js])

### Summary
`definition.js`'s `validateAuthentifiers()` handles the `'definition template'` operator by querying for exactly one stable `definition_template` message and, if that invariant does not hold, calls `throw Error("not 1 template")` instead of failing gracefully through the callback chain, unlike the equivalent, carefully-handled code path in `validateDefinition()`.

### Finding Description
`definition.js` contains two parallel implementations of the `'definition template'` operator:

- In `validateDefinition()` (used when an address/asset spending condition is first being validated/defined), the check is done safely: [1](#0-0) 
returns `cb("template not found or too many")` on a bad row count, and any exception is caught and converted to a callback error.

- In `validateAuthentifiers()` (used on *every subsequent unit* whose signature must be checked against an address definition using this operator), the exact same invariant is instead enforced with an unguarded `throw`: [2](#0-1) 
```
case 'definition template':
    ...
    conn.query(..., function(rows){
        if (rows.length !== 1)
            throw Error("not 1 template");
        ...
    });
```
This `throw` occurs inside an asynchronous DB callback, so it cannot be caught by any surrounding `try/catch` in the validation call stack — it becomes an uncaught exception that propagates up through the event loop and crashes the Node.js process (comparable to a `CHECK`-failure abort in the TensorFlow advisory: an attacker-controllable structural anomaly — here, an unexpected row count for a referenced sub-structure — triggers an unconditional assertion/crash instead of a handled validation error).

`validateAuthentifiers` is invoked by `validation.js` on every unit whose author (or nested address in a definition, via the `'address'` operator) uses a definition containing a `'definition template'` node, each time re-evaluated against the *current* unit's `last_ball_mci` (not the MCI at which the definition was first accepted): [3](#0-2) 
Because the row-count query is bounded by `main_chain_index<=? AND +sequence='good' AND is_stable=1`, the visible row set for the same target unit can differ from one call to the next as the candidate `last_ball_mci` grows or as previously-non-final ("temp-bad"→"final-bad") sequence flags settle, whereas `validateDefinition()` only ever validates this invariant once, at definition-acceptance time. Any node that later re-evaluates the same address definition for a subsequent spending/authentifier unit is exposed to this diverging state and can hit the `throw`.

### Impact Explanation
Any full node that processes a unit whose author's address definition (or a nested `'address'`-referenced definition) contains a `'definition template'` clause whose referenced target unit's app=`definition_template` message count is not exactly 1 at validation time will crash with an uncaught exception. Since unit validation is performed identically by every full node in the network as part of normal DAG processing (this is not a peer-supplied malformed-unit case caught by `ifJointError`/`ifUnitError`, but a code path that bypasses those error channels entirely via `throw`), a single unprivileged unit poster can craft a definition-template-based address definition and a triggering spend that reliably makes every node that validates it crash, repeatedly if the crashed node restarts and re-processes the same unit from its queue. This matches the "network unable to confirm new units" outcome class: the affected unit (and any units depending on it) can never be validated to completion because the validating process aborts before it can call any of the `ifUnitError`/`ifJointError`/`ifOk` callbacks.

### Likelihood Explanation
Reachability requires only: (1) publishing an address definition that contains a `['definition template', [unit, params]]` node, and (2) causing that definition to be re-evaluated via `validateAuthentifiers` under different `last_ball_mci`/stability conditions than existed when it was first accepted by `validateDefinition`. Both steps are achievable by an ordinary unit poster with no special privileges, no malicious peer/hub involvement, and no reliance on network timing races beyond normal DAG growth. The main uncertainty is the precise scenario that produces a mismatched row count between the two evaluation times (e.g., interaction with delayed stabilization, sequence status changes from `temp-bad` to `final-bad`, or invalid/never-stabilizing referenced units), which would require live testing against the exact stabilization/sequence-transition logic to confirm with certainty; the code-level defect (unguarded `throw` in an async callback on the "hot" per-unit validation path, contrasted with the safe callback pattern in `validateDefinition`) is nonetheless clearly reachable and demonstrable in isolation.

### Recommendation
Replace the `throw Error("not 1 template")` in `validateAuthentifiers()`'s `'definition template'` case with the same safe handling used in `validateDefinition()`: call `cb2(false)` (or a defined error callback) when `rows.length !== 1`, and wrap the subsequent `JSON.parse`/`replaceInTemplate` calls in `try/catch` exactly as done in `validateDefinition()` at [4](#0-3) , so that any anomaly results in a normal validation failure (`ifUnitError`/`ifJointError`) rather than a process-crashing uncaught exception.

### Proof of Concept
1. Post unit A defining address ADDR with a definition `['definition template', [T, {p: 'v'}]]`, where T is a unit that currently has exactly one stable `app='definition_template'` message with `main_chain_index <= last_ball_mci(A)`. `validateDefinition()` accepts it (row count = 1).
2. Arrange for the visibility of `definition_template` rows for T to differ under a later `last_ball_mci` (e.g., through delayed stabilization or a `sequence` transition affecting whether the relevant row satisfies `+sequence='good' AND is_stable=1`) so that a subsequent spending unit B from ADDR is validated with `last_ball_mci(B)` at which the same query returns `rows.length !== 1`.
3. When any full node calls `validateAuthentifiers` for unit B (via `validation.js`'s signature-verification path), the `'definition template'` branch at [5](#0-4)  throws inside the async `conn.query` callback, producing an uncaught exception that crashes the node process instead of returning a normal validation error.

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
