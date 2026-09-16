Found it: `definition.js` contains two implementations of the `definition template` opcode. The structural-validation path (`validateDefinition`, used when the definition is first created/checked) correctly handles the "not found" case by returning a soft error: [1](#0-0) 

But the authentifier/spending path (`validateAuthentifiers`, invoked every time the address is used to sign/authorize a payment) has an unchecked assumption that the row will always exist, and instead of returning an error it throws an uncaught exception: [2](#0-1) 

### Title
Unchecked Query-Result Assumption Leads to Uncaught Exception / Node Crash in `definition template` Authentifier Evaluation - (File: definition.js)

### Summary
`validateAuthentifiers()`'s `evaluate()` handles the `'definition template'` opcode by querying for the referenced `definition_template` message and directly assuming exactly one row is returned. If zero or more than one row is returned, the code does `throw Error("not 1 template")` inside an asynchronous `conn.query` callback instead of calling `cb2` with an error. This is the deserialization/return-value-unchecked class of bug from the reported advisory (parser code trusts an implicit invariant about parsed/queried data without validating it, and dereferences/uses it directly), here manifesting not as a null-pointer read but as an unhandled `throw` inside a DB callback that is not wrapped in a `try/catch` by any caller in the async chain, crashing the whole Node process.

### Finding Description
`storage.readDefinitionByAddress`/direct `conn.query` calls in `validateAuthentifiers` (definition.js:806-818) assume the `definition_template` message referenced by a `['definition template', [unit, params]]` clause is always present and unique at validation time. This assumption can be broken by an attacker in two ways:
1. The `unit` becomes non-stable or is voided/reorganized between when the definition was accepted (structural validation via `validateDefinition`, which correctly checks `rows.length !== 1` and returns a soft error at definition.js:326-327) and later when the same definition is evaluated during spending (`validateAuthentifiers`, definition.js:811-812).
2. Because address definitions are cached and re-evaluated on every subsequent unit that spends from that address (see comment at definition.js:1449-1453: "we need to re-validate the definition every time... in case a referenced address was redefined"), any single low-mci fork, delayed stabilization, or unit posted while the referenced template is only temporarily/differently stable can make the same `WHERE ... is_stable=1 AND sequence='good'` query return 0 or >1 rows during later validation, even though it returned exactly 1 row at creation time.

When that happens, `throw Error("not 1 template")` is executed inside the `conn.query` callback. This throw is not caught anywhere in the async call chain (`validateAuthentifiers` → `evaluate` → `conn.query` callback), so it propagates as an uncaught exception, terminating the Node.js process for any full node or hub that attempts to validate a unit spending from such an address definition.

### Impact Explanation
Any unprivileged unit poster who creates (or is a co-signer of) an address whose definition contains a `'definition template'` clause can later trigger this crash by causing the referenced `definition_template` unit's stability/sequence state to differ from what it was when the outer definition was structurally validated — for example, by exploiting normal DAG reorg/late-stabilization behavior, or simply by controlling the timing of stabilization of the two related units. This is a network-wide denial-of-service: any node (validator) that processes such a spending unit crashes, matching the "network unable to confirm new units" impact bar for this analysis (validating nodes going down stops confirmation), and is reachable purely from posted units — no privileged/hub/peer role required.

### Likelihood Explanation
Likelihood is moderate-to-high: the attacker fully controls the address definition (can embed `'definition template'`), fully controls the referenced template unit, and can control the ordering/timing of stabilization of the template unit relative to the defining and spending units. No cryptographic secrets or special network position are required — this is achievable by a normal wallet composing units.

### Recommendation
In `validateAuthentifiers`'s `evaluate()` for the `'definition template'` case (definition.js:802-818), replace `throw Error("not 1 template")` with a graceful failure path consistent with `validateDefinition`'s handling (definition.js:326-327), e.g. `return cb2(false)` (or the pattern used elsewhere in this function to signal condition-not-satisfied) instead of throwing. This avoids crashing the process on malformed/changed state and instead just fails signature validation for that authentifier path.

### Proof of Concept
1. Attacker creates address `A` with definition `['and', [['sig', {...}], ['definition template', [T, {p:'v'}]]]]` where `T` is a unit containing a `definition_template` message; at the time of `A`'s definition being accepted, `T` is stable and unique (passes `validateDefinition`'s check at definition.js:321-327).
2. Attacker arranges for `T`'s stability/sequence state (e.g., via a fork that causes `T` to be temporarily non-final, or by having two competing units at the same location) so that at a later mci, the query `SELECT payload FROM messages JOIN units USING(unit) WHERE unit=? AND app='definition_template' AND main_chain_index<=? AND sequence='good' AND is_stable=1` returns `rows.length !== 1` for the same `unit` value.
3. Attacker posts a new unit spending from address `A`, which triggers `validateAuthentifiers` → `evaluate` → the `'definition template'` case in definition.js:802-818.
4. `rows.length !== 1` is true, and `throw Error("not 1 template")` executes inside the async DB callback, which is unhandled, crashing the validating node's process.

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

**File:** definition.js (L802-818)
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
```
