### Title
Unchecked `throw` on missing/duplicate `definition template` crashes signature validation - (File: definition.js)

### Summary
`validateAuthentifiers` in `definition.js` evaluates the `'definition template'` operator by querying for the referenced template unit and throwing an uncaught `Error` if the query does not return exactly one row, instead of returning a validation error like its sibling code path does.

### Finding Description
When an address definition (used by any unit author, including attacker-controlled ones) contains a `['definition template', ['unit', params]]` clause, `validateAuthentifiers` runs this handler: [1](#0-0) 
If the referenced `unit` does not have exactly one stable, good-sequence `definition_template` message at or before `last_ball_mci` (zero matches because the template was never posted/isn't stable yet, or more than one due to duplicate app messages), the code does `throw Error("not 1 template")` inside the `conn.query` callback instead of calling `cb2(false)`/returning an error. This is functionally analogous to the CVE: a lookup that can legitimately fail (`LookupModMask` returning NULL for an invalid virtual modifier) is used without a guard, and the unchecked failure path directly crashes the process instead of being handled as an invalid/rejected input.

Notably, the parallel code path for the *same* operator in `validateDefinition` (used when a new definition is being registered, rather than when verifying signatures) already handles this correctly: [2](#0-1) 
`validateDefinition` returns `cb("template not found or too many")`, showing the correct fix and confirming the throw in `validateAuthentifiers` is a genuine inconsistency/bug rather than an intentional invariant.

Because the throw happens inside an asynchronous `conn.query` callback, it cannot be caught by any synchronous `try/catch` in the caller chain. In Node.js this becomes an unhandled exception that propagates to the top of the event loop, crashing the node process (denial of service) for every full node that validates the offending unit.

### Impact Explanation
Any node (all full nodes performing normal unit validation, including hubs and standard clients) that processes a unit whose author is defined by, or that references, an address definition containing a `'definition template'` clause pointing at a unit lacking exactly one stable `definition_template` message will crash. Since address definitions and authentifier evaluation are checked for every incoming unit that any unprivileged party can post to the network, this is reachable by a single malicious/careless unit poster and causes a network-wide denial of service as nodes independently evaluate the same unit and crash — a "network unable to confirm new units" condition, not merely one operator's node.

### Likelihood Explanation
The trigger requires only: (1) posting an address definition with a `'definition template'` element referencing a specific `unit` hash, and (2) that unit either never having a stable `definition_template` app message, or having more than one (e.g., due to non-serial/conflicting units at the same MCI, or simply referencing a unit that legitimately has zero `definition_template` messages, e.g., any ordinary unit hash). Constructing such a reference is straightforward and requires no privileged access — any wallet/AA author/asset issuer path that resolves address definitions and evaluates authentifiers goes through this code. This makes the likelihood high once the code path is reached, since crafting the miscount condition is trivial (referencing an arbitrary or empty template unit).

### Recommendation
Change the `'definition template'` handling in `validateAuthentifiers` (definition.js, around line 811-812) to mirror `validateDefinition`'s behavior: replace `if (rows.length !== 1) throw Error("not 1 template");` with a graceful failure, e.g. `if (rows.length !== 1) return cb2(false);` (or propagate a validation error consistent with how other authentifier-evaluation branches signal failure), and wrap the subsequent `JSON.parse`/`replaceInTemplate` calls in try/catch as already done in `validateDefinition`.

### Proof of Concept
1. Craft an address definition `arrDefinition = ['definition template', ['<hash-of-any-unit-without-a-stable-definition_template-message>', {p:'v'}]]` (e.g. reference any ordinary payment unit's hash).
2. Post a unit whose author uses this address with `authentifiers` targeting a path that requires evaluating this definition (or an asset spending condition that reaches `pathIncludesOneOfAuthentifiers`).
3. When any full node validates the unit, `validateAuthentifiers` reaches the `'definition template'` branch in `definition.js` lines 802-818, the `conn.query` callback finds `rows.length === 0`, and executes `throw Error("not 1 template")` inside the async callback, crashing the validating node process.

### Citations

**File:** definition.js (L325-327)
```javascript
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
