### Title
Remote unauthenticated node crash via unhandled `throw` in `definition template` evaluation - (File: definition.js)

### Summary
The Subversion bug crashes `mod_authz_svn` when a client requests a resource that doesn't exist while a relative-access-file lookup is in progress, because the missing-resource case isn't handled gracefully and triggers a fatal fault. The analogous defect in ocore is in the `'definition template'` operator of `validateAuthentifiers`, where a lookup for a referenced template unit that does not exist (or is not a valid, unique `definition_template` message) results in an uncaught `throw Error(...)` deep inside an async database callback instead of a graceful validation failure, crashing the node process.

### Finding Description
When an address definition contains the operator `['definition template', [unit, params]]`, evaluation looks up the referenced `unit` in the `messages`/`units` tables for a `definition_template` app message: [1](#0-0) 

If the referenced unit does not exist, is not stable/good, or does not carry exactly one qualifying `definition_template` payload, `rows.length !== 1` and the code executes `throw Error("not 1 template")` inside the `conn.query` callback. This throw is not wrapped in a `try/catch` and is not routed through the `cb2`/`callback` error-handling chain used everywhere else in `validateAuthentifiers`. Because this happens inside an asynchronous database callback, the exception becomes an unhandled exception at the process level (not just a rejected promise or a caught synchronous error), which crashes the Node.js process running the full node.

This code path is reached whenever a unit author signs using (or a new unit defines) an address definition containing the `'definition template'` op and that definition is evaluated against a template unit reference chosen entirely by the unit's author — an attacker fully controls the `unit` argument, and can point it at:
- A unit hash that does not exist in the DAG at all, or
- An existing unit that has no `definition_template` message, or
- A unit whose `main_chain_index` is not yet `<= last_ball_mci` / not stable / not `sequence='good'`.

Any of these trivially satisfiable conditions (from an unprivileged unit poster) drives `rows.length` to `0`, hitting the `throw`.

Contrast this with the neighboring `'address'` case in the same `evaluate` function, which correctly handles the "not found" case via an `ifDefinitionNotFound` callback path instead of throwing: [2](#0-1) 

### Impact Explanation
An unauthenticated/unprivileged actor (any unit poster) can craft and broadcast a unit whose author definition (or a co-author's inline definition) contains a `'definition template'` operator referencing a non-existent or otherwise disqualifying unit hash. When any full node validates this unit (which happens automatically as part of normal DAG processing for every peer that receives the unit), the node throws an uncaught exception and crashes. This is a remote, unauthenticated denial-of-service: a single malicious unit can crash every full node that processes it, potentially halting the network's ability to confirm new units if propagated widely — directly matching the "network unable to confirm new units" impact class.

### Likelihood Explanation
Likelihood is high: constructing the malicious payload requires no special privileges, no valid template unit, and no prior asset/AA setup — merely referencing an arbitrary unit hash for a `unit` composed with `['definition template', [<hash>, {}]]` inside an address definition (author's own definition or in an inline co-author definition, since `objAuthor.definition` accepts an array to `validateAuthentifiers`/`validateDefinition`). No prior structural check in `validateDefinition`'s `evaluate` catches the missing-template condition ahead of time, so the flaw is exercised on the very first validation of the unit by any receiving node.

### Recommendation
Replace the `throw Error("not 1 template")` with a graceful validation failure routed through `cb2`/`fatal_error`, consistent with how other lookup failures (e.g., the `'address'` case's `ifDefinitionNotFound`) are handled. For example, when `rows.length !== 1`, call `cb2(false)` (or set an appropriate `fatal_error`/`callback(err)`), and only proceed to `JSON.parse`/`replaceInTemplate` when exactly one valid template row is found. Ensure the same graceful handling exists both in `validateDefinition`'s structural evaluation (if it processes this op) and in `validateAuthentifiers`'s evaluation path.

### Proof of Concept
1. Attacker composes an address whose definition is:
```json
["definition template", ["NONEXISTENT_UNIT_HASH_BASE64_32BYTES", {}]]
```
2. Attacker posts a unit signed by an author using this definition (either as the address's registered definition or as an inline `author.definition` for a fresh address), satisfying all other structural checks in `validateDefinition` (which does not reach into the database to check template existence at structural-validation time for this op in the same fail-fast way).
3. When any node calls `validateAuthentifiers` → `evaluate` on this definition to verify the author's signature, it hits the `'definition template'` case at [3](#0-2)  and queries for a `definition_template` message on `NONEXISTENT_UNIT_HASH_BASE64_32BYTES`.
4. Since no such unit/message exists, `rows.length === 0`, and the code executes `throw Error("not 1 template")` inside the `conn.query` callback, producing an unhandled exception that crashes the validating node's process.

Note: I was unable to execute this against a live node in this environment; the analysis is based on static code review of the cited files/functions. A background Devin session with runtime access could confirm the crash empirically by submitting a unit as described to a local testnet node.

### Citations

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
