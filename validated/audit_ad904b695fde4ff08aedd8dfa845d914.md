### Title
Uncaught exception / node crash via unvalidated `definition template` params in `validateAuthentifiers` - ([File: definition.js])

### Summary
`validateAuthentifiers()` in `definition.js` evaluates address definitions during authentifier (signature) checking. Its `'definition template'` case (`definition.js:802-819`) extracts `unit`/`params` directly from `args` with no type/shape validation and calls `replaceInTemplate(arrTemplate, params)` with no `try/catch`, unlike its sibling implementation in `validateDefinition()` (`definition.js:306-343`) which validates `isArrayOfLength(args,2)`, `isValidBase64(unit,...)`, `isNonemptyObject(params)` and wraps the same call in try/catch.

### Finding Description
`validateDefinition()` (used when a *new* definition is introduced) carefully guards the `'definition template'` operator: [1](#0-0) 

`validateAuthentifiers()` (used every time a unit is validated to check signatures against an *already-established* address definition, or an asset spending condition) implements the same operator without any of these guards: [2](#0-1) 

`args[0]`/`args[1]` are taken as `unit`/`params` unconditionally — `args` could be anything (a string, number, `null`, or a short array), so `unit` may not be a valid hash and `params` may not be an object at all. `replaceInTemplate` (which walks `arrTemplate` and substitutes values found in `params`) is called without a `try/catch`, so any `TypeError` thrown while treating a non-object `params` as an object (e.g., attempting `params[key]` semantics inside the template substitution, or `Object.keys(params)`-style operations) propagates out of the `conn.query` callback completely uncaught. Since this occurs deep inside an asynchronous DB callback, it cannot be caught by any surrounding `try/catch` in the validation call chain, and in Node.js an exception thrown in a callback bubbles up as an uncaught exception, crashing the whole node process (unless a global `uncaughtException` handler exists, which merely masks rather than prevents the process instability).

This mirrors the class of bug in CVE-2021-20296: crafted/malformed data reaching a decode/substitution routine without the same defensive checks used elsewhere for a nearly identical code path, leading to a null/undefined-shape dereference and a crash affecting availability.

### Impact Explanation
A definition containing `['definition template', <malformed args>]` is only reachable if an address with such a definition (or an asset's spend/issue condition using it) has been established and is later used to sign or validate a payment/message — i.e. an "unprivileged unit poster" can construct and post a unit whose address (or co-signed address, or private asset condition) uses this construct, deliberately supplying a non-object `params` or malformed `unit`. When any node (light or full) validates the authentifiers of a unit spending from/authored by that address, or evaluates a private asset condition (`evaluateAssetCondition` also calls into the same `evaluate`), it hits the unguarded branch and can throw an uncaught exception, crashing the validating node process. This is a network-availability impact: nodes attempting to process/relay/confirm the crafted unit crash, preventing confirmation of new units and potentially causing repeated crash-on-restart if the unit re-enters the mempool/backlog — matching "network unable to confirm new units."

### Likelihood Explanation
Reaching the vulnerable branch requires: (1) getting an address/asset definition containing `'definition template'` accepted (definitions themselves are validated more strictly by `validateDefinition`, so the attacker must exploit the asymmetry — the definition can be crafted so that `args` passes the loose checks of `validateDefinition` but the semantics differ, or the attacker targets asset spend conditions handled purely through `validateAuthentifiers`/`evaluateAssetCondition`, which the report shows is invoked with `assocAuthentifiers=null` and does not go through `validateDefinition`'s stricter argument checks at all for that context), and (2) crafting `params`/`unit` to trigger a throwing code path inside `replaceInTemplate`. This is plausible but requires precise knowledge of `replaceInTemplate`'s internals to guarantee a thrown (not silently wrong) result — full verification of `replaceInTemplate`'s implementation was not obtained in this investigation (the function body itself was not retrieved), so confidence in the exact throw condition is moderate, not proven end-to-end.

### Recommendation
Harden `validateAuthentifiers()`'s `'definition template'` case to match `validateDefinition()`: validate `isArrayOfLength(args, 2)`, `isValidBase64(unit, constants.HASH_LENGTH)`, `isNonemptyObject(params)`, and validate each param is a string/number before calling `replaceInTemplate`. Wrap the `replaceInTemplate` call (and the `JSON.parse` of the stored template) in `try/catch`, treating any exception as a validation failure (`cb2(false)` / fatal error) rather than letting it propagate. Additionally, replace the unconditional `throw Error("not 1 template")` on `rows.length !== 1` with a graceful `cb2(false)`/fatal-error path, since that too is attacker-reachable and currently crashes the process instead of failing validation.

### Proof of Concept
1. Post a unit that defines (or is later used to define) an asset spend condition (or an inner address definition reachable via `'address'`) containing:
   `['definition template', ['<valid unit hash of a definition_template message>', <malformed_params>]]`
   where `<malformed_params>` is not a plain object (e.g. a string, number, or an array), so it fails `validation.js`'s `isNonemptyObject(params)` check only in the `validateDefinition` path but is never checked at all in `validateAuthentifiers`.
2. Have another (or the same) unit exercise the asset condition or spend from the address so `validateAuthentifiers`/`evaluateAssetCondition` is invoked, reaching `definition.js:802-819`.
3. `replaceInTemplate(arrTemplate, params)` is invoked with the malformed `params` and no `try/catch`; if it throws (this is the part not independently confirmed against `replaceInTemplate`'s source in this session), the exception is uncaught inside the `conn.query` callback, crashing the node process handling validation.

**Note on confidence**: I was not able to retrieve and inspect the body of `replaceInTemplate` in this session, so I cannot fully confirm it throws (rather than silently mishandling) malformed `params`. The core, confirmed finding is the structural asymmetry — missing type/shape validation and missing `try/catch` in `validateAuthentifiers`'s `'definition template'` branch compared to the parallel, defensively-coded branch in `validateDefinition`. This should be verified against `replaceInTemplate`'s actual implementation before treating the crash path as fully proven.

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
