### Title
Unguarded `definition template` param-type forwarding in `validateAuthentifiers` enables non-string/number values to be spliced into inner address definitions - (File: definition.js)

### Summary
`definition.js` implements the `definition template` op twice: once inside `validateDefinition()`'s `evaluate()` (used to statically validate a definition tree) and once inside `validateAuthentifiers()`'s `evaluate()` (used at spend/authentication time to actually walk the tree and check signatures). The `validateDefinition` copy guards the template-fill inputs; the `validateAuthentifiers` copy forwards `args`/`params` to `replaceInTemplate()` completely unguarded, mirroring the GitPython pattern where one code path (`clone`) got an unsafe-option denylist and a sibling path (`init`) with the same dangerous sink never received the same guard.

### Finding Description
In `validateDefinition()`, the `'definition template'` handler validates its inputs before use: it requires `args` to be a 2-element array, `unit` to be a valid 44-byte base64 hash, `params` to be a non-empty object, and — critically — that **every value in `params` is a string or number**, before calling `replaceInTemplate(arrTemplate, params)`: [1](#0-0) 

The sibling implementation in `validateAuthentifiers()`'s inner `evaluate()` performs none of these checks. It reads `unit` and `params` straight from `args` and passes `params` directly into `replaceInTemplate()`: [2](#0-1) 

`replaceInTemplate()` / `replaceInVar()` recursively substitutes `"$name"` placeholders in the template with whatever value is stored in `params[name]`, and explicitly allows the substituted value to change the type of the node ("may change type if params[name] is not a string"), then feeds the result straight back into `evaluate()` as a definition sub-tree: [3](#0-2) 

`validateAuthentifiers()` does call `validateDefinition()` first on the *top-level* `arrDefinition`, which is expected to have already caught bad params for templates reachable directly from the top of that same tree: [4](#0-3) 

However, this front-line check is not guaranteed to cover every tree that `validateAuthentifiers`'s own `evaluate()` will actually walk at spend time. Specifically, the `'address'` case in `validateAuthentifiers` (unlike in `validateDefinition`) fetches the *current, possibly-updated* on-chain definition of a referenced address via `storage.readDefinitionByAddress` and evaluates it directly, without re-running it through `validateDefinition`'s checks: [5](#0-4) 

An inner address's definition can change over time (key change / redefinition), and templates referenced from within it are only checked by whatever validation ran when that inner definition itself was authored — but the `'definition template'` case that actually executes during signature verification is the unguarded one. This is architecturally identical to the reported GitPython bug: two methods share the same dangerous sink (git init options / `replaceInTemplate`), one has a denylist/guard, the other — reachable independently — does not.

### Impact Explanation
If a param value of a non-string/non-number type (e.g., an object, array, or boolean) is spliced into a definition subtree at authentication time, `replaceInVar` will silently allow it because it only checks `typeof x` for `'number'|'boolean'|'string'|'object'` and falls through to structural recursion for `'object'`. This can let a spending condition's *shape* (not just its values) be altered by unauthenticated template parameters when the surrounding definition is evaluated via `validateAuthentifiers` rather than freshly validated via `validateDefinition`, potentially producing a definition tree that was never subjected to the full structural checks (`hasFieldsExcept`, `isPositiveInteger`, etc.) that `validateDefinition` enforces elsewhere. This could allow an address's effective spending condition to diverge from what was validated when the definition was authored, i.e. unauthorized spending or a node-disagreement/double-spend scenario if different nodes evaluate the same referenced definition_template payload differently.

### Likelihood Explanation
Reaching this path requires an address whose definition uses `['address', other_address]` referencing another address whose *own* definition uses `['definition template', ...]`, combined with the referenced address's definition being re-validated only via `validateAuthentifiers` and not `validateDefinition` at the time of the parent unit's authentication. This requires a specific, non-trivial DAG state to construct (definition redefinition timing), consistent with the "High complexity" precondition profile in the analogous GHSA report. It does not require a malicious node/peer — it is reachable by any unit poster who controls address definitions, satisfying the scope constraint.

### Recommendation
Add the same denylist/validation guard used in `validateDefinition`'s `'definition template'` case to the `'definition template'` case inside `validateAuthentifiers`: verify `isArrayOfLength(args, 2)`, `isValidBase64(unit, ...)`, `isNonemptyObject(params)`, and that every `params[key]` is a `string` or `number`, before calling `replaceInTemplate`. Alternatively, factor the single implementation out into a shared helper used by both `evaluate()` functions so the guard cannot drift out of sync again.

### Proof of Concept
Conceptual reproduction (requires DAG state construction, not verified end-to-end due to tool limitations):
1. Post a `definition_template` unit whose template body is a `dictionary`/structural node containing `"$x"` placeholders that are consumed positionally as part of an `and`/`or` structure.
2. Define address A with definition `['definition template', [template_unit, {x: <string>}]]` — this passes `validateDefinition` at authoring time because `x` is a string.
3. Define address B with `['address', A]`.
4. Redefine A (key change) such that the template reference is now evaluated through `validateAuthentifiers`'s `'address'` case for B's unit, at a point where A's template parameters could structurally differ (e.g., object instead of string) without going back through `validateDefinition`'s param-type guard.
5. Because `definition.js:802-819` skips the `typeof params[key] !== "string" && typeof params[key] !== "number"` check, an object/array value is spliced into the tree and evaluated, potentially satisfying a spending condition that would have been rejected under `validateDefinition`.

This is presented as an architectural/code-path analog to the reported CWE-88/94 pattern (missing guard on a sibling code path sharing the same dangerous sink); full exploitability could not be conclusively demonstrated with the available static analysis and would require dynamic DAG-state testing to confirm reachability of the divergent-validation window.

### Citations

**File:** definition.js (L306-320)
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

**File:** definition.js (L1454-1465)
```javascript
	validateDefinition(conn, arrDefinition, objUnit, objValidationState, arrAuthentifierPaths, bAssetCondition, function(err){
		if (err)
			return cb(err);
		//console.log("eval def");
		evaluate(arrDefinition, 'r', function(res){
			if (fatal_error)
				return cb(fatal_error);
			if (!bAssetCondition && arrUsedPaths.length !== Object.keys(assocAuthentifiers).length)
				return cb("some authentifiers are not used, res="+res+", used="+arrUsedPaths+", passed="+JSON.stringify(assocAuthentifiers));
			cb(null, res);
		});
	});
```

**File:** definition.js (L1468-1495)
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
```
