Confirmed: the `definition_template` payload validation only checks that it's a 2-element array (`isArrayOfLength(payload, 2)`) at [1](#0-0) , with no restriction on nesting depth of the array/object structure it contains, other than the overall unit size limit (`MAX_UNIT_LENGTH`). This means an attacker can craft a payload that is small in byte size but deeply nested (e.g. thousands of nested single-element arrays), which stays under the unit size cap while producing an unbounded-recursion structure.

### Title
Unbounded recursion in `replaceInTemplate`/`replaceInVar` during `definition template` evaluation causes uncaught stack-overflow DoS - (File: definition.js)

### Summary
`replaceInTemplate` recursively walks an attacker-supplied, previously-posted `definition_template` payload with no depth limit, and any thrown `RangeError` (stack overflow) is deliberately re-thrown rather than turned into a validation error, crashing the node process that is validating any unit referencing the template.

### Finding Description
The `definition template` operator in an address/asset spending-condition definition lets any unit reference a previously stored `app='definition_template'` message: `['definition template', [unit, params]]` [2](#0-1) . When such a definition is evaluated, the referenced template payload is fetched and expanded via `replaceInTemplate(arrTemplate, params)` [3](#0-2) .

`replaceInTemplate` calls the recursive helper `replaceInVar`, which recurses into every array element / object property with no depth or size limit at all: [4](#0-3) .

The only validation ever performed on a `definition_template` payload before it is persisted is that it is a 2-element array: [1](#0-0)  and, for AA-embedded templates, the same shallow check [5](#0-4) . Nothing bounds how deeply the array/object can be nested. Because JSON/array nesting is cheap to encode (`[[[[[...]]]]]`), an attacker can produce many thousands of nesting levels while staying comfortably under `MAX_UNIT_LENGTH`.

Crucially, the call site wraps `replaceInTemplate` in a `try { ... } catch(e) { if (e instanceof NoVarException) ... else throw e; }` [6](#0-5) . A JS engine stack overflow throws a `RangeError`, not a `NoVarException`, so it is explicitly re-thrown by `throw e;`. This throw happens inside a `conn.query` result callback (an async/DB callback context), so it is not caught by any surrounding validation error-handling logic and propagates as an uncaught exception, which by default crashes the Node.js process. The second call site, used during authentifier evaluation, does not even have a try/catch around `replaceInTemplate` at all [7](#0-6) , so the same unhandled `RangeError` occurs there too.

Note also that `evaluate()` in `validateDefinition` does enforce `MAX_COMPLEXITY`/`MAX_OPS` limits on the *definition op tree* itself [8](#0-7) , but this protection only applies after `replaceInTemplate` has already returned — it does not protect the template-expansion step, which is where the unbounded recursion actually happens.

### Impact Explanation
Any node that validates a unit using a `['definition template', ...]` clause referencing a maliciously deep template will crash with an uncaught `RangeError` (stack overflow), analogous to the NASM `expand_mmac_params` stack-use-after-scope DoS triggered by a crafted, deeply-nested macro-expansion input. Because template definitions are reachable both from ordinary address definitions and from wallet multi-device definition templates (`wallet_defined_by_keys.js`'s `validateWalletDefinitionTemplate`, also calling `Definition.replaceInTemplate` unguarded for `RangeError` [9](#0-8) ), and from the authentifier-evaluation path with no try/catch at all, this is reachable by an unprivileged unit poster and can cause every full node that processes/validates the referencing unit to crash — a network-wide denial-of-service on confirming new units, not merely a resource-exhaustion slowdown.

### Likelihood Explanation
An attacker needs only two ordinary, unprivileged actions: (1) post a stable `definition_template` message containing a deeply nested array/object structure, and (2) post a second unit whose address (or asset) definition references that template via `['definition template', [template_unit, params]]`. Both steps use standard, publicly available message types with only shallow structural validation (array-length-2 check), so crafting the payload requires no special privileges — only patience for step (1) to stabilize. This makes the analog highly likely to be reachable by any poster.

### Recommendation
Add an explicit recursion-depth (and/or total node count) limit inside `replaceInVar` in `definition.js`, throwing a normal validation error (e.g., a `NoVarException`-like typed error) when the limit is exceeded instead of letting a `RangeError` escape. Additionally, wrap the second (authentifier-evaluation) call site of `replaceInTemplate` in `definition.js` (~line 815) in the same try/catch used at the first site, and make sure a caught `RangeError` from `replaceInTemplate`/`replaceInVar` is converted into a normal validation failure (`cb("template too deeply nested")`) rather than being re-thrown.

### Proof of Concept
1. Construct a deeply nested `definition_template` payload, e.g. `['and', [X.repeat(N) with N ~ 50,000 nested one-element wrapper arrays]]` (or any array/object nesting depth sufficient to exceed the JS call stack, e.g. an array nested tens of thousands of levels deep, each level tiny in byte size so the whole unit stays under `MAX_UNIT_LENGTH`).
2. Post this as a unit with `app: 'definition_template', payload: <deeply nested 2-element array>` and wait for it to become stable.
3. Post a second unit whose address definition (or asset spending condition) is `['definition template', [<template_unit>, {some_param: 'value'}]]`.
4. When any node validates this second unit, `validateDefinition`'s `definition template` case calls `replaceInTemplate(arrTemplate, params)` [3](#0-2) , which recurses to the crafted depth in `replaceInVar` [10](#0-9)  and throws `RangeError: Maximum call stack size exceeded`, which is re-thrown unhandled at line 338, crashing the validating node process.

### Citations

**File:** validation.js (L2003-2009)
```javascript
		case "definition_template":
			if (objValidationState.bHasDefinitionTemplate)
				return callback("can be only one definition template");
			objValidationState.bHasDefinitionTemplate = true;
			if (!ValidationUtils.isArrayOfLength(payload, 2))
				return callback(objMessage.app+" payload must be array of two elements");
			return callback();
```

**File:** definition.js (L103-111)
```javascript
	function evaluate(arr, path, bInNegation, cb){
		complexity++;
		count_ops++;
		if (complexity > constants.MAX_COMPLEXITY)
			return cb("complexity exceeded at "+path);
		if (count_ops > constants.MAX_OPS)
			return cb("number of ops exceeded at "+path);
		if (objValidationState.max_complexity && objValidationState.complexity + complexity > objValidationState.max_complexity)
			return cb(`custom complexity limit ${objValidationState.max_complexity} exceeded at ${path}`);
```

**File:** definition.js (L306-313)
```javascript
			case 'definition template':
				// ['definition template', ['unit', {param1: 'value1'}]]
				if (objValidationState.bNoReferences)
					return cb("no references allowed in address definition");
				if (!isArrayOfLength(args, 2))
					return cb("2-element array expected in "+op);
				var unit = args[0];
				var params = args[1];
```

**File:** definition.js (L328-339)
```javascript
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

**File:** aa_validation.js (L425-429)
```javascript
				case 'definition_template':
					if (!ValidationUtils.isArrayOfLength(payload, 2))
						return cb2("AA definition_template must be array of two elements");
					cb2();
					break;
```

**File:** wallet_defined_by_keys.js (L502-507)
```javascript
	try{
		var arrFakeDefinition = Definition.replaceInTemplate(arrWalletDefinitionTemplate, params);
	}
	catch(e){
		return handleResult(e.toString());
	}
```
