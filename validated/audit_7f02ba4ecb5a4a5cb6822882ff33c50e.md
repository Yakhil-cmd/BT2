### Title
Unbounded recursive template expansion in `replaceInTemplate` causes stack-overflow DoS during address/asset definition validation - ([File: definition.js])

### Summary
`replaceInTemplate` (and its inner `replaceInVar`) in `definition.js` recursively walks an attacker-controlled JSON structure (a previously posted `definition_template` message payload) with no depth limit, no complexity counter, and no call-stack-yielding mechanism, unlike every other recursive evaluator in the same file (`evaluate()` in `validateDefinition`/`validateAuthentifiers`, which enforces `constants.MAX_COMPLEXITY`/`MAX_OPS`). This mirrors the YASM `expand_mmac_params` bug class: unbounded recursive expansion of macro/template parameters leading to a crash (stack exhaustion) rather than a controlled parse error.

### Finding Description
`definition_template` messages are validated only for being a 2-element array, with no depth or size constraint on the nested structure: [1](#0-0) 

An address (or asset) definition can reference this stored template via the `definition template` operator, fetch it from the DB, and expand it with attacker-supplied `params`: [2](#0-1) [3](#0-2) 

The expansion itself is done by `replaceInTemplate`/`replaceInVar`, which recurses into every array element and object key of the template with **no depth check, no counter, and no `setImmediate`/`setTimeout` stack-unwind** — unlike the sibling `evaluate()` functions in the same file that increment `complexity`/`count_ops` and bail out once `constants.MAX_COMPLEXITY`/`MAX_OPS` is exceeded: [4](#0-3) [5](#0-4) 

Because a deeply-nested array template (e.g. `[[[[...]]]]`) grows only ~2 bytes per nesting level, an attacker can post one moderately-sized `definition_template` unit with thousands of nesting levels while staying under normal unit/message size limits, then trigger the unbounded recursion by referencing it from a `definition template` op in any address definition or AA nested definition evaluation path. This crashes the Node.js process validating the unit ("Maximum call stack size exceeded"), which is an unrecoverable exception in this codebase (not a catchable validation error), taking down the validating node.

The codebase's own test suite acknowledges this exact recursion hazard for formula ASTs (`test/formula.test.js` "deeply nested array/dictionary/max/if" tests) and mitigates it there with periodic `setImmediate` yields and depth caps in `formula/validation.js` and `formula/evaluation.js`: [6](#0-5) [7](#0-6) 
No equivalent protection exists for `replaceInTemplate`.

### Impact Explanation
A crash of the recursive `replaceInVar` call (uncaught `RangeError: Maximum call stack size exceeded`) is not caught by any `try/catch` in `validateDefinition`; it propagates and terminates the validating process. Since every full node/hub must validate every incoming unit's address definitions (including nested `definition template` references), a single crafted unit referencing a maliciously deep template can crash any node that attempts to validate it — a network-wide denial of service that prevents confirmation of new units on affected nodes, matching the "network unable to confirm new units" impact bar.

### Likelihood Explanation
Reachable by any unprivileged user: (1) post a `definition_template` message with a deeply nested array/object payload (only checked to be a 2-element array), get it confirmed/stable; (2) post any unit whose author/asset definition contains `['definition template', [template_unit, params]]` referencing it. No special privileges, hub cooperation, or peer compromise required — purely a self-authored posted-unit attack, consistent with the allowed threat model (unprivileged unit poster / asset issuer).

### Recommendation
Add a depth (and/or node-count) limit to `replaceInTemplate`/`replaceInVar`, mirroring the `MAX_DEPTH`/complexity guards used elsewhere in `definition.js` and `aa_validation.js` (e.g., reuse `isTooDeeplyNestedOrHasTooManyNodes` from `string_utils.js`, which already implements this check, to validate the fetched template before expansion), returning a normal validation error instead of recursing unbounded. Additionally consider capping nesting depth in `definition_template` payload validation in `validation.js` (case `"definition_template"`) at write time, not only at reference time.

### Proof of Concept
1. Attacker posts a `definition_template` message with payload `['and', [depth-N nested array structure]]` where N (e.g. 50,000) is large enough to exhaust the V8 stack, but total serialized size stays within normal unit-size limits since each nesting level adds ~2 bytes.
2. Once the template unit is stable, attacker (or anyone) posts a unit whose address/asset definition (or nested AA definition) includes `['definition template', [template_unit_hash, {}]]`.
3. When any node validates this second unit, `evaluate()` in `definition.js` hits the `'definition template'` case, loads the payload, and calls `replaceInTemplate(arrTemplate, params)` → `replaceInVar` recurses N levels deep with no bound, crashing the process with a stack overflow before validation can reject the malformed/oversized structure.

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

**File:** definition.js (L306-341)
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

**File:** formula/validation.js (L272-288)
```javascript
	function evaluate(arr, cb, bTopLevel) {
		count++;
		if (count % 100 === 0) // avoid extra long call stacks to prevent Maximum call stack size exceeded
			return (typeof setImmediate === 'function') ? setImmediate(evaluate, arr, cb) : setTimeout(evaluate, 0, arr, cb);
		depth++;
		const orig_cb = cb;
		cb = err => {
			depth--;
			if (err && !errorLocation && arr && typeof arr === 'object' && arr.line !== undefined) {
				errorLocation = arr.source_location
					? Object.assign({}, arr.source_location)
					: { line: arr.line };
			}
			orig_cb(err);
		};
		if (depth > 100 && (mci >= constants.pemCurvesFixMci || require('../storage.js').getMinRetrievableMci() >= constants.pemCurvesFixMci))
			return cb("maximum depth exceeded");
```

**File:** test/formula.test.js (L6415-6425)
```javascript
test.cb('deeply nested array', t => {
	var trigger = { data: { q: { a: 6 } } };
	var stateVars = {};
	const depth = 2000;
	evalFormulaWithVars({ conn: db, formula: `${'['.repeat(depth)}1${']'.repeat(depth)}`, trigger: trigger, locals: {  }, stateVars: stateVars,  objValidationState: objValidationState, address: 'MXMEKGN37H5QO2AWHT7XRG6LHJVVTAWU'}, (res, complexity, count_ops) => {
		t.deepEqual(res, null);
	//	t.deepEqual(complexity, 1);
	//	t.deepEqual(count_ops, depth + 1);
		t.end();
	})
});
```
