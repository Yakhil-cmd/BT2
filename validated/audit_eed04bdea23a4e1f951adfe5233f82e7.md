### Title
Unbounded Recursive Template Expansion in `replaceInTemplate()` Causes Stack-Exhaustion DoS - (File: definition.js)

### Summary
`Definition.replaceInTemplate()` recursively walks an entire template structure (`arrTemplate`) to substitute `$param` placeholders, with **no depth limit and no complexity/op accounting**, unlike the sibling `evaluate()` function that enforces `MAX_COMPLEXITY`/`MAX_OPS`. The template content is attacker-supplied (a previously-posted `definition_template` message payload), so an unprivileged unit poster can reach unbounded native call-stack recursion, mirroring the ImageMagick `DestroyXMLTree()` unbounded-recursion bug class (JLSEC-2026-998).

### Finding Description
When an address definition contains a `'definition template'` operator, `evaluate()` in `definition.js` loads the stored template payload and calls `replaceInTemplate(arrTemplate, params)` *before* re-entering the depth/complexity-checked `evaluate()`: [1](#0-0) 

`replaceInTemplate` recurses into every array element / object property of `arrTemplate` with `replaceInVar`, with no depth counter, no `MAX_DEPTH`, and no `count`/`setImmediate` stack-unwinding technique that other recursive evaluators in this codebase use: [2](#0-1) 

Contrast this with the sibling `evaluate()` function, which enforces `MAX_COMPLEXITY`/`MAX_OPS` on every recursive step and is the mechanism that actually bounds `and`/`or`/`r of set` nesting depth: [3](#0-2) [4](#0-3) [5](#0-4) 

`replaceInTemplate` is invoked *prior to* this complexity gate, so a template whose raw JSON structure is deeply nested (e.g., thousands of nested arrays) will exhaust the JS call stack purely inside `replaceInVar`, regardless of how small `MAX_COMPLEXITY` is. The call site wraps this in a `try/catch` that only recognizes its own `NoVarException`; any other exception, including the `RangeError: Maximum call stack size exceeded` produced by the recursion, is deliberately re-thrown: [6](#0-5) 

Because this call happens inside an asynchronous `conn.query` callback, the re-thrown error becomes an unhandled exception outside of any `try/catch` the caller can intercept, which crashes the Node.js process handling unit validation.

The same unbounded `replaceInTemplate` call is also reachable from the wallet/device shared-address flow, when a paired device sends an address-definition template to set up a shared/multisig address: [7](#0-6) 

### Impact Explanation
A successful exploitation crashes the node process performing validation (via an unhandled `RangeError` inside an async callback), which stops that node from validating/confirming any further units. If triggered broadly (e.g., embedded in an address used across the network, or sent to many hubs/wallets), this can cause a **network unable to confirm new units** — matching the accepted impact categories. It is a pure availability (DoS) issue with no confidentiality/integrity impact, analogous to the CVSS 7.5 (`AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`) rating of the reference advisory.

### Likelihood Explanation
Reachability requires only:
1. Posting (or having previously posted/stable) a `definition_template` message with a deeply nested JSON payload — no special privilege needed, any unit poster can create this message type, bounded only by `MAX_UNIT_LENGTH` (5 MB), which comfortably permits hundreds of thousands of nesting levels.
2. Posting (or having a peer post) an address definition or device-shared-address template that references this template via the `'definition template'` operator with any valid `params`.

Both steps are available to a normal, unprivileged unit poster / AA author / paired device, satisfying the "unprivileged reachability" requirement. No malicious peer/hub/network-layer assumption is needed — the trigger is fully contained in application-level parsing of unit/message content.

### Recommendation
Add an explicit depth counter (mirroring the `MAX_DEPTH` pattern already used in `aa_validation.js` and the `depth > 100` check in `formula/validation.js`) to `replaceInVar`/`replaceInTemplate`, rejecting templates that exceed a small fixed nesting depth before recursing. Additionally, ensure any `RangeError` (stack overflow) thrown from this code path is caught and converted into a normal validation failure (`cb("template too deep")`) rather than being re-thrown as an unhandled exception in an async context.

### Proof of Concept
1. Post a `definition_template` message whose `payload` is a deeply nested array structure that itself contains a `$param` placeholder, e.g. programmatically build `payload = nest(50000, ['$deep'])` (50,000 levels of `['and', [ ... ]]`-shaped nesting or plain arrays) and get it included/stable.
2. From another unit (or address definition, or a `shared_address` device message per `wallet_defined_by_addresses.js`), reference it: `['definition template', [<hash_of_step1_unit>, {deep: 'anything'}]]`.
3. When any node evaluates this definition (e.g., during `validateDefinition`/`validateAuthentifiers`, or `validateAddressDefinitionTemplate` for shared addresses), `replaceInTemplate` recurses 50,000 levels deep in `replaceInVar` before any complexity check applies, throwing `RangeError: Maximum call stack size exceeded`, which is re-thrown out of the `conn.query` async callback and crashes the process. [2](#0-1) [8](#0-7)

### Citations

**File:** definition.js (L103-113)
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
		if (!isArrayOfLength(arr, 2))
			return cb("expression must be 2-element array");
```

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

**File:** constants.js (L58-58)
```javascript
exports.MAX_COMPLEXITY = process.env.MAX_COMPLEXITY || 100;
```

**File:** constants.js (L67-67)
```javascript
exports.MAX_OPS = process.env.MAX_OPS || 2000;
```

**File:** wallet_defined_by_addresses.js (L503-508)
```javascript
	try{
		var arrFakeDefinition = Definition.replaceInTemplate(arrDefinitionTemplate, params);
	}
	catch(e){
		return handleResult(e.toString());
	}
```
