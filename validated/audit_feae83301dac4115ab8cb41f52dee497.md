## Finding

An unprivileged AA author can embed formula strings of unbounded length inside an AA's `messages`/`init`/getters (only the address-definition `'formula'` opcode has an explicit length cap), and these strings are fed directly into the nearley Earley parser during AA-definition validation, a process with known worst-case cubic (O(n³)) time complexity for ambiguous grammars.

### Title
Unbounded formula length in AA definitions causes CPU-exhaustion DoS during oscript parsing - (File: aa_validation.js, formula/validation.js, formula/evaluation.js)

### Summary
`definition.js` caps formula length at 10000 characters for the address-definition `'formula'` opcode [1](#0-0) , but the equivalent length check is absent for formulas used inside AA `messages`, `if`/`init` expressions and `getters`, which are validated via `aa_validation.js`'s `validate()`/`validateDefinition()` and ultimately parsed by `formula/validation.js` and `formula/evaluation.js` using the same nearley grammar [2](#0-1) . Because AA-definition units are still bounded only by the generic `MAX_UNIT_LENGTH` (5,000,000 bytes) rather than by a formula-specific limit, an attacker can post a single AA-defining unit containing a multi-hundred-KB to multi-MB formula string that every validating node must run through the nearley `Parser.feed()` call [3](#0-2) [4](#0-3) .

### Finding Description
- The `'formula'` opcode inside address definitions explicitly checks `args.length > 10000` and rejects it as "formula too long" [1](#0-0) .
- No analogous length check exists in `aa_validation.js`'s AA-definition walk (`validate()`), which recursively finds every string field that parses as a formula (`getFormula(value)`) and calls `validateFormula` regardless of the string's length [5](#0-4) .
- `formula/validation.js` and `formula/evaluation.js` both call `new nearley.Parser(nearley.Grammar.fromCompiled(grammar)); parser.feed(formula)` synchronously, on the Node.js main thread, with no size guard before feeding [6](#0-5) [4](#0-3) .
- Earley parsers (which nearley implements) have well-documented worst-case O(n³) time complexity on ambiguous grammars; the oscript grammar contains many overlapping operator/production forms, so a crafted long formula (constructed, e.g., via deeply repeated/ambiguous operator chains) can force the parser into near-worst-case behavior.
- The AA-definition unit that carries this formula is validated like any other unit and is only bounded by the generic `MAX_UNIT_LENGTH` (5e6 bytes) check in `validation.js`, which does not scrutinize the size of any single formula field [7](#0-6) [8](#0-7) .
- This mirrors the reported node-tar class of bug: a small, well-formed piece of attacker-controlled input (a formula string, not compressed data) is expanded into disproportionate resource consumption (CPU time and call-stack/array growth in the parser) with no configured ceiling specific to that operation, even though an equivalent path elsewhere in the same codebase (`definition.js`) explicitly recognizes the need for such a ceiling.

### Impact Explanation
Formula parsing in `validateFormula`/`evaluate` runs synchronously in the unit-validation pipeline, which every full node (including witnesses) executes before it can accept/relay subsequent units. A crafted AA-definition unit with a pathological formula string can stall a node's validation loop for an extended period, delaying propagation, main-chain advancement, and confirmation of unrelated units network-wide while the malicious unit is being validated by each node in turn — i.e., "a network unable to confirm new units" in the terms of the validation rubric. Because AA definitions can be posted by any unprivileged address, this is reachable without any special privileges.

### Likelihood Explanation
Medium-to-High. Constructing an AA definition and paying its byte-size fee is a normal, cheap, unprivileged action (posting a unit under 5MB). No cryptographic break or race condition is required — only crafting a sufficiently large/ambiguous formula string, which is a deterministic, repeatable operation. The main uncertainty is the exact multiplier of the parser's worst-case blowup for the specific oscript grammar productions, which I could not measure by executing the parser in this environment; this should be validated empirically (e.g., benchmarking `nearley.Parser.feed()` against a few-hundred-KB adversarially structured oscript formula) before treating the severity as definitively Critical rather than High/Medium.

### Recommendation
Add an explicit formula-length cap (consistent with the `10000`-character cap already used in `definition.js`) at every site where a formula string is fed to the nearley parser — specifically in `aa_validation.js`'s `validate()` before calling `validateFormula`, and defensively inside `formula/validation.js` and `formula/evaluation.js` themselves — so no oscript formula of unbounded size can reach the Earley parser regardless of the containing AA-definition field (`messages`, `if`, `init`, `getters`).

### Proof of Concept
Conceptual PoC (not executed in this environment due to lack of a runtime/sandbox):
1. Construct an AA definition whose `messages[].payload.if` (or any other field consumed by `aa_validation.js`'s `validate()`) is a single formula string of, e.g., 500KB–4MB, composed of deeply nested/ambiguous arithmetic or boolean sub-expressions permitted by the oscript grammar (e.g., long chains of `(a+(a+(a+...)))` mixed with ambiguous operator forms).
2. Post this AA-definition unit (well within `MAX_UNIT_LENGTH`).
3. When nodes validate the unit, `aa_validation.js`'s `validate()` reaches the `if` field and calls `validateFormula`, which calls `formula/validation.js`'s `nearley.Parser.feed(formula)` with the crafted string.
4. Measure wall-clock time/CPU spent in `parser.feed` for increasing input sizes to confirm super-linear growth versus the linear growth expected if a length cap analogous to `definition.js`'s existed.

Because I lack execution access to actually run and time this parse against the real `formula/grammars/oscript.js` grammar, the magnitude of the blowup (and hence whether this reaches "network unable to confirm new units" in practice) should be confirmed with a live benchmark before treating this as fully proven; the missing-bound root cause itself, however, is directly verifiable in the cited source lines.

### Citations

**File:** definition.js (L594-600)
```javascript
			case 'formula':
				if (objValidationState.last_ball_mci < constants.formulaUpgradeMci)
					return cb("formulas not allowed at this mci yet");
				if (!isNonemptyString(args))
					return cb("formula must be a non-empty string");
				if (args.length > 10000 && (objValidationState.last_ball_mci >= constants.pemCurvesFixMci || !objValidationState.hasBall && storage.getMinRetrievableMci() >= constants.pemCurvesFixMci))
					return cb("formula too long");
```

**File:** aa_validation.js (L598-635)
```javascript
	function validate(obj, name, path, locals, depth, cb, bValueOnly) {
		if (depth > MAX_DEPTH)
			return cb("max depth reached");
		count++;
		if (count % 100 === 0) // interrupt the call stack
			return setImmediate(validate, obj, name, path, locals, depth, cb, bValueOnly);
		locals = _.cloneDeep(locals);
		var value = obj[name];
		if (typeof name === 'string' && !bValueOnly) {
			var f = getFormula(name);
			if (f !== null) {
				var opts = {
					formula: f,
					locals: _.cloneDeep(locals),
				};
				return validateFormula(opts, function (err) {
					if (err)
						return cb(err);
					validate(obj, name, path, locals, depth, cb, true);
				});
			}
		}
		if (typeof value === 'number' || typeof value === 'boolean')
			return cb();
		if (typeof value === 'string') {
			var f = getFormula(value);
			if (f === null)
				return cb();
		//	console.log('path', path, 'name', name, 'f', f);
			var bStateUpdates = (path === '/messages/state');
			var opts = {
				formula: f,
				locals: locals,
				bStatementsOnly: bStateUpdates,
				bStateVarAssignmentAllowed: bStateUpdates,
			};
			validateFormula(opts, cb);
		}
```

**File:** formula/validation.js (L249-266)
```javascript
	var parser = {};
	try {
		if(cache[formula]){
			parser.results = cache[formula];
		}else {
			parser = new nearley.Parser(nearley.Grammar.fromCompiled(grammar));
			parser.feed(formula);
			if(formulasInCache.length > cacheLimit){
				var f = formulasInCache.shift();
				delete cache[f];
			}
			formulasInCache.push(formula);
			cache[formula] = parser.results;
		}
	} catch (e) {
		console.log('==== parse error', e, e.stack)
		return callback({error: 'parse error', complexity, errorMessage: e.message});
	}
```

**File:** formula/evaluation.js (L104-121)
```javascript
	var parser = {};
	if(cache[formula]){
		parser.results = cache[formula];
	}else {
		try {
			parser = new nearley.Parser(nearley.Grammar.fromCompiled(grammar));
			parser.feed(formula);
			formulasInCache.push(formula);
			cache[formula] = parser.results;
			if (formulasInCache.length > cacheLimit) {
				var f = formulasInCache.shift();
				delete cache[f];
			}
		}catch (e) {
			console.log('exception from parser', e);
			return callback('parse failed: '+e, null);
		}
	}
```

**File:** constants.js (L59-59)
```javascript
exports.MAX_UNIT_LENGTH = process.env.MAX_UNIT_LENGTH || 5e6;
```

**File:** validation.js (L257-268)
```javascript
		if (objectLength.getHeadersSize(objUnit) !== objUnit.headers_commission)
			return callbacks.ifJointError("wrong headers commission, expected "+objectLength.getHeadersSize(objUnit));
		try {
			const payloadSize = objectLength.getTotalPayloadSize(objUnit);
			if (payloadSize !== objUnit.payload_commission)
				return callbacks.ifJointError("wrong payload commission, unit " + objUnit.unit + ", expected " + payloadSize);
		}
		catch (e) {
			return callbacks.ifJointError("failed to calculate payload commission: " + e);
		}
		if (objUnit.headers_commission + objUnit.payload_commission > constants.MAX_UNIT_LENGTH && !bGenesis && !bAA)
			return callbacks.ifUnitError("unit too large");
```
