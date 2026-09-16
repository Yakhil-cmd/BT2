### Title
Uncontrolled resource consumption via ambiguous-grammar Earley parsing of attacker-supplied oscript/ojson formulas in AA/address definitions - ([File: formula/validation.js])

### Summary
`getFormula()` merely strips the surrounding `{`/`}` braces from a string with no cost bound [1](#0-0) . The actual parsing is performed by `formula/validation.js`'s `exports.validate`, which unconditionally feeds the raw formula text into a `nearley` Earley parser before any complexity/op-count accounting takes place: `parser = new nearley.Parser(...); parser.feed(formula);` [2](#0-1) . The same pattern exists in `formula/evaluation.js`'s `exports.evaluate` [3](#0-2)  and in the raw AA-definition parser `formula/parse_ojson.js` (`parseOjsonGrammar`/`parseOscriptGrammar`) [4](#0-3) . The code explicitly acknowledges that the oscript/ojson grammar can be ambiguous — it logs "ambiguous grammar" when `parser.results.length > 1` [5](#0-4)  and again in `evaluation.js` [6](#0-5) . Earley parsing of ambiguous grammars is a classic case of algorithmic/uncontrolled resource consumption: crafted-but-syntactically-valid (or syntactically borderline) input can drive the parser's internal state-set/chart to blow up super-linearly in time and memory before any of ocore's `MAX_COMPLEXITY`/`MAX_OPS`/depth limits are ever consulted — those limits are only enforced during the post-parse `evaluate()` walk, not during `parser.feed()` itself.

### Finding Description
An unprivileged unit poster can embed an oscript/ojson formula almost anywhere an address/asset condition or AA definition accepts one: the `'formula'` op in `definition.js` (`validateDefinition`) [7](#0-6) , AA `getters` [8](#0-7) , and numerous AA message fields validated via `getFormula()` in `aa_validation.js` — e.g. payment `output.amount`, `output.if`, `output.init`, asset `cap`/`denominations` formulas [9](#0-8) [10](#0-9) .

For the address/asset-condition `'formula'` op there is at least a length cap (`args.length > 10000`) before the string reaches `formulaParser.validate` [11](#0-10) , but this cap only bounds input length, not grammar ambiguity or the number of parse states the Earley algorithm must track — up to 10,000 characters is still ample room to construct deeply/ambiguously nested expressions (nested parentheses, chained binary operators, nested arrays/dictionaries, `otherwise`/ternary chains, etc., all of which are left- and right-recursive productions in `oscript.ne`, e.g. `AS -> AS "+" MD | AS "-" MD | ... | MD` and `ternary_expr -> or_expr "?" expr ":" ternary_expr` [12](#0-11) ) that make the Earley chart grow non-linearly. Several other call-sites that feed formula text into `getFormula()`/`validateFormula()` for AA message payloads do not appear to enforce any comparable length ceiling before parsing begins (visible in the `aa_validation.js` payment/asset code paths above), so the effective payload size is bounded only by the general unit/message size limits, which are considerably larger than 10,000 bytes.

Crucially, this parsing happens during **unit/AA validation**, which every full node in the network must perform to accept the unit into the DAG and eventually main-chain-stabilize it — this is not an isolated, per-request cost paid only by the submitter. A single posted unit containing such a formula forces every validating node to redo the same expensive Earley parse.

### Impact Explanation
This maps to the "network unable to confirm new units" acceptance criterion: a single crafted unit (AA definition, address/asset definition with a `'formula'` condition, or an AA trigger/message containing a pathological formula string) can be broadcast once and cause every node that validates it — witnesses, hubs, and ordinary full nodes alike — to spend disproportionate CPU/memory in `nearley.Parser.feed()` before any of ocore's complexity/op/depth guards apply. Because validation of every new unit and every AA trigger execution is on the critical path for DAG growth and MC stabilization, sustained submission of such units could measurably degrade or stall the network's ability to validate and confirm new units, which is the concrete, reachable, node-wide harm called for by the report's validation bar (as opposed to a "resource-only" localized slowdown).

### Likelihood Explanation
Likelihood is moderate: the attack requires only posting a unit (defining an address, an asset, or an AA) or triggering an AA with a message payload — actions available to any unprivileged network participant, with no special key material or elevated trust needed, matching the "unauthenticated, no user interaction" character of the referenced BentoML DoS. The main uncertainty (which could not be fully resolved from the indexed source alone) is exactly how large/ambiguous a nearley chart can be coaxed to grow with ≤10,000 characters of valid oscript syntax and the grammar's actual ambiguity properties — this would require running the grammar (`formula/grammars/oscript.js`/`oscript.ne`) through `nearley` with adversarial inputs to measure real-world blow-up, which is not verifiable from static reading alone.

### Recommendation
- Impose a hard upper bound on nearley Earley-parser internal work (e.g., abort parsing if the number of parser states/columns exceeds a fixed multiple of input length) in `formula/validation.js`, `formula/evaluation.js`, and `formula/parse_ojson.js`, independent of the post-parse complexity/op counters.
- Apply the existing 10,000-character formula-length cap (or a stricter one) uniformly to every call site that invokes `getFormula()`/`validateFormula()` on AA message fields (payment `amount`/`if`/`init`, asset `cap`/`denominations`, getters), not only the address/asset-condition `'formula'` op.
- Consider replacing/augmenting the ambiguous grammar with an unambiguous one, or detect and reject ambiguous parses (`parser.results.length > 1`) as early and cheaply as possible rather than only after the parse completes.
- Add fuzz/adversarial testing against the `oscript`/`ojson` grammars specifically targeting Earley parser complexity blow-up (deeply nested/ambiguous constructs at the current length ceiling).

### Proof of Concept
Not independently executable from the static index — reproducing the actual resource blow-up requires running `formula/validation.js`'s `exports.validate` (or `formula/parse_ojson.js`) against a crafted oscript string (e.g., deeply chained ambiguous operators/parentheses at or near the 10,000-character cap) inside a live ocore node/test harness and measuring `nearley.Parser.feed()` CPU/memory versus input size. A background Devin session with access to the full repository and a Node.js runtime would be needed to construct and measure such a payload against `formula/grammars/oscript.js`.

### Citations

**File:** formula/common.js (L82-93)
```javascript
function getFormula(str, bOptionalBraces) {
	if (bOptionalBraces)
		throw Error("braces cannot be optional");
	if (typeof str !== 'string')
		return null;
	if (str[0] === '{' && str[str.length - 1] === '}')
		return str.slice(1, -1);
	else if (bOptionalBraces)
		return str;
	else
		return null;
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

**File:** formula/validation.js (L1523-1541)
```javascript
	if (parser.results.length === 1 && parser.results[0]) {
		//	console.log('--- parser result', JSON.stringify(parser.results[0], null, '\t'));
		evaluate(parser.results[0], err => {
			if (depth !== 0)
				throw Error("mismatched depth " + depth);
			finalizeLocals(locals);
			const result = { complexity, count_ops, error: err || false };
			if (err && errorLocation)
				result.error_location = errorLocation;
			callback(result);
		}, true);
	} else {
		if (parser.results.length > 1){
			console.log('validation: ambiguous grammar', parser.results);
			callback({ complexity, error: 'ambiguous grammar' });
		}
		else
			callback({complexity, error: 'parser failed'});
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

**File:** formula/evaluation.js (L3226-3231)
```javascript
	} else {
		if (parser.results.length > 1) {
			console.log('ambiguous grammar', parser.results);
			callback('ambiguous grammar', null);
		}
	}
```

**File:** formula/parse_ojson.js (L44-54)
```javascript
function parseOjsonGrammar (text) {
	var nearleyParser = new nearley.Parser(nearley.Grammar.fromCompiled(ojsonGrammar));
	nearleyParser.feed(text);
	return nearleyParser;
};

function parseOscriptGrammar (formula) {
	var nearleyParser = new nearley.Parser(nearley.Grammar.fromCompiled(oscriptGrammar));
	nearleyParser.feed(formula);
	return nearleyParser;
};
```

**File:** definition.js (L594-614)
```javascript
			case 'formula':
				if (objValidationState.last_ball_mci < constants.formulaUpgradeMci)
					return cb("formulas not allowed at this mci yet");
				if (!isNonemptyString(args))
					return cb("formula must be a non-empty string");
				if (args.length > 10000 && (objValidationState.last_ball_mci >= constants.pemCurvesFixMci || !objValidationState.hasBall && storage.getMinRetrievableMci() >= constants.pemCurvesFixMci))
					return cb("formula too long");
				formulaParser.validate({
					formula: args,
					complexity,
					count_ops,
					mci: objValidationState.last_ball_mci,
					locals: {},
					bAA: false,
					bAssetCondition,
				}, function (result) {
					complexity = result.complexity;
					count_ops = result.count_ops;
					cb(result.error);
				});
				break;
```

**File:** aa_validation.js (L141-189)
```javascript
						for (var i = 0; i < outputs.length; i++) {
							var output = outputs[i];
							if (isNonemptyString(output)) {
								var output_formula = getFormula(output);
								if (output_formula === null)
									return cb3("bad output formula: " + output);
								continue;
							}
							if (!isNonemptyObject(output))
								return cb3("output must be a non-empty object: " + JSON.stringify(output));
							if (hasFieldsExcept(output, ['address', 'amount', 'init', 'if']))
								return cb3('foreign fields in output');
							if ('if' in output) {
								if (!isNonemptyString(output.if))
									return cb3("bad if in output: " + JSON.stringify(output.if));
								var f = getFormula(output.if);
								if (f === null)
									return cb3("if in output is not a formula: " + output.if);
							}
							if ('init' in output) {
								if (!isNonemptyString(output.init))
									return cb3("bad init in output: " + JSON.stringify(output.init));
								var f = getFormula(output.init);
								if (f === null)
									return cb3("init in output is not a formula: " + output.init);
							}
							if (!isNonemptyString(output.address))
								return cb3('address not a string: ' + JSON.stringify(output.address));
							var f = getFormula(output.address);
							if (f !== null) {
							}
							else if (!isValidAddress(output.address))
								return cb3("bad address: "+output.address);
							if (typeof output.amount === 'number') {
								if (!isPositiveInteger(output.amount) || output.amount > constants.MAX_CAP)
									return cb3('bad amount number: ' + output.amount);
							}
							else if (typeof output.amount === 'string') {
								var f = getFormula(output.amount);
								if (f === null)
									return cb3("bad formula in amount: " + output.amount);
							}
							else if (typeof output.amount === 'undefined') {
								if (bHaveSendAll)
									return cb3("a second send-all output");
								bHaveSendAll = true;
							}
							else
								return cb3('bad amount: ' + JSON.stringify(output.amount));
```

**File:** aa_validation.js (L230-262)
```javascript
					if ("cap" in payload) {
						if (typeof payload.cap === 'number') {
							if (!(isPositiveInteger(payload.cap) && payload.cap <= constants.MAX_CAP))
								return cb2("invalid cap: " + payload.cap);
						}
						else if (typeof payload.cap === 'string') {
							var f = getFormula(payload.cap);
							if (f === null)
								return cb2("bad formula in cap: " + payload.cap);
						}
						else
							return cb2("wrong cap: " + JSON.stringify(payload.cap));
					}

					function validateDenominations(denominations, cb3) {
						if (isNonemptyString(denominations)) {
							var f = getFormula(denominations);
							if (f === null)
								return cb3("denominations is a string but not formula: " + denominations);
							return cb3();
						}
						if (!isNonemptyArray(denominations))
							return cb3("wrong denominations: " + JSON.stringify(denominations));
						if (denominations.length > constants.MAX_DENOMINATIONS_PER_ASSET_DEFINITION)
							return cb3("too many denominations");
						for (var i=0; i<denominations.length; i++){
							var denomInfo = denominations[i];
							if (!isNonemptyObject(denomInfo))
								return cb3("denomination must be a non-empty object: " + JSON.stringify(denomInfo));
							if (hasFieldsExcept(denomInfo, ["denomination", "count_coins"]))
								return cb3("unknown fields in denomination: " + JSON.stringify(denomInfo));
							if (typeof denomInfo.denomination === 'number') {
								if (!isPositiveInteger(denomInfo.denomination))
```

**File:** aa_validation.js (L575-596)
```javascript
	function validateDefinition(arrDefinition, cb) {
		var locals = {};
		var f = getFormula(arrDefinition[1].getters);
		if (f === null) // no getters
			return validate(arrDefinition, 1, '', locals, 0, cb);
		// validate getters before everything else as they can define a few functions
		delete arrDefinition[1].getters;
		var opts = {
			formula: f,
			locals: locals,
			bStatementsOnly: true,
			bGetters: true,
		};
		validateFormula(opts, function (err) {
			if (err)
				return cb(err);
			if (complexity > 0)
				return cb(`getters incremented complexity to ${complexity}`);
			getters = getGettersFromLocals(locals);
			validate(arrDefinition, 1, '', locals, 0, cb);
		});
	}
```

**File:** formula/grammars/oscript.js (L197-206)
```javascript
    {"name": "ternary_expr", "symbols": ["or_expr", {"literal":"?"}, "expr", {"literal":":"}, "ternary_expr"], "postprocess": function(d) {return addLocation(['ternary', d[0], d[2], d[4]], d); }},
    {"name": "ternary_expr", "symbols": ["or_expr"], "postprocess": id},
    {"name": "or_expr$subexpression$1", "symbols": [{"literal":"or"}]},
    {"name": "or_expr$subexpression$1", "symbols": [{"literal":"OR"}]},
    {"name": "or_expr", "symbols": ["or_expr", "or_expr$subexpression$1", "and_expr"], "postprocess": function(d) {return addLocation(['or', d[0], d[2]], d); }},
    {"name": "or_expr", "symbols": ["and_expr"], "postprocess": id},
    {"name": "and_expr$subexpression$1", "symbols": [{"literal":"and"}]},
    {"name": "and_expr$subexpression$1", "symbols": [{"literal":"AND"}]},
    {"name": "and_expr", "symbols": ["and_expr", "and_expr$subexpression$1", "comp_expr"], "postprocess": function(d) {return addLocation(['and', d[0], d[2]], d); }},
    {"name": "and_expr", "symbols": ["comp_expr"], "postprocess": id},
```
