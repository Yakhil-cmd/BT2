## Analog Finding

### Title
Unbounded Nearley/Earley Parsing of Attacker-Controlled oscript/ojson Formulas Enables Parser-Level Node Hang (DoS) - (File: formula/validation.js, formula/evaluation.js, formula/parse_ojson.js)

### Summary
CVE-2020-2627 is a MySQL **parser**-stage flaw that lets an unprivileged, network-reachable client crash/hang the server before any authorization or query-execution logic runs. The ocore analog is the oscript/ojson grammar parsing performed by the bundled `nearley` Earley parser: any unprivileged unit poster who defines an Autonomous Agent (AA), or embeds a `formula` address-definition operator, supplies a raw string that is fed directly into `nearley.Parser.feed()` with no pre-parse size/shape limits comparable to the post-parse complexity/op-count/depth limits that exist only *after* a successful parse.

### Finding Description
Every AA-definition formula (state formula, message `if`/`init`, `payment` output `amount`/`address`, `asset` `cap`, poll `choices`, address-definition `formula` op, etc.) is validated by first constructing a fresh Earley parser and calling `.feed(formula)`: [1](#0-0) 
The same unmitigated parse call is used again at evaluation time: [2](#0-1) 
and in `ojson` object parsing used to auto-derive AA definitions from templates: [3](#0-2) 

All of the safety limits that exist for oscript formulas — `MAX_COMPLEXITY`, `MAX_OPS`, and the AST-traversal `depth > 100` guard — are only applied to the **parsed AST** *after* `parser.feed()` has already completed: [4](#0-3) [5](#0-4) 

There is no bound on the raw formula string comparable to those AST-level checks except a single `args.length > 10000` check that only applies to the address-definition `formula` op: [6](#0-5) 
No such length check exists in `aa_validation.js`'s `validateFormula()` before it hands the string to `formulaValidator.validate()`: [7](#0-6) 
The only outer bound on a formula's size is therefore the overall unit-size ceiling: [8](#0-7) 
which permits up to ~5 MB of formula text per unit — orders of magnitude larger than the `MAX_AA_STRING_LENGTH` (4096) enforced only on string *literal values* inside a formula, not on formula source length itself.

Nearley's default Earley parsing algorithm has worst-case cubic (and for pathological/ambiguous grammar fragments effectively much worse in practice due to repeated state-set exploration and lack of a length/ambiguity guard) time and memory behavior with respect to input length. Because the oscript grammar contains left-recursive/ambiguous constructs (e.g., `AS`, `MD`, `or_expr`, `and_expr` rules) as seen in the compiled grammar: [9](#0-8) 
a crafted, deeply/repetitively structured formula (e.g., thousands of chained operators, nested parentheses, or nested array/dictionary literals as already shown to reach the evaluator in existing tests) can be constructed to make `parser.feed()` consume excessive CPU/memory well before the post-parse complexity checks ever execute — the check that exists to catch "deeply nested" structures only fires during AST evaluation, not during parsing: [10](#0-9) 

Because every full node independently parses every AA definition/state formula found in every posted unit and every AA trigger execution re-parses formulas (cache only helps repeat identical strings, and a unique formula defeats the cache), a single unprivileged unit poster (AA author) can force this expensive parse on every validating/witnessing node in the network by posting one unit.

### Impact Explanation
A computationally pathological formula string can cause validating nodes to spend excessive CPU/memory time inside `nearley.Parser.feed()` while processing a single broadcast unit, before any of the existing complexity/op/depth guards apply. Because unit/AA validation is synchronous, node-local work performed by every node that receives the unit, this can degrade or stall validation throughput network-wide — a "network unable to confirm new units" style denial-of-service, matching the CVSS Availability-only impact of CVE-2020-2627.

### Likelihood Explanation
Likelihood is bounded by whether nearley's default Earley implementation actually exhibits super-linear-enough blowup on inputs constructible within the oscript grammar and within the ~5MB unit-size ceiling to matter in practice; this requires empirical benchmarking of `nearley.Parser.feed()` on adversarial oscript grammar inputs (e.g., deeply chained ambiguous binary-operator expressions) to confirm real-world CPU/memory cost, which could not be measured from static code inspection alone.

### Recommendation
- Add an explicit maximum length limit on the raw formula string (analogous to `MAX_AA_STRING_LENGTH`/the existing 10000-char check in `definition.js`) before calling `parser.feed()` in `formula/validation.js`, `formula/evaluation.js`, and `formula/parse_ojson.js`.
- Benchmark and, if needed, bound nearley's internal state-set growth (e.g., via a token/step counter passed into the lexer/parser loop) so parsing itself can be aborted early on pathological but short/adversarial inputs, not just on overly long ones.
- Consider caching/rejecting formulas whose token count exceeds a conservative multiple of practical, legitimate AA formulas.

### Proof of Concept
Not directly executable without measuring nearley's actual performance characteristics on the oscript grammar; the reachable path is:
1. Attacker crafts an AA definition (or address `formula` op / `ojson` template) containing a formula string built from thousands of repeated ambiguous/nested operator tokens (e.g., `1+1+1+...` chained with parenthesization or `[[[[...]]]]` nesting) sized just under the unit-size limit.
2. Attacker broadcasts the unit.
3. Every full node calls `formulaValidator.validate()` / `parse_ojson.parse()`, which invoke `nearley.Parser.feed(formula)` on the full string before any complexity or depth check is applied, as shown in the cited code.

### Citations

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

**File:** formula/validation.js (L268-288)
```javascript
	var count = 0;
	let depth = 0;
	let errorLocation = null;

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

**File:** aa_validation.js (L535-571)
```javascript
	function validateFormula(aa_opts, cb) {
		if (typeof aa_opts.formula !== 'string' || !aa_opts.locals)
			throw Error("bad opts in validateFormula: " + JSON.stringify(aa_opts));
		var opts = {
			formula: fixFormula(aa_opts.formula, address),
			complexity: complexity,
			count_ops: count_ops,
			bAA: true,
			bStatementsOnly: aa_opts.bStatementsOnly || false,
			bGetters: aa_opts.bGetters || false,
			bStateVarAssignmentAllowed: aa_opts.bStateVarAssignmentAllowed || false,
			locals: aa_opts.locals,
			readGetterProps: readGetterProps,
			mci: mci,
		};
	//	console.log('--- validateFormula', formula);
		formulaValidator.validate(opts, function (result) {
			if (typeof result.complexity !== 'number' || !isFinite(result.complexity))
				throw Error("bad complexity after " + opts.formula + ": " + result.complexity);
			complexity = result.complexity;
			count_ops = result.count_ops;
			if (result.error) {
				if (result.error_location) {
					validationErrorDetails = {
						formula: opts.formula,
						error_location: result.error_location,
					};
				}
				var errorMessage = "validation of formula " + opts.formula + " failed: " + result.error
				errorMessage += result.errorMessage ? `\nparser error: ${result.errorMessage}` : ''
				return cb(errorMessage);
			}
			if (complexity > constants.MAX_COMPLEXITY)
				return cb('complexity exceeded: ' + complexity);
			if (count_ops > constants.MAX_OPS)
				return cb('number of ops exceeded: ' + count_ops);
			cb();
```

**File:** definition.js (L594-601)
```javascript
			case 'formula':
				if (objValidationState.last_ball_mci < constants.formulaUpgradeMci)
					return cb("formulas not allowed at this mci yet");
				if (!isNonemptyString(args))
					return cb("formula must be a non-empty string");
				if (args.length > 10000 && (objValidationState.last_ball_mci >= constants.pemCurvesFixMci || !objValidationState.hasBall && storage.getMinRetrievableMci() >= constants.pemCurvesFixMci))
					return cb("formula too long");
				formulaParser.validate({
```

**File:** constants.js (L59-59)
```javascript
exports.MAX_UNIT_LENGTH = process.env.MAX_UNIT_LENGTH || 5e6;
```

**File:** formula/grammars/oscript.js (L199-206)
```javascript
    {"name": "or_expr$subexpression$1", "symbols": [{"literal":"or"}]},
    {"name": "or_expr$subexpression$1", "symbols": [{"literal":"OR"}]},
    {"name": "or_expr", "symbols": ["or_expr", "or_expr$subexpression$1", "and_expr"], "postprocess": function(d) {return addLocation(['or', d[0], d[2]], d); }},
    {"name": "or_expr", "symbols": ["and_expr"], "postprocess": id},
    {"name": "and_expr$subexpression$1", "symbols": [{"literal":"and"}]},
    {"name": "and_expr$subexpression$1", "symbols": [{"literal":"AND"}]},
    {"name": "and_expr", "symbols": ["and_expr", "and_expr$subexpression$1", "comp_expr"], "postprocess": function(d) {return addLocation(['and', d[0], d[2]], d); }},
    {"name": "and_expr", "symbols": ["comp_expr"], "postprocess": id},
```

**File:** test/formula.test.js (L6415-6437)
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

test.cb('deeply nested dictionary', t => {
	var trigger = { data: { q: { a: 6 } } };
	var stateVars = {};
	const depth = 2000;
	evalFormulaWithVars({ conn: db, formula: `${'{a:'.repeat(depth)}1${'}'.repeat(depth)}`, trigger: trigger, locals: {  }, stateVars: stateVars,  objValidationState: objValidationState, address: 'MXMEKGN37H5QO2AWHT7XRG6LHJVVTAWU'}, (res, complexity, count_ops) => {
		t.deepEqual(res, null);
	//	t.deepEqual(complexity, 1);
	//	t.deepEqual(count_ops, depth + 1);
		t.end();
	})
});
```
