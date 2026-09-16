### Title
Denial of Service via algorithmically-inefficient Earley parsing (`nearley`) of attacker-controlled oscript/ojson formulas - (File: `formula/evaluation.js`, `formula/validation.js`)

### Summary
Both AA-definition validation and AA-trigger execution feed attacker-controlled strings directly into a general-purpose Earley parser (`nearley`) using the `oscript` grammar, with no bound on the parse-time cost of the input beyond a coarse string-length cap. Because Earley parsing has worst-case cubic (O(n³)) time complexity on ambiguous/deeply-nested grammars, a single crafted formula string embedded in an ordinary unit (AA definition or AA trigger message) forces every validating full node to spend disproportionate CPU time parsing it — the same bug class as CVE‑2025‑11230 (HAProxy `mjson`: "inefficient algorithm complexity ... allows remote attackers to cause a denial of service via specially crafted JSON requests"), except the "specially crafted" payload here is an oscript formula rather than JSON.

### Finding Description
`getFormula()` merely strips the surrounding `{`/`}` braces from a message field (payload, `if`, `init`, `state`, data-feed key/value, output address, etc.) with no length- or complexity-aware check: [1](#0-0) 

The extracted formula text is then fed straight into `nearley.Parser` using the compiled `oscript` grammar, both during static AA-definition validation: [2](#0-1) 

and during actual formula evaluation when an AA trigger is processed: [3](#0-2) 

The grammar itself is known to be ambiguous — both call sites and the `ojson` parser explicitly special-case "ambiguous parser result" (i.e., `parser.results.length !== 1`): [4](#0-3) 

`nearley`'s Earley-parsing engine has worst-case O(n³) time complexity in the length of the input for grammars with ambiguity or heavy left/right recursion (present here via recursive `expr`, `AS`, `MD`, `ternary_expr`, `or_expr`, `and_expr` productions): [5](#0-4) [6](#0-5) 

The only guard applied before parsing is a flat string-length check (`MAX_AA_STRING_LENGTH`) enforced on evaluated *values*, not on the source text supplied to the parser at parse time, and no complexity/time budget exists for the parse step itself: [7](#0-6) 

An AA author who defines a new autonomous agent controls every formula string in `aa_validation.validateAADefinition` (payload formulas, `if`/`init` conditions, `state` formula), which are parsed by every node when the AA-defining unit is validated: [8](#0-7) [9](#0-8) 

Any user who then sends a trigger unit to that AA causes each formula to be re-parsed (or served from a bounded LRU parse cache keyed by exact formula string, which an attacker can trivially defeat by varying whitespace/formatting per trigger) on every full node validating and executing that trigger, including AA cascades.

### Impact Explanation
A remote, unprivileged actor (any wallet that can post a unit) can craft a single AA definition (or a series of triggers to an already-deployed AA) containing deeply nested/ambiguous oscript expressions that fit comfortably within existing per-message/per-unit size limits, yet cause disproportionate (potentially cubic-in-length) CPU time in every node's `nearley` Earley parse. Because unit/AA validation is on the hot path for a node to accept and relay new units and to advance main-chain stability, sustained submission of such units can stall or dramatically slow down validation across the network — a network-wide "unable to confirm new units" condition, which the rules classify as a valid, non-resource-only DoS impact.

### Likelihood Explanation
Likelihood is Medium-High: crafting formula strings is trivial (plain text, no cryptographic or witness requirements), the attack surface (AA definitions and AA triggers) is explicitly open to any unprivileged unit poster, and the vulnerable code path (`nearley.Parser(...).feed(formula)`) is unconditionally executed on validation with no execution-time budget, only a coarse length cap on resulting decoded strings — not on parser work. The main mitigating factor is the formula-parse result cache (`cache[formula]`), but this is keyed by exact string and bounded (`cacheLimit`), so an attacker varying formulas defeats caching entirely.

### Recommendation
Add an explicit parse-time budget / wall-clock or step-count limit around each `nearley.Parser.feed()` call in `formula/evaluation.js` and `formula/validation.js`, abort and reject the unit/AA definition if the limit is exceeded, and/or bound formula complexity (e.g., max nesting depth, max token count) before invoking the Earley parser, independent of the raw string length. Consider replacing/complementing the ambiguous grammar with an unambiguous one or precompiling stricter operator-precedence rules to remove the worst-case cubic blowup paths.

### Proof of Concept
Not independently executed (no code-execution/timing environment available in this analysis); the mechanism is demonstrated structurally:
1. Define an AA whose `messages[].payload` (formula) or `if`/`init` field contains a deeply nested expression built from the recursive productions shown above, e.g. a long chain of nested ternary/concat/or/and expressions or nested parentheses designed to maximize Earley chart ambiguity, kept under the per-field length limits enforced elsewhere in `aa_validation.js`.
2. Post the AA-definition unit; every full node calls `formulaValidator.validate` → `nearley.Parser(...).feed(formula)` on the crafted string during `validateAADefinition`.
3. Repeat with varying whitespace/formatting to bypass the `cache[formula]` LRU cache, and/or send repeated AA triggers with similarly crafted `trigger.data`/formula content, forcing `exports.evaluate` in `formula/evaluation.js` to re-parse on every trigger.
4. Measure CPU time consumed by validating nodes versus a linear-size baseline formula, to confirm super-linear scaling consistent with Earley's worst-case complexity.

**Note:** I was not able to fully verify the exact numeric value of `MAX_UNIT_LENGTH`/related per-message size caps in `constants.js` within the available search budget, so the precise maximum crafted-formula size an attacker can fit into one unit is unconfirmed; this does not affect the root-cause finding but would refine the severity/PoC sizing.

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

**File:** formula/evaluation.js (L143-150)
```javascript
		if (typeof arr !== 'object') {
			if (typeof arr === 'boolean') return cb(arr);
			if (typeof arr === 'string') {
				if (arr.length > constants.MAX_AA_STRING_LENGTH)
					return setFatalError("string is too long: " + arr, { arr }, false, cb);
				return cb(arr);
			}
			return setFatalError("unknown type of arr: "+(typeof arr), { arr }, false, cb);
```

**File:** formula/parse_ojson.js (L35-41)
```javascript
	if (!_.isArray(parserResults)) {
		throw new Error(`Error parsing formula starting at line ${context.line} col ${context.col}`)
	} else if (parserResults.length !== 1) {
		throw new Error(`Error parsing formula starting at line ${context.line} col ${context.col}: ambiguous parser result`)
	} else {
		searchNewlineRecursive(parserResults[0])
	}
```

**File:** formula/grammars/oscript.js (L197-226)
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
    {"name": "expr", "symbols": ["otherwise_expr"], "postprocess": id},
    {"name": "expr_list$ebnf$1", "symbols": ["expr"], "postprocess": id},
    {"name": "expr_list$ebnf$1", "symbols": [], "postprocess": function(d) {return null;}},
    {"name": "expr_list$ebnf$2", "symbols": []},
    {"name": "expr_list$ebnf$2$subexpression$1", "symbols": [{"literal":","}, "expr"]},
    {"name": "expr_list$ebnf$2", "symbols": ["expr_list$ebnf$2", "expr_list$ebnf$2$subexpression$1"], "postprocess": function arrpush(d) {return d[0].concat([d[1]]);}},
    {"name": "expr_list", "symbols": ["expr_list$ebnf$1", "expr_list$ebnf$2"], "postprocess":  function(d) {
        	var arr = d[0] ? [d[0]] : [];
        	return arr.concat(d[1].map(function (item) {return item[1];}));
        } },
    {"name": "comp_expr$subexpression$1", "symbols": [{"literal":"=="}]},
    {"name": "comp_expr$subexpression$1", "symbols": [{"literal":"!="}]},
    {"name": "comp_expr$subexpression$1", "symbols": [{"literal":">"}]},
    {"name": "comp_expr$subexpression$1", "symbols": [{"literal":">="}]},
    {"name": "comp_expr$subexpression$1", "symbols": [{"literal":"<"}]},
    {"name": "comp_expr$subexpression$1", "symbols": [{"literal":"<="}]},
    {"name": "comp_expr", "symbols": ["AS", "comp_expr$subexpression$1", "AS"], "postprocess": function(d) { return addLocation(['comparison', d[1][0].value, d[0], d[2]], d[1]); }},
    {"name": "comp_expr", "symbols": ["AS"], "postprocess": id},
    {"name": "comparisonOperator", "symbols": [(lexer.has("comparisonOperators") ? {type: "comparisonOperators"} : comparisonOperators)], "postprocess": function(d) { return d[0].value }},
    {"name": "local_var_expr", "symbols": [{"literal":"${"}, "expr", {"literal":"}"}], "postprocess": function(d) { return d[1]; }},
```

**File:** formula/grammars/oscript.ne (L361-372)
```text
MD -> MD "*" unary_expr  {% function(d) {return addLocation(['*', d[0], d[2]], d); } %}
    | MD "/" unary_expr  {% function(d) {return addLocation(['/', d[0], d[2]], d); } %}
    | MD "%" unary_expr  {% function(d) {return addLocation(['%', d[0], d[2]], d); } %}
    | unary_expr             {% id %}

AS -> AS "+" MD {% function(d) {return addLocation(['+', d[0], d[2]], d); } %}
    | AS "-" MD {% function(d) {return addLocation(['-', d[0], d[2]], d); } %}
    | "-" MD {% function(d) {return addLocation(['-', new Decimal(0), d[1]], d); } %}
    | "+" MD {% function(d) {return addLocation(['+', new Decimal(0), d[1]], d); } %}
    | AS %concat MD {% function(d) {return addLocation(['concat', d[0], d[2]], d); } %}
    | MD            {% id %}

```

**File:** aa_validation.js (L63-71)
```javascript
			if (!['string', 'object'].includes(typeof payload) || !payload)
				return cb2("payload must be a string or object: " + payload);

			if (message.app !== 'text' && isNonemptyString(payload)) {
				var payload_formula = getFormula(payload);
				if (payload_formula === null)
					return cb2("payload is a string but doesn't look like a formula: " + payload);
				return cb2();
			}
```

**File:** aa_validation.js (L436-444)
```javascript
		if (mci >= constants.aa2UpgradeMci && typeof message === 'string')
			return cb();
		if (message.app === 'state') {
			var f = getFormula(message.state);
			if (f === null)
				return cb('bad state formula: ' + JSON.stringify(message.state));
			return cb();
		}
		validateFieldWrappedInCases(message, 'payload', validatePayload, cb);
```
