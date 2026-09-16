Confirmed: `formula/validation.js:5` does `var grammar = require("./grammars/oscript.js")` — the **compiled** nearley grammar, not the `.ne` source. The same pattern applies to `formula/evaluation.js` and `formula/parse_ojson.js`, which load `./grammars/oscript.js` and `./grammars/ojson.js` [1](#0-0) . The actual, human-edited source of truth for the oscript/ojson grammar is `formula/grammars/oscript.ne` and `formula/grammars/ojson.ne` [2](#0-1) [3](#0-2) , but neither `validation.js`, `evaluation.js`, nor `parse_ojson.js` parses the `.ne` file directly at runtime — they only ever load the pre-compiled, checked-in `.js` artifacts [4](#0-3) .

The compilation step is a manual, external command that must be run and committed separately:
```
"compileGrammar:oscript": "nearleyc ./formula/grammars/oscript.ne -o ./formula/grammars/oscript.js",
"compileGrammar:ojson": "nearleyc ./formula/grammars/ojson.ne -o ./formula/grammars/ojson.js"
``` [5](#0-4) 

This is structurally the same bug class as the reported Obyte "vault.teal.tmpl" issue: one artifact (`vault.js` string / here, the `.ne` grammar) is the reviewed, intended specification of the security rules, while a second, independently-maintained artifact (`vault.teal.tmpl` / here, the compiled `.js` grammar) is what actually executes in production and is only kept in sync by a manual, easy-to-forget step (copy-paste / `nearleyc` regeneration). If a maintainer tightens a restriction only in the `.ne` grammar (e.g., a syntax-level restriction meant to block a dangerous oscript/ojson construct in AA definitions or trigger-supplied formulas) but forgets to run `compileGrammar:oscript`/`compileGrammar:ojson` and commit the regenerated `.js` file, the node continues running the old, laxer compiled grammar. This is directly reachable by an unprivileged AA author (defining an AA via the `definition` message) or by an AA trigger sender supplying formula-bearing data, since AA/oscript definitions and trigger formulas are parsed and validated exclusively through this compiled grammar in `aa_validation.js`/`validation.js` and executed through `formula/evaluation.js`.

### Title
Oscript/OJSON compiled grammar (`grammars/oscript.js`, `grammars/ojson.js`) can silently drift from its `.ne` source, permitting bypass of grammar-level restrictions - (File: formula/grammars/oscript.ne, formula/grammars/ojson.ne, formula/validation.js, formula/evaluation.js, formula/parse_ojson.js, package.json)

### Summary
The oscript/ojson formula grammar used to validate and evaluate AA definitions and trigger-supplied formulas is authored in `formula/grammars/oscript.ne` and `formula/grammars/ojson.ne`, but production code (`formula/validation.js`, `formula/evaluation.js`, `formula/parse_ojson.js`) never parses the `.ne` source — it only loads the pre-compiled `formula/grammars/oscript.js` / `formula/grammars/ojson.js` artifacts. These artifacts are regenerated only via a manual, separate `yarn`/`npm` script (`compileGrammar:oscript`, `compileGrammar:ojson`) that a developer must remember to run and commit whenever the `.ne` grammar changes.

### Finding Description
`formula/validation.js` and `formula/evaluation.js` both require the compiled grammar module directly (`require("./grammars/oscript.js")`), and `formula/parse_ojson.js` requires both compiled grammar modules [1](#0-0) . The grammar's actual specification — including any restriction added to close off a dangerous syntactic construct — lives in the `.ne` files, which are hand-edited and only converted to the runtime artifact by the `nearleyc` commands declared in `package.json` [5](#0-4) . There is no runtime or CI-enforced check in the codebase (as visible in the indexed portions of the repository) that verifies the committed `.js` grammar was actually regenerated from the current `.ne` file, nor any hash/consistency check between the two. This exactly mirrors the reported "vault.teal.tmpl vs vault.js" bug class: one file is the reviewed/intended source of the security-relevant logic, and a second, independently committed artifact is what is actually executed, kept in sync only by a manual step that is trivial to skip.

### Impact Explanation
If a grammar-level restriction is intended to prevent a dangerous or unbounded oscript construct (for example, a new operator, syntactic pattern, or field that formula validation/evaluation in `aa_validation.js`, `validation.js`, and `evaluation.js` rely on the grammar to reject or shape before further semantic checks run) and the `.ne` file is updated without regenerating and committing the compiled `.js` grammar, the deployed node keeps parsing formulas with the old, laxer grammar. Any AA author defining an AA (`payload.definition` in the `definition` app message, validated in `validation.js:1747-1782` and `aa_validation.js`) or any AA trigger sender supplying formula-bearing `data` can then submit oscript that the stale grammar still accepts, even though it was meant to be blocked. Depending on what protection was meant to be added, this can translate into unintended complexity bypass, malformed/duplicate-field structures reaching the evaluator, or other semantic-check bypasses in `formula/evaluation.js`, potentially leading to AA fund loss, incorrect state updates, or a validity/stability disagreement between nodes if some nodes were rebuilt with a correctly regenerated grammar and others were not.

### Likelihood Explanation
This is a build/release-process risk rather than a bug always present, so its likelihood depends on developer discipline around running `compileGrammar:oscript`/`compileGrammar:ojson` before every grammar change is merged and released. Given the report's own precedent (a security check omitted in exactly this "must remember to regenerate/copy" pattern), and the fact that ocore ships the compiled `.js` grammar as a checked-in artifact with no automated verification against the `.ne` source, the likelihood of an eventual drift going unnoticed until exploited by a crafted AA definition or trigger is Medium.

### Recommendation
- Short term: Add a CI step (or a pretest/build script) that regenerates `grammars/oscript.js` and `grammars/ojson.js` from the `.ne` sources and fails the build if the regenerated output differs from what is committed, so drift between `formula/grammars/*.ne` and `formula/grammars/*.js` can never silently ship.
- Long term: Compile the grammar at install/build time from the `.ne` source instead of committing the derived `.js` artifact, or add a runtime self-check (e.g., hashing the `.ne` file and embedding the expected hash in the compiled grammar) so `formula/validation.js`/`formula/evaluation.js`/`formula/parse_ojson.js` refuse to start if the compiled grammar does not correspond to the current source grammar.

### Proof of Concept
Not directly demonstrable without a concrete pair of diverging `.ne`/`.js` grammar files, since the current repository snapshot's `.ne` and compiled `.js` grammars appear consistent (I could not run `nearleyc` or diff the compiled output against the source within this read-only environment to prove an actual current drift). The exploitability is structural: (1) a maintainer edits `formula/grammars/oscript.ne` or `formula/grammars/ojson.ne` to add a restriction, (2) forgets to run `yarn compileGrammar:oscript`/`compileGrammar:ojson` (or runs it but forgets to commit the regenerated file), (3) the released node still uses the old `formula/grammars/oscript.js`/`ojson.js` loaded by `formula/validation.js:5` and `formula/evaluation.js`, so an AA author or trigger sender can post a `definition` or trigger `data` payload using the syntax that was supposed to be newly rejected, and it will still validate and execute successfully. Confirming an actual present-day instance of drift would require running the `nearleyc` build locally against the committed `.ne` files and diffing against `formula/grammars/oscript.js`/`ojson.js`, which is outside the capability of this read-only code index; a Devin session with terminal access could perform that verification directly.

### Citations

**File:** formula/validation.js (L1-5)
```javascript
/*jslint node: true */
"use strict";
const util = require('util');
var nearley = require("nearley");
var grammar = require("./grammars/oscript.js");
```

**File:** formula/grammars/oscript.ne (L211-270)
```text
	if (v.type === 'local_var_name')
		v = v.value.substr(1);
	return addLocation(['local_var', v], d[0]);
}  %}

local_var_assignment -> local_var (%dotSelector|"[" expr:? "]"):* "=" (expr|func_declaration) ";" {% function(d) {
	var selectors = null;
	if (d[1] && d[1].length)
		selectors = d[1].map(function(item){
			if (item[0].type === 'dotSelector')
				return item[0].value.substr(1);
			else
				return item[1];
		});
	return addLocation(['local_var_assignment', d[0][1], d[3][0], selectors], d); 
} %}

state_var_assignment -> "var" "[" expr "]" ("="|"+="|"-="|"*="|"/="|"%="|"||=") expr ";" {% function(d) { return addLocation(['state_var_assignment', d[2], d[5], d[4][0].value], d); } %}

response_var_assignment -> "response" "[" expr "]" "=" expr ";" {% function(d) { return addLocation(['response_var_assignment', d[2], d[5]], d); } %}

search_fields -> (%dotSelector):+ {% function(d) {
/*	var fields = [d[0].value];
	if (d[1] && d[1].length)
		fields = fields.concat(d[1].map(field => field[0].value.substr(1)));
	return fields;*/
	return d[0].map(field => field[0].value.substr(1));
} %}

search_param ->  search_fields comparisonOperator (expr|"none")  {% function(d) { return addLocation([d[0], d[1], d[2][0]], d); } %}

search_param_list -> search_param ("," search_param):*  {% function(d) { return addLocation([d[0]].concat(d[1].map(function (item) {return item[1];})), d);   } %}


arguments_list -> %local_var_name:? ("," %local_var_name):*  {% function(d) {
	var arr = d[0] ? [d[0].value.substr(1)] : [];
	return arr.concat(d[1].map(function (item) {return item[1].value.substr(1);}));
} %}

func_declaration -> ("(" arguments_list ")" | arguments_list) "=>" (expr | "{" main "}") {% function(d, location, reject) {
		var arglist = d[0][0].type === 'leftParen' ? d[0][1] : d[0][0];
		var bBlock = d[2][0].type === 'braceLeft';
		var body = bBlock ? d[2][1] : d[2][0];
		if (!bBlock && body[0] === 'dictionary' && body[1].length === 0) // empty dictionary looks the same as empty function
			return reject;
		return addLocation(['func_declaration', arglist, body], d); 
	} %}

func_call -> %local_var_name "(" expr_list ")"    {% function(d) {return addLocation(['func_call', d[0].value.substr(1), d[2]], d); } %}
remote_func_call -> remote_func "(" expr_list ")"  {% function(d) {
	return addLocation(['remote_func_call', d[0][1], d[0][2], d[0][3], d[2]], d); 
} %}
remote_func 
	-> (%addressValue|local_var) "." %local_var_name  
	{% function(d) {
		var remote_aa = d[0][0];
		if (remote_aa.type === 'addressValue')
			remote_aa = remote_aa.value;
		return addLocation(['remote_func', remote_aa, null, d[2].value.substr(1)], d); 
	} %}
```

**File:** formula/grammars/ojson.ne (L1-90)
```text
@{%

const moo = require('moo')

const lexer = moo.states({
	main: {
		space: {match: /\s+/, lineBreaks: true},
		comment: /\/\/.*$/,
		blockComment: { match: /\/\*[^]*?\*\//, lineBreaks: true },
		formulaDoubleStart: { match: '"{', push: 'formulaDouble' },
		formulaSingleStart: { match: "'{", push: 'formulaSingle' },
		formulaBackStart: { match: '`{', push: 'formulaBack' },
		decimal: /(?:[+-])?(?:[0-9]|[1-9][0-9]+)(?:\.[0-9]+)?(?:[eE][-+]?[0-9]+)?\b/,
		word: {
			match: /[a-zA-Z0-9_]+/,
			type: moo.keywords({
        false: 'false',
        true: 'true',
    	}),
		},
		autonomous_agent: [
			/'autonomous agent'/,
			/"autonomous agent"/,
			/`autonomous agent`/,
		],
		quotedString: [
			/'(?:[^'\\\n]|\\.)*'/,
			/"(?:[^"\\\n]|\\.)*"/,
			/`(?:[^`\\\n]|\\.)*`/,
		],
		'{': '{',
		'}': '}',
		'[': '[',
		']': ']',
		':': ':',
		',': ','
	},
	formulaDouble: {
		formulaDoubleEnd: { match: '}"', pop: 1 },
		formula: {match: /[\s\S]+?(?=}")/, lineBreaks: true},
	},
	formulaSingle: {
		formulaSingleEnd: { match: "}'", pop: 1 },
		formula: {match: /[\s\S]+?(?=}')/, lineBreaks: true},
	},
	formulaBack: {
		formulaBackEnd: { match: '}`', pop: 1 },
		formula: {match: /[\s\S]+?(?=}`)/, lineBreaks: true},
	},
})

var origNext = lexer.next;
	lexer.next = function () {
	var tok = origNext.call(this);
	if (tok) {
		switch (tok.type) {
			case 'space':
			case 'comment':
			case 'blockComment':
				return lexer.next();
		}
		return tok;
	}
	return undefined;
};

const TYPES = {
	STR: 'STR',
	PAIR: 'PAIR',
	TRUE: 'TRUE',
	FALSE: 'FALSE',
	ARRAY: 'ARRAY',
	OBJECT: 'OBJECT',
	DECIMAL: 'DECIMAL',
	FORMULA: 'FORMULA',
}

const c = (token) => ({
	col: token.col,
	line: token.line,
	offset: token.offset,
	lineBreaks: token.lineBreaks,
})

const formula = (d) => ({
	type: TYPES.FORMULA,
	value: d[1] ? d[1].text : '',
	context: d[1] ? c(d[1]) : c(d[0])
})

```

**File:** formula/grammars/ojson.js (L1-88)
```javascript
// Generated automatically by nearley, version 2.16.0
// http://github.com/Hardmath123/nearley
(function () {
function id(x) { return x[0]; }


const moo = require('moo')

const lexer = moo.states({
	main: {
		space: {match: /\s+/, lineBreaks: true},
		comment: /\/\/.*$/,
		blockComment: { match: /\/\*[^]*?\*\//, lineBreaks: true },
		formulaDoubleStart: { match: '"{', push: 'formulaDouble' },
		formulaSingleStart: { match: "'{", push: 'formulaSingle' },
		formulaBackStart: { match: '`{', push: 'formulaBack' },
		decimal: /(?:[+-])?(?:[0-9]|[1-9][0-9]+)(?:\.[0-9]+)?(?:[eE][-+]?[0-9]+)?\b/,
		word: {
			match: /[a-zA-Z0-9_]+/,
			type: moo.keywords({
        false: 'false',
        true: 'true',
    	}),
		},
		autonomous_agent: [
			/'autonomous agent'/,
			/"autonomous agent"/,
			/`autonomous agent`/,
		],
		quotedString: [
			/'(?:[^'\\\n]|\\.)*'/,
			/"(?:[^"\\\n]|\\.)*"/,
			/`(?:[^`\\\n]|\\.)*`/,
		],
		'{': '{',
		'}': '}',
		'[': '[',
		']': ']',
		':': ':',
		',': ','
	},
	formulaDouble: {
		formulaDoubleEnd: { match: '}"', pop: 1 },
		formula: {match: /[\s\S]+?(?=}")/, lineBreaks: true},
	},
	formulaSingle: {
		formulaSingleEnd: { match: "}'", pop: 1 },
		formula: {match: /[\s\S]+?(?=}')/, lineBreaks: true},
	},
	formulaBack: {
		formulaBackEnd: { match: '}`', pop: 1 },
		formula: {match: /[\s\S]+?(?=}`)/, lineBreaks: true},
	},
})

var origNext = lexer.next;
	lexer.next = function () {
	var tok = origNext.call(this);
	if (tok) {
		switch (tok.type) {
			case 'space':
			case 'comment':
			case 'blockComment':
				return lexer.next();
		}
		return tok;
	}
	return undefined;
};

const TYPES = {
	STR: 'STR',
	PAIR: 'PAIR',
	TRUE: 'TRUE',
	FALSE: 'FALSE',
	ARRAY: 'ARRAY',
	OBJECT: 'OBJECT',
	DECIMAL: 'DECIMAL',
	FORMULA: 'FORMULA',
}

const c = (token) => ({
	col: token.col,
	line: token.line,
	offset: token.offset,
	lineBreaks: token.lineBreaks,
})

```

**File:** package.json (L48-52)
```json
  "scripts": {
    "test": "yarn ava --timeout=60s --concurrency=1 --fail-fast --verbose",
    "compileGrammar:oscript": "nearleyc ./formula/grammars/oscript.ne -o ./formula/grammars/oscript.js",
    "compileGrammar:ojson": "nearleyc ./formula/grammars/ojson.ne -o ./formula/grammars/ojson.js"
  },
```
