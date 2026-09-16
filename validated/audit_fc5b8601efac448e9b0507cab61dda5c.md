### Title
Unbounded Earley-parser CPU blowup on malformed `formula` op in address/AA definitions - (File: definition.js)

### Summary
`ocore`'s `oscript`/`ojson` DSL is parsed with the `nearley` Earley-parser (`formula/grammars/oscript.js`, `formula/grammars/ojson.js`). Earley parsing is worst-case cubic (`O(n^3)`) in the length of the input, and degrades further when the grammar is ambiguous — which this grammar demonstrably is, since both `formula/validation.js` and `formula/evaluation.js` explicitly handle a `parser.results.length > 1` "ambiguous grammar" case. A `formula` op inside a plain address definition is user-supplied text up to 10,000 characters that is fed directly into this parser during ordinary unit/definition validation, with no bound on parse-tree ambiguity or a timeout, mirroring the CVE-2024-28871 bug class (malformed input driving pathological parser CPU cost).

### Finding Description
Any address definition may contain a `['formula', "<oscript text>"]` element. During `validateDefinition()` the `formula` case only checks non-emptiness and a raw length cap of 10,000 characters: [1](#0-0) 

That text is handed to `formulaParser.validate()`, which constructs a fresh `nearley.Parser` over the compiled `oscript.js` grammar and feeds the entire string in one shot: [2](#0-1) 

The grammar produced by nearley for `oscript.ne`/`ojson.ne` is not guaranteed unambiguous — the code explicitly anticipates and logs `'ambiguous grammar'` when `parser.results.length > 1`, both in the validator and the evaluator: [3](#0-2) [4](#0-3) 

Earley parsing with an ambiguous grammar can require tracking exponentially many derivations (or at minimum the generic `O(n^3)` worst case) as the input grows; there is no per-parse operation counter, wall-clock timeout, or restriction on nesting/branching before or during the `nearley.Parser.feed()` call. The only safeguards present anywhere in the formula pipeline (`MAX_COMPLEXITY`, `MAX_OPS`, `MAX_DEPTH`, the `count % 100` `setImmediate` throttle) apply only to the post-parse AST *evaluation*/*validation* walk, not to the raw text-to-AST parsing step itself, which is exactly where the CPU cost of an Earley parser with grammar ambiguity concentrates. Because `formula` text can reach 10,000 bytes and is only rejected as "too long" *after* the length check but *before* any complexity accounting, a poster can submit near-maximum-length formula text engineered to maximize grammar ambiguity/backtracking in `oscript.js`, and every full node that validates the containing unit's address definition will pay the same (potentially very large) parsing cost, with no way to bound or interrupt it mid-parse.

### Impact Explanation
`validateDefinition()` in `definition.js` is executed by every full node as part of ordinary consensus-critical unit/address-definition validation (this also applies transitively to AA definitions containing `formula`-typed fields via `aa_validation.js`/`formula/validation.js`, which reuse the identical parser and grammar). A single posted unit containing a pathological `formula` op can force every validating node in the network to spend disproportionate CPU parsing that one string. Because unit validation is synchronous per-unit gatekeeping before a unit can be accepted/relayed, an attacker able to repeatedly submit such units (each within normal size/fee limits) can degrade validation throughput network-wide, i.e., a network unable to confirm new units in a timely manner — one of the explicitly accepted impacts for this analog class.

### Likelihood Explanation
Any unprivileged unit poster can author an address definition (or use an AA definition template) containing a `formula` op; this requires no special privileges, keys, or node-level trust — only that `formulaUpgradeMci` has passed, which it has on both mainnet and testnet per `constants.js`. The 10,000-character length ceiling is generous, and crafting a formula string that maximizes nearley grammar ambiguity for `oscript.ne` (built from deeply overlapping operator/precedence rules such as `AS`, `MD`, `comp_expr`, `otherwise_expr`, `remote_func`, `with_selectors`, etc., visible in `formula/grammars/oscript.ne`) is a matter of grammar/DSL analysis rather than any cryptographic or race-condition difficulty. The only mitigating factor is that a proof-of-concept has not been executed against the live grammar to measure exact wall-clock blow-up, so the severity depends on how ambiguous the compiled grammar actually is in practice — this is flagged as unverified.

### Recommendation
- Impose a hard operation/time budget on the `nearley.Parser.feed()` call itself (e.g., abort/throw if internal Earley chart size or elapsed time exceeds a threshold), not just on the subsequent AST walk.
- Reduce/eliminate grammar ambiguity in `oscript.ne`/`ojson.ne` so that `parser.results.length` can never exceed 1 for well-formed programs, and reject any input that still produces multiple parses early with cheap detection.
- Consider replacing or supplementing the general Earley parser with a linear-time (e.g., recursive-descent/Pratt) parser for the deterministic subset of the language actually needed, especially for the consensus-critical `formula` op path in `definition.js`.
- Lower the `formula` length ceiling further and/or make it dependent on measured parse cost rather than a flat character count, and add fuzzing/differential testing specifically targeting nearley ambiguity blow-up for both `oscript.js` and `ojson.js`.

### Proof of Concept
Not independently verified against the live grammar (would require running `nearley.Parser` over `formula/grammars/oscript.js` with crafted ~10,000-byte input designed to stack ambiguous productions such as nested `otherwise`/ternary/`or`/`and`/comparison chains, `with_selectors`, and `remote_func`/`func_call` combinations, then measuring parse time). Conceptually:
1. Construct an oscript `formula` string close to the 10,000-character limit consisting of deeply nested/overlapping expressions that are known to be ambiguous or near-ambiguous in the `oscript.ne` grammar (e.g., long chains of `otherwise`/ternary operators combined with optional trailing clauses that the grammar can parse multiple ways).
2. Wrap it in a minimal valid address definition: `["sig", {"pubkey": "..."}]` is replaced/augmented with `["formula", "<crafted text>"]` as one branch of an `or`/`and` definition satisfying the "must have a signature" rule.
3. Post a unit whose author uses this definition (or an AA definition template with an equivalent `formula`-bearing field).
4. Measure CPU time spent inside `formulaParser.validate()` / `nearley.Parser.feed()` on a validating node versus a similarly-sized non-ambiguous formula, to confirm super-linear scaling.

### Citations

**File:** definition.js (L594-613)
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

**File:** formula/evaluation.js (L3226-3231)
```javascript
	} else {
		if (parser.results.length > 1) {
			console.log('ambiguous grammar', parser.results);
			callback('ambiguous grammar', null);
		}
	}
```
