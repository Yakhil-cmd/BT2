### Title
Missing callback path in `formula/evaluation.js:evaluate()` when the oscript parser produces zero results — silent hang instead of error propagation - ([File: formula/evaluation.js])

### Summary
`formula/evaluation.js` parses each oscript formula with a nearley parser and then branches on the shape of `parser.results`. The code only handles two cases explicitly: exactly one successful parse (evaluate it), and more than one parse (`'ambiguous grammar'`). It never handles the case where `parser.results.length === 0`, which nearley returns (without throwing) when the fed input is a syntactically valid *prefix* of the grammar but never reaches a completed parse. In that case the enclosing `callback` is never invoked at all — the parsing error is silently swallowed instead of being propagated, mirroring the CVE-class root cause in the report (parser continues without surfacing an error, and the caller that expects a definite result mishandles the missing-result state).

### Finding Description
In `exports.evaluate` in `formula/evaluation.js`: [1](#0-0) 

```js
if (parser.results && parser.results.length === 1 && parser.results[0]) {
    evaluate(parser.results[0], res => { ... }, true);
} else {
    if (parser.results.length > 1) {
        console.log('ambiguous grammar', parser.results);
        callback('ambiguous grammar', null);
    }
    // no else branch: if parser.results.length === 0, `callback` is NEVER called
}
```

Compare this to the sibling formula validator in `formula/validation.js`, which handles the exact same three cases correctly and always calls back: [2](#0-1) 

The nearley parser (`parser.feed(formula)` at [3](#0-2)  ) only *throws* when the fed text is not a valid prefix of any parse path (a "dead end"); it does not throw when the text is a valid but incomplete prefix — in that state `parser.results` legitimately returns an empty array (length 0) even though `parser.feed()` succeeded. This is analogous to the libxml2 "recovery mode" behavior described in the report: parsing proceeds without raising an error, and the caller (here, `exports.evaluate`) fails to detect/propagate the incomplete-parse condition, leaving the consumer to operate on an undefined/missing result instead of a well-formed error.

Every caller of `exports.evaluate` supplies a `callback` and assumes it is *always* invoked eventually — e.g. `formula/evaluation.js:callGetter` at [4](#0-3)  and the trigger-handling code in `aa_composer.js` at [5](#0-4) . All of this AA/trigger processing executes under a per-address mutex lock (`mutex.lock(arrAuthorAddresses, ...)` in `validation.js`, and address-scoped locks in `aa_composer.js`), and inside `async.series`/`async.eachSeries` control flow chains. If the internal `callback` in `evaluate()` is never invoked, the outer `cb`/`callback` chain that depends on it also never fires.

### Impact Explanation
A formula string that legitimately validates via `formula/validation.js:exports.validate` (which does propagate the "parser failed"/"ambiguous grammar" errors and thus rejects genuinely malformed input) is not guaranteed to behave identically inside `exports.evaluate`, because `evaluate()` re-parses the *fixed* formula (`fixFormula(opts.formula, opts.address)` at [6](#0-5) ) independently, using its own parser instance and its own cache keyed by formula text. Any code path where the text handed to `evaluate()` differs from what was validated, or where a stale/incomplete cache entry (`cache[formula]`, populated from a possibly incomplete `parser.results`, see [7](#0-6) ) is reused, can result in `parser.results.length === 0` at evaluation time even though validation passed. When that happens the AA-trigger evaluation callback never fires:
- The mutex-protected chain (`aa_composer.js` trigger handling, and `validation.js`'s per-author-address mutex) stalls indefinitely for that address.
- Because AA processing is sequential per mci/address in the write pipeline (`writer.js`/`aa_composer.js`), a stuck evaluation can block subsequent unit/trigger processing for the affected address, which can manifest as AA fund/state freezing and, in the worst case, a node's inability to make forward progress validating/confirming new units that touch the affected AA or address — i.e. denial of availability, matching the "S:U/A:H"-style impact of the reported libxml2 CVE, achieved purely by data that reaches `evaluate()` from an untrusted trigger/AA definition.

### Likelihood Explanation
Reaching this code path requires being able to submit oscript/AA formulas or trigger data (which any unprivileged unit poster or AA-trigger sender can do) and requires crafting a formula whose *evaluation-time* parse is incomplete (0 results) despite having passed the separate validation-time parse. This depends on subtleties of the nearley grammar (a formula that is a valid partial prefix but doesn't reduce to a complete parse) and on the two independent parser/cache mechanisms in `validation.js` vs `evaluation.js` diverging for the same formula text. The exact combination of grammar rules that produce `results.length === 0` without `parser.feed` throwing was not confirmed by direct execution/testing in this review (no code-execution tools were available), so likelihood should be treated as uncertain/moderate pending confirmation of a concrete formula string that reproduces the zero-result state at evaluation time only.

### Recommendation
Add an explicit `else` branch (matching `formula/validation.js`) in `formula/evaluation.js:exports.evaluate` for the `parser.results.length === 0` (and any other non-1) case, always invoking `callback` with an explicit error (e.g. `'parser failed'`), so that no invocation of `evaluate()` can leave its callback unresolved:
```js
} else if (parser.results.length > 1) {
    callback('ambiguous grammar', null);
} else {
    callback('parse failed', null);
}
```
Additionally, audit the formula cache (`cache[formula]`) to ensure it never stores an empty-results parse silently, and verify that `fixFormula` cannot cause a formula validated under one text to be evaluated under different text without re-validation.

### Proof of Concept
Not independently verified by execution (no runtime/tooling available in this review). Conceptually: an attacker-controlled AA definition or trigger payload containing an oscript formula string that nearley's nearley `feed()` accepts as a valid prefix (no throw) but that never completes to a single derivation (`parser.results.length === 0`) would, when routed through `exports.evaluate` (e.g., via `aa_composer.js`'s trigger handling or `formula/evaluation.js:callGetter`), cause the internal `callback` to never be called, stalling the per-address mutex-protected processing chain indefinitely. Confirming a concrete formula string that reproduces `results.length === 0` at evaluation time (while passing `formula/validation.js`'s independent parse) requires running the nearley grammar (`formula/grammars/oscript.js`) directly, which was not available in this analysis.

### Citations

**File:** formula/evaluation.js (L66-66)
```javascript
	var formula = fixFormula(opts.formula, opts.address);
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

**File:** formula/evaluation.js (L3205-3231)
```javascript
	if (parser.results && parser.results.length === 1 && parser.results[0]) {
		evaluate(parser.results[0], res => {
			if (fatal_error) {
				callback(fatal_error, null);
			} else {
				if (early_return !== undefined)
					res = early_return;
				if (res instanceof wrappedObject)
					res = bObjectResultAllowed ? string_utils.cloneDeep(res.obj) : true;
				else if (Decimal.isDecimal(res)) {
					if (!isFiniteDecimal(res))
						return callback('result is not finite', null);
					res = toDoubleRange(res);
					res = (res.isInteger() && res.abs().lt(Number.MAX_SAFE_INTEGER)) ? res.toNumber() : res.toString();
				}
				else if (typeof res === 'string' && res.length > constants.MAX_AA_STRING_LENGTH)
					return callback('result string is too long', null);
				astTrace = [];
				callback(null, res);
			}
		}, true);
	} else {
		if (parser.results.length > 1) {
			console.log('ambiguous grammar', parser.results);
			callback('ambiguous grammar', null);
		}
	}
```

**File:** formula/evaluation.js (L3331-3336)
```javascript
		exports.evaluate(opts, astTrace, xpath, function (err, res) {
			if (res === null) 
				return cb(err.formattedError || "formula " + f + " failed: " + err);
			if (!hasOwnProperty(locals, getter))
				return cb("no such getter: " + JSON.stringify(getter));
			if (!(locals[getter] instanceof Func))
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

**File:** aa_composer.js (L817-826)
```javascript
					objValidationState: objValidationState,
					address: address
				};
				formulaParser.evaluate(opts, [], xpath + '/init', function (err, res) {
					if (res === null)
						return cb(err.formattedError || "formula " + value.init + " failed: " + err);
					delete value.init;
					replace(obj, name, path, locals, xpath, cb);
				});
			});
```
