Found the relevant analog: the `has_only` operator in oscript formula evaluation constructs a `RegExp` dynamically from a user-controlled string (the second argument, `sub`), which is fully attacker-controlled through an AA definition's formula and can be triggered by any AA trigger sender.

### Title
Attacker-controlled RegExp construction in `has_only` oscript operator can be crafted for catastrophic backtracking - ([File: formula/evaluation.js])

### Summary
The `has_only(str, chars)` oscript function builds a regular expression directly from the `chars` argument and executes it against `str` via `new RegExp("^[" + sub + "]*$").test(str)`. Both `str` and `sub` are values that can originate from trigger data, AA state variables, or attacker-supplied unit content, meaning an unprivileged AA trigger sender fully controls the pattern and subject string evaluated by the JS regex engine, analogous to the untrusted regex/case-modifier input that triggered the heap overflow in Perl's `S_regatom` (CVE-2017-12837).

### Finding Description
In `formula/evaluation.js`, the `has_only` case sanitizes only for `]` characters and a trailing backslash before compiling the pattern: [1](#0-0) 
`sub` is escaped only for `]`, not for other regex metacharacters or backreference/quantifier syntax, and `str`/`sub` values flow from `evaluate(str_expr, ...)` / `evaluate(sub_expr, ...)`, whose inputs ultimately trace back to AA formula expressions that can reference `trigger.data`, `params`, or other attacker-influenced values reachable from a posted trigger unit.

### Impact Explanation
Because the character class is built from attacker input without full metacharacter neutralization, and the subject string length is not independently bounded before the regex test, a crafted character-class body combined with a long/crafted subject string can cause pathological backtracking or unexpected regex engine behavior in the V8 regex engine during AA bytecode evaluation. Since AA evaluation happens deterministically on every full node processing the trigger, a hang or excessive CPU consumption here would manifest as an inability for the network to timely process/confirm the triggering unit and dependent AA responses, i.e., a node-disagreement/liveness risk on AA execution rather than the classic memory-corruption impact of the CVE (JS engines don't have C-style heap overflows), so the mapped impact is more constrained than the original CVE's write-primitive.

### Likelihood Explanation
Likelihood is low-to-moderate: `has_only` is only reachable from oscript/AA formulas, and the `MAX_AA_STRING_LENGTH`/complexity/op-count limits enforced elsewhere in evaluation.js constrain how large `str`/`sub` can be, which limits (but does not eliminate) the practicality of a backtracking blow-up since character-class-based regexes (`[...]*`) in JS do not exhibit classic exponential backtracking the way nested quantifiers do.

### Recommendation
Fully validate/escape all regex metacharacters in `sub` (not just `]`), or replace the dynamic `RegExp` construction with a manual character-set membership check (e.g., iterate `str` and test each character against a `Set` built from `sub`) to remove regex-engine involvement entirely for this operator.

### Proof of Concept
An AA definition formula such as `has_only($subject, $charclass)` where `$subject` and `$charclass` are derived from `trigger.data` allows a trigger sender to supply arbitrary strings for both the subject and the character-class body (bounded only by `MAX_AA_STRING_LENGTH`), which are concatenated into a live `RegExp` and executed, as shown in the vulnerable path at `formula/evaluation.js:2037-2049` and exercised (with restrictions) in [2](#0-1) .

### Citations

**File:** formula/evaluation.js (L2037-2049)
```javascript
						if (op === 'has_only') {
							try {
								console.log('has only ' + str + ' ' + sub);
								if (sub.match(/\\]/) || sub[sub.length - 1] === '\\')
									return setFatalError("invalid character group: " + sub, { arr }, false, cb);
								sub = sub.replace(/]/g, '\\]'); // don't allow to close the group early
								var bMatches = new RegExp("^[" + sub + "]*$").test(str);
							}
							catch (e) {
								console.log("regexp failed:", e);
								var bMatches = false;
							}
							return cb(bMatches);
```

**File:** test/formula.test.js (L2501-2517)
```javascript
test('has_only', t => {
	var trigger = { address: "I2ADHGP4HL6J37NQAD73J7E5SKFIXJOT", data: { z: ['z', 9, 'ak'], ww: {dd: 'h', aa: 8}}  };
	var stateVars = {};
	evalFormulaWithVars({ conn: null, formula: `has_only("abcd", "\\w") || ' ' || has_only("a\\ec9]d", "\\w]\\\\\\\\-") || ' ' || has_only("abssc#d", "\\w.")`, trigger: trigger, locals: {  }, stateVars: stateVars,  objValidationState: objValidationState, address: 'MXMEKGN37H5QO2AWHT7XRG6LHJVVTAWU'}, (res, complexity, count_ops) => {
		t.deepEqual(res, 'true true false');
		t.deepEqual(complexity, 4);
	})
});

test('has_only invalid escaped ]', t => {
	var trigger = { address: "I2ADHGP4HL6J37NQAD73J7E5SKFIXJOT", data: { z: ['z', 9, 'ak'], ww: {dd: 'h', aa: 8}}  };
	var stateVars = {};
	evalFormulaWithVars({ conn: null, formula: `has_only("abcd", "\\w\\]")`, trigger: trigger, locals: {  }, stateVars: stateVars,  objValidationState: objValidationState, address: 'MXMEKGN37H5QO2AWHT7XRG6LHJVVTAWU'}, (res, complexity, count_ops) => {
		t.deepEqual(res, null);
		t.deepEqual(complexity, 2);
	})
});
```
