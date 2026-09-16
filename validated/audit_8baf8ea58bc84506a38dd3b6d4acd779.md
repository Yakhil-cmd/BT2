### Title
`has_only()` oscript builtin can be inverted into a blacklist via unescaped leading `^` in the character-class argument, silently defeating input-restriction checks written by AA authors - ([File: formula/evaluation.js])

### Summary
The `has_only(str, charset)` builtin, exposed to any Autonomous Agent (AA) author for use in oscript trigger-handling code, is implemented by embedding the attacker/AA-influenced `charset` argument directly inside a JavaScript regular-expression character class (`[...]`). Only the closing bracket `]` and a trailing backslash are sanitized; a leading `^` is not rejected or escaped. Since `^` as the first character of a regex character class negates the class, an AA whose logic derives the `charset` from trigger data (or any value that ultimately reaches `has_only` unescaped) can have its "characters must be only from this allow-list" check silently flipped into "characters must be none of this list", defeating the intended input restriction. This mirrors the CVE-2023-32370 bug class: a pattern/wildcard-based restriction mechanism that can fail to actually restrict when a crafted pattern (there, a wildcard domain; here, a leading `^`) is supplied.

### Finding Description
`has_only` is evaluated in `formula/evaluation.js`: [1](#0-0) 

```js
if (op === 'has_only') {
    try {
        console.log('has only ' + str + ' ' + sub);
        if (sub.match(/\\]/) || sub[sub.length - 1] === '\\')
            return setFatalError("invalid character group: " + sub, { arr }, false, cb);
        sub = sub.replace(/]/g, '\\]'); // don't allow to close the group early
        var bMatches = new RegExp("^[" + sub + "]*$").test(str);
    }
    ...
```

Only two hazards are checked: an escaped `]` (`\]`) and a trailing unescaped backslash. There is no check preventing `sub` from starting with `^`, and no escaping is performed for `^`. In JavaScript regex syntax, `[^...]` matches any character *not* in the set, the exact opposite of `[...]`. This means:

- `has_only("abcd", "abcd")` → regex `^[abcd]*$` → `true` (as intended, whitelist).
- `has_only("abcd", "^abcd")` → regex `^[^abcd]*$` → `false` for `"abcd"`, but `true` for a string that contains *none* of a/b/c/d — the semantics of the check are completely inverted for any charset value that begins with `^`.

The bug is purely in the ocore-provided oscript function, not in any specific AA's business logic: it is `evaluate()` in `formula/evaluation.js` that builds the regex directly from the untrusted operand without escaping `^`.

`has_only` is a documented, generally-available oscript function (see keyword list and grammar rule) intended for AAs to validate that user/trigger-supplied strings only contain safe characters before using them (e.g., in comparisons, storage keys, or as inputs to other operations): [2](#0-1) 

Any AA that builds the `charset` operand dynamically (e.g., from `trigger.data`, `params`, or values previously validated with insufficient constraints) can have this whitelist check inverted by an attacker who controls that operand, since nothing downstream re-checks for a leading `^`. The AA-side test suite for `has_only` only exercises the escaping issues (`]` and trailing `\`), confirming the leading-`^` case was not considered by the implementers: [3](#0-2) 

### Impact Explanation
Any AA that relies on `has_only()` to enforce that some trigger-controlled string only contains an allow-listed set of characters (a common oscript idiom for validating identifiers, symbols, or other free-text fields before using them to gate logic, build storage keys, or route funds) can have that validation silently inverted by a malicious trigger sender who influences the charset operand with a leading `^`. Since `has_only` returns a boolean consumed directly by AA `if`/`require`/`bounce` logic, an inverted check can let a value that should have been rejected pass validation, or reject a value that should have passed — this can be leveraged by an unprivileged AA-trigger sender to steer AA control flow in unintended ways, including paths that release/allocate AA funds under conditions the AA author believed were being screened out. This is a logic flaw within ocore's own formula evaluator (`formula/evaluation.js`), not an application bug, so it affects every AA that uses `has_only` with an attacker-influenced pattern.

### Likelihood Explanation
Exploitation requires only sending a normal trigger unit to an AA whose oscript code calls `has_only()` with a charset value that is (even partially) derived from trigger data — a plausible and unremarkable oscript pattern for building configurable/whitelist-validation logic. No special privileges, node compromise, or protocol-level access are needed; a single crafted unit is sufficient to flip the semantics of the check for that AA invocation.

### Recommendation
In the `has_only` handler in `formula/evaluation.js` (and the mirrored complexity/validation logic in `formula/validation.js`), reject (or escape) a leading `^` in the `charset` operand before constructing the character-class regex, e.g.:
```js
if (sub[0] === '^')
    return setFatalError("invalid character group: " + sub, { arr }, false, cb);
```
or escape it as `\^` at position 0 so it is always treated literally rather than as a negation operator, restoring guaranteed whitelist semantics regardless of caller-supplied input.

### Proof of Concept
Given an oscript expression evaluated through `evalFormulaWithVars` (as in the existing test harness):
```js
has_only("abcd", "abcd")     // -> "true"  (whitelist works as intended)
has_only("abcd", "^abcd")    // -> "false" (semantics silently inverted: same string now fails an "allow abcd" check)
has_only("xyz",  "^abcd")    // -> "true"  (a string containing none of a/b/c/d is now accepted by what looks like an "only abcd" whitelist)
```
Any AA logic of the form `require(has_only($user_value, $expected_charset) ...)` where `$expected_charset` can be influenced by trigger data will have its restriction bypassed by prefixing the charset with `^`.

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

**File:** formula/grammars/oscript.ne (L420-423)
```text
    | "starts_with" "(" expr "," expr ")"    {% function(d) {return addLocation(['starts_with', d[2], d[4]], d); } %}
    | "ends_with" "(" expr "," expr ")"    {% function(d) {return addLocation(['ends_with', d[2], d[4]], d); } %}
    | "contains" "(" expr "," expr ")"    {% function(d) {return addLocation(['contains', d[2], d[4]], d); } %}
    | "has_only" "(" expr "," expr ")"    {% function(d) {return addLocation(['has_only', d[2], d[4]], d); } %}
```

**File:** test/formula.test.js (L2501-2526)
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

test('has_only invalid final \\', t => {
	var trigger = { address: "I2ADHGP4HL6J37NQAD73J7E5SKFIXJOT", data: { z: ['z', 9, 'ak'], ww: {dd: 'h', aa: 8}}  };
	var stateVars = {};
	evalFormulaWithVars({ conn: null, formula: `has_only("abcd", "a-z\\\\")`, trigger: trigger, locals: {  }, stateVars: stateVars,  objValidationState: objValidationState, address: 'MXMEKGN37H5QO2AWHT7XRG6LHJVVTAWU'}, (res, complexity, count_ops) => {
		t.deepEqual(res, null);
		t.deepEqual(complexity, 2);
	})
});
```
