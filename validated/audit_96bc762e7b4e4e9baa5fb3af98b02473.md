### Title
Incomplete character-class escaping in oscript `has_only()` allows unescaped `^` to invert filter semantics - (File: `formula/evaluation.js`)

### Summary
The `has_only` oscript operator builds a JavaScript regular-expression character class directly from an oscript string operand and only escapes the closing bracket `]`. It never escapes (or rejects) a leading `^`, which is the regex metacharacter that negates a character class. Any AA whose logic passes an attacker/trigger-influenced string into the second argument of `has_only()` can have its "characters must be only from set X" check silently flipped into "characters must be anything except set X," exactly the same class of bug as CVE-2026-44617: escaping was implemented for one metacharacter (analogous to RFC 4514 DN-escaping) while a different, structurally significant metacharacter of the actual target grammar (regex character-class syntax, analogous to RFC 4515 filter syntax) was left unescaped.

### Finding Description
`has_only(str, charset)` is implemented in [1](#0-0)  as:
```
if (sub.match(/\\]/) || sub[sub.length - 1] === '\\')
    return setFatalError("invalid character group: " + sub, { arr }, false, cb);
sub = sub.replace(/]/g, '\\]'); // don't allow to close the group early
var bMatches = new RegExp("^[" + sub + "]*$").test(str);
```
The comment "don't allow to close the group early" shows the author's intent: prevent the attacker-controlled string from prematurely closing the `[...]` character-class and injecting arbitrary regex outside of it. Only `]` is neutralized for that purpose. However, inside a JS/PCRE-style character class, a leading `^` (i.e., `[^...]`) has special structural meaning: it negates the whole class. The code does not strip, escape, or reject a leading `^` in `sub`, so `new RegExp("^[" + sub + "]*$")` can become `^[^...]*$` — a negated class — whenever `sub` begins with `^`.

This mirrors the LDAP incomplete-fix bug class in the report: an escaping routine designed for one syntax subset (closing bracket only) is applied to a richer grammar (a full regex character class) that has other structurally significant metacharacters, so the "safe" escaping is incomplete and an attacker who controls the classified string can change the meaning of the whole matching expression rather than just injecting literal characters.

Grammar/production for `has_only` is defined in [2](#0-1)  and the validator counts it only as a normal 2-arg string op with no special-casing for the pattern operand, in [3](#0-2) , confirming there is no additional restriction placed on the "charset" argument beyond generic expression evaluation — it can be any oscript-evaluated string, including one derived from `trigger.data` or `params`.

### Impact Explanation
`has_only()` is documented/tested as a whitelist-style input sanitizer inside AA formulas (see [4](#0-3) , where AA authors use it to assert "this string contains only characters from this set"). If an AA design passes any attacker-influenced value (from `trigger.data`, previous AA responses, or state vars seeded by triggers) as the *pattern/charset* argument — a realistic pattern for generic/config-driven AAs that let users or governance supply an "allowed characters" rule — a trigger sender can prefix that value with `^` to invert the check. A validation that was meant to reject unsafe characters (quotes, delimiters, control characters, etc.) in a field then accepts exactly the opposite set, letting attacker-chosen dangerous characters flow into whatever the AA does next with that value (e.g., building further definitions/addresses, gating a payout branch, or feeding another string operation). Depending on how a given AA uses the (falsely) validated string downstream, this can lead to AA logic making the wrong decision, causing AA fund loss/misdirection or logic bypass. This is a Medium-severity issue: it is a genuine incomplete-escaping/logic-inversion vulnerability, but concrete impact depends on the calling AA's design (it is a footgun in the oscript standard library rather than a network-wide consensus defect).

### Likelihood Explanation
Exploitability requires an AA whose author routes an attacker-influenced string into the pattern argument of `has_only()`. This is a plausible but not universal pattern (generic validators, registries, configurable-rule AAs). The primitive itself is trivially triggerable by any AA trigger sender with no special privileges — they simply need to control (directly or via a previously-stored, trigger-updatable value) the pattern string and prefix it with `^`.

### Recommendation
In the `has_only` handler in [1](#0-0) , escape/neutralize every regex-significant character in `sub` for the position it will occupy inside a character class, not just `]`. At minimum:
- Reject or escape a leading `^` (e.g. escape as `\^` or reject the pattern), so it can never re-enter negation semantics.
- Escape `-` and `\` consistently (currently `\` is only checked for a dangling trailing backslash, not escaped elsewhere), and document/restrict which regex escapes (`\w`, `\d`, etc.) are intentionally allowed vs. accidentally passed through.
- Add a unit test asserting `has_only("x", "^abc")` treats `^` as a literal character to match, not as class negation.

### Proof of Concept
```js
// formula/evaluation.js, has_only case
var sub = "^abc";                 // attacker-controlled pattern (e.g. trigger.data.pattern)
sub = sub.replace(/]/g, '\\]');   // no-op here, ']' escaping only
var re = new RegExp("^[" + sub + "]*$");
console.log(re.test("xyz!$"));    // true: negated class "not a,b,c" matches "xyz!$"
// An AA author intending has_only(value, "^abc") to mean
// "value may contain only the literal characters ^, a, b, c"
// instead gets "value may contain anything except a, b, c",
// letting characters like quotes/delimiters/control chars pass validation.
```

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

**File:** formula/grammars/oscript.ne (L423-423)
```text
    | "has_only" "(" expr "," expr ")"    {% function(d) {return addLocation(['has_only', d[2], d[4]], d); } %}
```

**File:** formula/validation.js (L1053-1068)
```javascript
			case 'has_only':
				if (mci < constants.aa2UpgradeMci)
					return cb(op + " not activated yet");
				complexity++;
			case 'starts_with':
			case 'ends_with':
			case 'contains':
			case 'index_of':
				var str = arr[1];
				var sub = arr[2];
				evaluate(str, function (err) {
					if (err)
						return cb(err);
					evaluate(sub, cb);
				});
				break;
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
