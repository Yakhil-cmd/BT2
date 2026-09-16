### Title
Regex character-class injection via unsanitized `has_only()` charset argument allows negation of oscript/AA input-validation checks - (File: formula/evaluation.js)

### Summary
The `has_only(str, charset)` oscript/AA formula function builds a JavaScript regular expression by directly concatenating an attacker-influenceable `charset` string into a regex character class (`"^[" + sub + "]*$"`), only escaping `]` and rejecting a trailing backslash. It does not prevent the `charset` argument from starting with `^`, which is the character-class negation metacharacter. This mirrors the ingress-nginx `auth-tls-match-cn` bug class (CWE-15/CWE-20): an untrusted value is embedded into a security-relevant matching expression without full sanitization, letting the value "break out" of its intended data context and change the semantics of the check (there, nginx config directives; here, the meaning of the regex construct).

### Finding Description
`has_only` is implemented in `formula/evaluation.js`: [1](#0-0) 
```
if (op === 'has_only') {
    try {
        if (sub.match(/\\]/) || sub[sub.length - 1] === '\\')
            return setFatalError("invalid character group: " + sub, { arr }, false, cb);
        sub = sub.replace(/]/g, '\\]'); // don't allow to close the group early
        var bMatches = new RegExp("^[" + sub + "]*$").test(str);
    }
    ...
```
Both `str` and `sub` are the results of evaluating arbitrary oscript expressions [2](#0-1) , so `sub` can be derived from `trigger.data`, `trigger.output`, or other attacker-controlled trigger fields when an AA author writes something like `has_only(some_string, trigger.data.charset)` to validate that a value consists only of an allowed character set (a common oscript idiom for input sanitization, e.g. validating tickers, addresses, or textual identifiers before using them in further logic such as building keys, choosing outputs, or gating payments).

The only sanitization applied to `sub` is: (1) reject if it contains an escaped `]` sequence or ends in a bare backslash, and (2) escape literal `]` characters. There is no check preventing `sub` from beginning with `^`. In a JS/PCRE character class, a leading `^` right after `[` negates the class (e.g., `[^abc]` matches anything **except** a/b/c). Because the code constructs the pattern as `"^[" + sub + "]*$"`, if the caller-supplied `sub` starts with `^`, the resulting pattern becomes `^[^<rest of sub>]*$` — the character class is inverted. This flips the meaning of `has_only` from "string consists only of these characters" to "string consists only of characters NOT in this set," a complete semantic inversion of a function whose name and documented purpose imply an allow-list character check.

This is directly analogous to the ingress-nginx flaw: an attacker-controlled string intended to be treated as an inert value (a CN string / a character set) is inserted into a security-sensitive construct without protecting the syntactic boundary that gives the surrounding construct special meaning, allowing the attacker to change what the construct actually checks.

### Impact Explanation
An AA author who uses `has_only(x, <attacker-controlled charset>)` as a guard before performing a state-changing or fund-moving action (e.g., "only proceed if the recipient identifier / asset ticker / textual key contains only permitted characters") can have that guard silently inverted by a trigger sender who supplies a charset argument beginning with `^`. Depending on how the AA is written, this can let an attacker bypass an intended allow-list check embedded in the AA's decision logic, potentially leading to AA fund loss (unintended payment/output branch taken), corrupted state variable content, or other logic bypasses that were meant to be enforced by `has_only`. The severity is bounded by how AA authors use the primitive, but the underlying primitive itself does not behave as documented/expected under attacker-chosen input, which is the essence of the CWE-15/CWE-20 config/logic-injection class in the reference CVE.

### Likelihood Explanation
Any address can post an AA trigger with arbitrary `data` fields that reach formula evaluation as string values [3](#0-2) , so exploitation requires only that a deployed AA passes trigger-influenced data as the `sub`/charset argument to `has_only` — a realistic and encouraged pattern for validating textual trigger input in oscript. No special privileges beyond posting a normal AA trigger unit are needed.

### Recommendation
Reject (or escape) a leading `^` in the `sub` argument before it is placed into the character class (in addition to the existing `]`/trailing-backslash checks), e.g. escape it as `\^` when it is the first character, or explicitly return a fatal error if `sub.charAt(0) === '^'`. Add regression tests confirming `has_only(str, "^...")` behaves as an allow-list match on the literal `^` character rather than as class negation.

### Proof of Concept
1. Deploy an AA whose bounce/response logic includes something like:
```
if: `{has_only(trigger.data.name, trigger.data.charset)}`
```
intended so the trigger sender can only supply `name` consisting of characters from an AA-defined safe set, with `charset` normally fixed by the AA author. If instead a more permissive contract accepts `charset` from trigger data directly (or an AA re-uses a validation helper this way), an attacker triggers with:
```
trigger.data = { name: "; DROP everything special;", charset: "^" }
```
`has_only` builds the pattern `new RegExp("^[^]*$")`, which matches essentially any string (character class negating an empty set matches everything), instead of the intended narrow allow-list, causing the guard to always pass and the "sanitized-input-only" branch of the AA to execute regardless of the actual content of `trigger.data.name`.

### Citations

**File:** formula/evaluation.js (L2010-2028)
```javascript
			case 'starts_with':
			case 'ends_with':
			case 'contains':
			case 'has_only':
			case 'index_of':
				var str_expr = arr[1];
				var sub_expr = arr[2];
				evaluate(str_expr, function (res) {
					if (fatal_error)
						return cb(false);
					if (res instanceof wrappedObject)
						res = true;
					var str = res.toString();
					evaluate(sub_expr, function (sub_res) {
						if (fatal_error)
							return cb(false);
						if (sub_res instanceof wrappedObject)
							sub_res = true;
						var sub = sub_res.toString();
```

**File:** formula/evaluation.js (L2037-2050)
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
						}
```
