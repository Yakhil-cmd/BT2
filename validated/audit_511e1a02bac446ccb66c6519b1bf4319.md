Confirmed: `has_only(str, chars)` builds `new RegExp("^[" + sub + "]*$")` where `sub` (the "allowed characters" argument) is attacker/trigger-controllable and only defended against `]` and a trailing `\` (to avoid breaking the character class syntax), per [1](#0-0) . Nothing prevents `sub` from starting with `^`, which in a JS regex character class means negation. So an AA author who writes `has_only(trigger.data.x, trigger.data.allowed_chars)` intending "x must contain only these characters" can have the semantics inverted by a trigger sender supplying `allowed_chars="^"+something`, turning the check into "x must NOT contain these characters" — the opposite of the intended allowlist. The AA developer template validation only checks that the arguments are syntactically valid formulas (`formula/validation.js:1053-1068`), never restricts the allowed-character-set string itself, so this loophole is not caught before deployment either.

### Title
Character-Class Allowlist Inversion in oscript `has_only()` via Unescaped Leading `^` - (File: formula/evaluation.js)

### Summary
The `has_only(str, chars)` oscript builtin, used by AA authors to validate that a string is composed only of a permitted character set, constructs a JavaScript regular expression character class directly from the caller-supplied `chars` argument. It escapes `]` and rejects a trailing unescaped `\`, but does not defend against a leading `^`, which JS regex syntax interprets as negating the character class.

### Finding Description
`has_only` is implemented in the shared `evaluate()` opcode dispatcher: [1](#0-0) 
It takes the second argument `sub` and plugs it into `"^[" + sub + "]*$"`. If `sub` begins with `^` (e.g. `"^abc"`), the resulting pattern becomes `^[^abc]*$`, which matches strings that contain **only characters other than** `a`, `b`, `c` — the exact opposite of an allowlist of `a`, `b`, `c`. The only sanitization performed is escaping literal `]` and disallowing a dangling `\` at the end of `sub` (`formula/evaluation.js:2040-2042`), which exists purely to keep the constructed regex from throwing, not to preserve the semantics of the character class.

Static formula validation for `has_only` (`formula/validation.js:1053-1068`) and the AA definition validator (`aa_validation.js`) only check that both operands are valid sub-expressions/formulas; they impose no constraint on the value the "allowed characters" argument evaluates to. Consequently, if an AA's oscript logic derives the allowed-character set from trigger data (a very natural pattern for building generic validators, e.g. `has_only(trigger.data.name, params.allowed_chars)` or building a dynamic charset from multiple trigger fields concatenated together), any AA trigger sender can inject a leading `^` into that value and flip the allowlist check into a denylist check without the AA author's code detecting any error — the call still returns a normal boolean, just with the wrong polarity.

### Impact Explanation
Any AA design that uses `has_only()` as an input-sanitization/allowlist gate before performing a security-sensitive action (e.g., only accept identifiers/tickers/labels made of specific safe characters before using them to construct further state-var keys, output addresses, data feed names, or before authorizing a payment/asset action) can have that gate silently inverted by an attacker-controlled trigger. This can let a malicious trigger push otherwise-rejected values through the check, potentially causing the AA to spend, freeze, or misdirect funds it would not have processed under the intended validation logic — an unauthorized-spending / fund-loss path in AAs that were relying on `has_only` for whitelisting.

### Likelihood Explanation
Any single unprivileged unit poster can send an AA trigger with `data` values chosen to place `^` as the first character of a `has_only()` charset argument, if that argument is influenced (even indirectly, e.g. through concatenation) by trigger data. No special privileges, definitions, or witness cooperation are required, and the behavior is deterministic and consensus-consistent (every full node computes the same wrong-but-agreed-upon result), so it does not itself cause a fork — the risk is entirely in the exploitability of the flawed sanitization primitive by AA authors who reasonably assume `has_only` performs simple allowlisting.

### Recommendation
Reject (or escape) a leading `^` in the `sub` argument before building the character class (in addition to the existing `]` and trailing-`\` checks), or otherwise neutralize its special meaning at the start of the class (e.g., always insert a literal, non-negating prefix or explicitly disallow the character `^` as the first character), so that `has_only` cannot be turned into "has none of" via input the AA author did not intend as a negation operator.

### Proof of Concept
```
$allowed = trigger.data.allowed;  // attacker-controlled, e.g. "^xyz"
$ok = has_only(trigger.data.name, $allowed);
if ($ok) {
    // AA author intended: name is composed only of a whitelisted charset
    // Actual behavior when $allowed = "^xyz": name is accepted as long as
    // it does NOT contain x, y or z -- i.e. almost anything passes.
}
```
Sending a trigger with `data.allowed = "^xyz"` and any `data.name` not containing `x`, `y`, or `z` makes `has_only` return `true` even though `name` was never restricted to the intended charset, defeating the sanitization gate.

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
