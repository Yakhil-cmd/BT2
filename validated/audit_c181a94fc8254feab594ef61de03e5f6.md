### Title
Regex character-class injection in oscript `has_only()` allows validation bypass via negated character class (`^`) - ([File: formula/evaluation.js])

### Summary
The `has_only(str, chars)` oscript built-in is meant to let Autonomous Agent (AA) authors whitelist which characters are allowed in a string (e.g. to sanitize user-supplied trigger data before using it in addresses, asset names, storage keys, or other security-relevant logic). The implementation builds a JavaScript `RegExp` character class directly from the caller-supplied `chars` argument, escaping only the `]` character. It does not escape or reject a leading `^`, which in a `[...]` character class has special meaning (negation). An AA author who innocently writes `has_only(x, "^ABC")` (intending to allow the characters `^`, `A`, `B`, `C`) gets a character class `[^ABC]*` instead, which means "any character except A, B, C" — the exact opposite of the intended whitelist.

### Finding Description
`has_only` is evaluated in `formula/evaluation.js`: [1](#0-0) 

The code only strips/escapes `]` in the user-controlled character set (`sub`) before embedding it into a regex character class:
```
if (sub.match(/\\]/) || sub[sub.length - 1] === '\\')
    return setFatalError("invalid character group: " + sub, { arr }, false, cb);
sub = sub.replace(/]/g, '\\]'); // don't allow to close the group early
var bMatches = new RegExp("^[" + sub + "]*$").test(str);
```
This is analogous to the Asterisk CVE's root cause: a component makes a "liberal"/incomplete assumption about which characters are ordinary vs. special (there, whitespace vs. control characters; here, ordinary vs. regex-metacharacters within a character class), so a downstream parser (the JS regex engine) interprets the data differently than the code's author intended. Specifically:
- A leading `^` in `sub` is not escaped or rejected, so `[^...]` becomes a *negated* class.
- `-` between two characters is also not escaped, so `sub` such as `"a-z"` builds a range rather than the three literal characters `a`, `-`, `z` (a related, softer issue), compounding unpredictable interpretation of AA-author-supplied character sets.

Since `has_only` is a documented AA formula function (`formula/grammars/oscript.ne`) used for validating/whitelisting characters in state vars, addresses, or other trigger-derived strings, any AA that relies on it for input sanitization is exposed. An AA author who authors `has_only(trigger.data.something, "^0-9a-zA-Z")` (attempting to allow only digits, letters, and the caret) actually creates a filter that accepts almost any string not composed solely of the listed characters — completely inverting the intended validation.

### Impact Explanation
Any AA using `has_only()` as an input allow-list gate before performing security-relevant operations (deciding on payouts, building addresses/keys, gating branches of logic based on "safe" characters) can have that gate silently inverted by a caret placed first in the second argument. Since AA definitions are public oscript source and any unprivileged party can send a trigger unit to an AA, an attacker who notices such a definition can craft trigger data that the AA developer believed was excluded by the whitelist, but which is actually accepted due to the negation, causing the AA to proceed with unintended/unsafe data. Depending on the AA's logic this can result in unauthorized fund release, corrupted persistent state (state vars), or other value-affecting behavior — squarely within "AA fund loss" impact bucket described in scope.

### Likelihood Explanation
This is not attacker-controlled at the network layer; it is a foot-gun in the oscript function itself that any AA author could trigger unintentionally (e.g. wanting to allow the literal caret character as one of the allowed symbols, a very natural way to write it). Given `has_only` is documented and available since AA v2 upgrade (`mci < constants.aa2UpgradeMci` gate in `formula/validation.js`), the risk scales with adoption of the function for input sanitization. The likelihood of an AA developer using a leading `^` is not negligible, and once deployed, exploitation by any external unit poster is straightforward and requires no special privileges — they just need to observe the AA source (which is public) and craft trigger data accordingly.

### Recommendation
Harden `has_only`'s regex construction:
- Escape all regex metacharacters that have meaning inside a character class, not just `]`: at minimum `^` (when it would appear first) and `-` (unless intended as a range, this should be an explicit language feature, not implicit).
- Alternatively, avoid `RegExp` character-class construction entirely and implement `has_only` as a simple character-membership check by iterating `sub` into a `Set` of literal characters and testing each character of `str` against that set. This eliminates any regex-metacharacter interpretation issues entirely and matches the intuitive whitelist semantics AA authors expect.
- Add validation.js-level checks (in `formula/validation.js`) to reject or explicitly document a leading `^` in the second argument if changing runtime semantics would be a network upgrade concern.

### Proof of Concept
1. Deploy (or imagine) an AA with oscript logic such as:
   ```
   if (has_only(trigger.data.suffix, "^abc"))
       response['status'] = 'accepted';
   else
       bounce("bad suffix");
   ```
   The author intends to accept only strings composed of `^`, `a`, `b`, `c`.
2. Internally this evaluates:
   ```js
   new RegExp("^[^abc]*$").test(str)
   ```
   which actually matches any string that contains **none** of `a`, `b`, `c` — the opposite of the intended check.
3. An unprivileged trigger sender submits `trigger.data.suffix = "XYZ123!@#"` (containing none of a/b/c). The AA treats this as "accepted" even though the author intended to only accept strings drawn from `{^, a, b, c}`, allowing arbitrary attacker-controlled data to flow into whatever logic gated by `response['status'] = 'accepted'` (e.g., payout branch, state var write, or downstream address construction), leading to unintended AA behavior/fund handling.

Note: I was not able to find any additional escaping/validation of the `has_only` second argument elsewhere in the reachable validation path (`formula/validation.js` only checks that `mci` is new enough to allow `has_only` and increments complexity; it does not validate the content of the character-set argument), which is consistent with the runtime code shown above. [2](#0-1)

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

**File:** formula/validation.js (L1053-1056)
```javascript
			case 'has_only':
				if (mci < constants.aa2UpgradeMci)
					return cb(op + " not activated yet");
				complexity++;
```
