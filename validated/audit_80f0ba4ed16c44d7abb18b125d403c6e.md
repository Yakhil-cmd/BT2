## Finding: Incomplete Character-Class Escaping in `has_only()` Allows Regex Semantics to Be Subverted

### Title
Insufficient Escaping in Oscript `has_only()` Regex Character-Class Construction Allows AA Logic Bypass — (File: `formula/evaluation.js`)

### Summary
The `has_only` opcode in the oscript formula evaluator builds a JavaScript `RegExp` character class by directly splicing an attacker-influenceable string into `"^[" + sub + "]*$"`, escaping only the closing bracket `]`. This is analogous to the reported `escapeUnsafeCharacters` bug: an "escaping" routine that only accounts for a single unsafe character (`` ` `` in the original report, `]` here) while leaving other characters that are meaningful inside the destination context — a JS regex character class — completely unescaped.

### Finding Description [1](#0-0) 

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

`str` and `sub` are both fully general oscript expressions (`str_expr`, `sub_expr`), so both can be derived from `trigger.data`, `trigger.outputs`, or any other attacker-supplied unit content, since an AA trigger sender fully controls `trigger.data` in a unit they post: [2](#0-1) .

Character classes (`[...]`) in JavaScript `RegExp` treat several characters specially beyond `]`:
- A leading `^` negates the class (`[^...]` matches everything *not* listed).
- `-` defines a range (e.g., `a-z`).
- `\` starts an escape sequence (partially guarded here, but only for a trailing backslash and only for the literal two-char sequence `\]`).

The code only strips out closing brackets and rejects a subset of backslash patterns; it does nothing to prevent `sub` from beginning with `^` or containing `-` ranges or other backslash escape sequences (e.g., `\d`, `\w`, `\s`) that alter the matching semantics of the character class in ways an oscript AA author never intended. This mirrors the reported bug class exactly: an escaping function that handles one "breakout" character but not the full set required to safely embed untrusted data into the target syntax.

### Impact Explanation
`has_only()` is a documented oscript primitive that AA authors use to validate that a piece of trigger data (e.g., a memo, a nonce, a symbol, an identifier supplied by a caller) is restricted to an allowed character set before using it to gate a payment, mint an asset, or update state. If an attacker can pass a value such as `"^0-9"` (or any string starting with `^`) as the "allowed characters" argument — directly, or indirectly if the AA composes this value from other trigger fields — the semantics of the check silently invert or otherwise diverge from what the AA author intended (matching "any character not in this set" instead of "only characters in this set", or accepting an unintended range). An AA that relies on `has_only()` as an admission-control gate for spending funds, minting/burning, or authorizing sensitive state transitions could have its validation logic bypassed, resulting in unauthorized fund release or state corruption from AA balances — squarely within "AA fund loss" per the scope rules.

### Likelihood Explanation
Reachable by any address that can trigger an AA using `has_only()`, without any special privilege, simply by crafting `trigger.data` fields that flow (directly or via string concatenation) into the second argument of `has_only()`. Exploitability is fully dependent on whether a deployed AA uses attacker-influenced input as the "characters" operand of `has_only` (a legitimate and encouraged usage pattern for input sanitization in AAs), making it a design footgun baked into a core validation primitive rather than a hypothetical.

### Recommendation
Properly escape all regex metacharacters that are significant inside a character class before splicing `sub` into the `RegExp` source — at minimum `\`, `]`, `^` (particularly as the first character), and `-`. Prefer explicitly escaping every character of `sub` with `sub.replace(/[.*+?^${}()|[\]\\-]/g, '\\$&')` (or building the match via a `Set` of allowed characters instead of a regex) rather than constructing a raw `RegExp` string from user-influenced data. Add unit tests asserting that leading `^` or embedded `-` in the "characters" argument do not alter the intended "only-characters" semantics.

### Proof of Concept
Consider an AA (or a direct oscript formula evaluation) invoking:
```
has_only(trigger.data.value, trigger.data.allowed)
```
If the trigger data flowing into `has_only` supplies `allowed = "^0-9"` and `value` is any string that contains no digits (e.g., `"abc"`), the resulting regex is `^[^0-9]*$`، which — due to the unescaped leading `^` — now means "contains only non-digit characters", the exact opposite of the intended "only digits" check. Any AA logic gating a sensitive action on `has_only()` returning `true`/`false` as expected will therefore make an incorrect authorization decision for attacker-chosen `value`/`allowed` pairs, since neither operand is sanitized against regex-character-class metacharacters by `formula/evaluation.js` lines 2037-2049 [1](#0-0) .

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
