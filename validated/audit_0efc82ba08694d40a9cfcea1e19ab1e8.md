### Title
`has_only` character-class injection allows AA-formula string validation bypass via unescaped regex metacharacters - (File: formula/evaluation.js)

### Summary
The `has_only(str, chars)` oscript function builds a JavaScript `RegExp` character class directly from an evaluated, potentially attacker-controlled `chars` argument, escaping only the `]` character. It fails to neutralize `^` (negation) and `-` (range) inside the character class, allowing the semantic meaning of the "allowed characters" check to be inverted or altered, analogous to the Shescape bug class where incomplete escaping let a metacharacter (`~`) retain unintended special meaning inside an assignment context.

### Finding Description
In `formula/evaluation.js` the `has_only` operator is evaluated as: [1](#0-0) 

```js
if (op === 'has_only') {
    try {
        if (sub.match(/\\]/) || sub[sub.length - 1] === '\\')
            return setFatalError("invalid character group: " + sub, { arr }, false, cb);
        sub = sub.replace(/]/g, '\\]'); // don't allow to close the group early
        var bMatches = new RegExp("^[" + sub + "]*$").test(str);
    }
    ...
}
```

`sub` (the "allowed characters" argument, `sub_expr` at line 2016) is evaluated from an arbitrary oscript expression — it can come directly from `trigger.data`, i.e. from data an unprivileged unit poster supplies when triggering an AA [2](#0-1) . Only the `]` character is escaped before being embedded into a `RegExp` character class (`"^[" + sub + "]*$"`). No escaping is applied to `^` or `-`:

- If `sub` begins with `^` (e.g. an attacker supplies `"^abc"`), the resulting pattern becomes `^[^abc]*$`, which is a **negated** character class. The check silently flips from "string contains only these characters" to "string contains none of these characters."
- If `sub` contains a `-` between two characters (e.g. `"0-9"` intended literally, or an attacker-crafted string producing an unintended range like `"!-~"`), it is interpreted as a character **range**, greatly widening or narrowing the accepted character set in ways the AA author did not intend.

This is the same root-cause class as the Shescape advisory: an escaping routine that neutralizes one dangerous character (`]`/`~`) but omits other characters that retain special meaning in the target grammar (regex character-class syntax vs. shell/Dash tilde-expansion syntax), leading to unintended semantic expansion of user-controlled input (CWE-116/CWE-20).

### Impact Explanation
AA authors commonly use `has_only` to whitelist-validate data supplied by triggers (e.g., verifying that a string field only contains alphanumerics before using it to construct an address, asset id, memo, or business-logic branch). Because the "allowed characters" argument is itself evaluated from oscript expressions and can be derived from `trigger.data` (fully attacker-controlled, since anyone can post a unit that triggers an AA), an attacker who also controls or influences the second argument can invert the validation logic (via a leading `^`) or manipulate ranges (via `-`). This can let an attacker's trigger pass a validation check the AA relies on for correctness/security (e.g., bypassing an intended input-sanitization gate before funds are moved or state is updated), potentially resulting in AA fund loss, incorrect responses, or unintended state transitions — i.e., logic bypass in oscript evaluation reachable directly from an AA trigger sent by any unprivileged user.

### Likelihood Explanation
Exploitability depends on how a specific AA formula uses `has_only` — whether the "characters" argument is influenced by attacker-controlled trigger data or is a fixed literal chosen by the AA author. Where AAs pass a dynamic/attacker-influenced second argument (a realistic and not-uncommon pattern for flexible whitelist definitions), the bypass is trivial and deterministic (just prepend `^`). Where the character set is always a hardcoded literal, this issue is not reachable. Overall likelihood is contingent on AA design choices but requires no special privilege — any unit poster/trigger sender can supply the crafted string.

### Recommendation
Escape all regex-significant characters inside a character class before building the `RegExp`, not just `]`. At minimum, escape `^` when it appears anywhere in `sub` (or specifically when it is the first character), and escape or otherwise neutralize `-` (e.g., by escaping it as `\-` or moving it to a position where it cannot form a range), in addition to the existing `]` escaping. Alternatively, avoid dynamic regex character-class construction entirely and instead validate membership by iterating characters of `str` and checking `sub.includes(char)` (or similar `Set`-based check), which sidesteps regex metacharacter semantics altogether.

### Proof of Concept
```
formula: has_only(trigger.data.value, trigger.data.allowed)
trigger.data = { value: "malicious;payload", allowed: "^" }
```
Evaluation builds `new RegExp("^[^]*$").test("malicious;payload")`, which — due to the unescaped leading `^` — evaluates to `true` for essentially any input (matching "any character not in the empty negated set", i.e. matching everything), instead of the intended "string contains none of the listed characters" or a restrictive whitelist check, defeating the AA's intended input validation gate. [1](#0-0)

### Citations

**File:** formula/evaluation.js (L2015-2028)
```javascript
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
