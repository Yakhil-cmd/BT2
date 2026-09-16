### Title
Regex/Character-Class Injection in `has_only()` Oscript Function Allows Attacker-Controlled Charset to Alter Match Semantics - (File: `formula/evaluation.js`)

### Summary
The `has_only(str, chars)` Oscript function builds a `RegExp` character class directly from an attacker-influenceable string (`chars`, e.g. AA trigger data) with only a single, incomplete sanitization step (escaping `]`), then evaluates it against `str`. This mirrors the reported `marsdb` bug class (CWE-77): user-controlled input is spliced unsanitized into a string that is compiled and executed by a JS interpreter primitive (`Function` in marsdb, `RegExp` here), letting the attacker change the semantics/behavior of a supposedly fixed matcher.

### Finding Description
In `formula/evaluation.js` the `has_only` case (part of the shared `starts_with|ends_with|contains|has_only|index_of` handler) evaluates both operands of the AA/oscript formula and then builds a regular expression directly from the second operand: [1](#0-0) 

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

`sub` (the second argument to `has_only()`) comes from an arbitrary expression (`sub_expr`) evaluated from the formula, which can reference `trigger.data`, `trigger.outputs`, `params`, or other externally supplied AA trigger fields — i.e. content fully controlled by whoever posts a unit that triggers the AA. [2](#0-1) 

The only sanitization performed is escaping the `]` character so the class cannot be closed early. It does **not**:
- Prevent the attacker from placing `^` as the first character of the class, which negates the whole character class (turning "only these chars allowed" into "only chars **not** in this set allowed").
- Escape `-` (range operator), letting an attacker define arbitrary character ranges (e.g. `a-z\x00-\xff`) far broader than an AA author intended.
- Escape backslash-based class shorthand tokens embedded via legitimate characters (e.g. injecting `\d`, `\w`, `\s` since those are just two normal characters `\` and `d` that pass through if not the final char — the code only blocks a *trailing* single backslash).

Because oscript is a Turing-incomplete DSL specifically designed so that no user input can affect control flow outside sandboxed data operations, allowing a value from trigger data to control the *meaning* of a regex-based sanitization check embedded in an AA is a genuine injection into an interpreter/matcher construct, directly analogous to marsdb passing an unsanitized `$where` selector into `new Function(...)`.

### Impact Explanation
Many AAs are expected to use `has_only()` as an allow-list validator, e.g. to ensure a user-supplied identifier, address fragment, or numeric string used later in fund-moving logic (`payment[[...]]`, `bounce`, storing to `var[...]` used in payout calculations) contains only permitted characters. If the *charset* argument itself is influenced by attacker-controlled data (a plausible AA pattern — e.g., dynamic allow-lists built from `params` or state combined with trigger data, or careless AA code that echoes trigger fields into the charset by mistake), an attacker who posts a crafted trigger unit can:
- Negate the character class with a leading `^`, causing `has_only()` to return `true` for strings that should have been rejected (or vice versa), silently inverting the intended input-validation gate.
- Broaden the allowed set via unescaped `-` ranges to defeat character-restriction logic.

Since `has_only()` results can gate branching that leads to payments, state-var updates, or bounce logic inside AAs, a broken/invertible validator can let an attacker smuggle unexpected characters/values through validation, potentially enabling unauthorized state transitions or fund movement in a vulnerable AA — a concrete impact category (AA fund loss/incorrect logic) within scope of the rules.

### Likelihood Explanation
Exploitability depends on whether a given AA passes attacker-influenced data as the *second* argument to `has_only()` (the charset), which is a less common but plausible AA design pattern (e.g. dynamic allow-lists parameterized by trigger fields, or AA authors mistakenly swapping arguments). The vulnerability is 100% deterministic and reachable by any unprivileged unit poster/AA trigger sender for any AA where this pattern exists — no privileged access, hub, or peer position needed. The bug is in shared core AA-formula evaluation code (`formula/evaluation.js`), so it affects every deployed AA that uses `has_only()` in this way, making it Medium-severity: real but conditional on AA-author code patterns rather than universally exploitable in every AA.

### Recommendation
- Properly escape **all** regex metacharacters in `sub` before embedding it in a character class, not just `]`. At minimum also escape `^` (when in first position) and `-`, and reject/escape trailing or leading control sequences robustly (e.g. via a dedicated regex-escaping utility, not ad-hoc `.replace()`).
- Alternatively, avoid `RegExp` entirely for `has_only`: implement it by iterating `str` characters and checking membership against the literal character set of `sub` (e.g. `Array.from(sub)`), which removes any interpreter-injection surface.
- Add unit tests specifically covering `has_only(str, '^...')` and `has_only(str, 'a-z...')` to confirm the intended literal, non-negatable, non-range semantics.

### Proof of Concept
Within an AA that (mis)uses trigger data as the charset argument, e.g.:
```
{
  bounce_fees: {base: 10000},
  messages: {
    cases: [
      {
        if: `has_only(trigger.data.id, trigger.data.allowed_chars)`,
        messages: [ /* ... privileged payment logic assumed safe due to the check above ... */ ]
      }
    ]
  }
}
```
An attacker posts a trigger unit with:
```
trigger.data = {
  id: "malicious;DROP-like-payload",
  allowed_chars: "^"   // negates the class: "^[^]*$" matches ANY string
}
```
Evaluating `has_only(trigger.data.id, trigger.data.allowed_chars)` builds `new RegExp("^[^]*$")`, which matches virtually any input (since `[^]` in JS regex matches any character including newlines), bypassing the intended allow-list restriction and letting the "if" branch execute for input that the AA author never intended to pass validation.

### Citations

**File:** formula/evaluation.js (L2013-2028)
```javascript
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
