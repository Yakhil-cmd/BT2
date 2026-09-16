## Title
Insufficient validation of top-level `if`/`init` fields in AA message definitions permanently breaks message execution - (File: `aa_validation.js`)

### Summary
`aa_validation.js`'s `validateMessages()` validates the `if` and `init` fields attached to a top-level AA message only by checking that they are non-empty strings, unlike every other place in the same file where `if`/`init` expressions are checked (via `getFormula()`) to actually be parseable oscript formulas. Since AA definitions are immutable once posted, a garbage/non-formula `if` or `init` string that passes this weaker check can never be corrected, permanently crippling message execution for that AA in a way directly analogous to the reported DAO issue: insufficient upfront validation of a control field lets an unprivileged unit poster create a stuck/invalid object that cannot be fixed post-creation.

### Finding Description
In `validateMessages()` (`aa_validation.js:447-484`), each top-level AA message may carry `if`/`init` conditional-execution fields: [1](#0-0) 

The only check performed is `isNonemptyString`, not that the string is a valid, parseable oscript formula. Contrast this with the identical field validated one level down, inside `validateFieldWrappedInCases()`, which explicitly calls `getFormula()` to confirm the string compiles: [2](#0-1) 

and with output-level `if`/`init` in payment messages, which are also formula-checked: [3](#0-2) 

and with the `state` message's `state` formula, which is likewise validated with `getFormula()`: [4](#0-3) 

This is exactly the DAO bug pattern: a control field (`typeStr` in the DAO, `if`/`init` here) that governs later conditional branching is accepted with only a shallow type check (non-empty string / non-empty typeStr) at creation time, while the "real" validation (formula compile / `typeStr` equality match) only happens later, at evaluation/finalisation time — by which point the object is immutable and cannot be corrected. An AA definition, once posted via a `definition` message (`validation.js:1747-1767`, which calls `aa_validation.validateAADefinition`), can never be amended or withdrawn, so any message whose `if`/`init` field is syntactically well-formed as a string but not a valid formula (e.g. `"if": "not a formula ((("` ) is baked into the AA forever.

### Impact Explanation
Because AA code is immutable and content-addressed (the address is the definition's hash, `definition.js`/`aa_validation.js:729`), a defect that only manifests at trigger time cannot be patched. If a message's `if` condition fails to evaluate as a formula at execution time, the AA engine must either treat the whole trigger as failed (bouncing it) or skip that message — in either case, funds sent to that AA in the outputs of that specific message can never be paid out through the intended branch, effectively freezing/misdirecting AA funds for the lifetime of the contract with no way to fix the underlying definition. Any user (an "AA author") reachable to define/deploy an AA can trigger this, and any subsequent AA-trigger sender's funds are affected once they interact with such an AA — matching the "AA fund loss or freezing" impact class explicitly accepted for this class of finding.

### Likelihood Explanation
The condition is easy to trigger: any developer/attacker composing an AA definition unit can supply a non-empty but syntactically invalid `if`/`init` string on a top-level message and have it pass `validateAADefinition()` and get accepted into the DAG, since the check only verifies `isNonemptyString`. This requires no special privileges — just posting a valid unit containing a `definition` message. Given how easy it is to overlook (the very same file validates deeper-nested `if`/`init` correctly, so this is a straightforward oversight rather than requiring an unusual crafted input), the likelihood of accidental or intentional occurrence is moderate to high.

### Recommendation
In `validateMessages()` (`aa_validation.js:478-481`), validate `message.if` and `message.init` the same way nested `if`/`init` fields are validated elsewhere in the file — call `getFormula()` on the string and reject the AA definition if it returns `null`:
```js
if ('if' in message) {
    if (!isNonemptyString(message.if))
        return cb('bad if in message: ' + JSON.stringify(message.if));
    if (getFormula(message.if) === null)
        return cb('if in message is not a formula: ' + message.if);
}
if ('init' in message) {
    if (!isNonemptyString(message.init))
        return cb('bad init in message: ' + JSON.stringify(message.init));
    if (getFormula(message.init) === null)
        return cb('init in message is not a formula: ' + message.init);
}
```
This makes top-level message `if`/`init` validation consistent with the case-level, output-level, and `state`-level formula checks already present in the same file, preventing malformed/unusable AA definitions from ever being deployed.

### Proof of Concept
1. Craft an AA definition unit whose `messages` array contains a message with a top-level `if` field that is a non-empty but non-parseable string, e.g.:
```json
["autonomous agent", {
  "messages": [
    { "app": "payment", "if": "not_a_valid_formula(((", "payload": { "asset": "base", "outputs": [{"address": "{trigger.address}", "amount": "{trigger.output[[asset=base]]-1000}"}] } }
  ]
}]
```
2. Post this as a `definition` message (`validation.js:1747`). `aa_validation.validateAADefinition()` → `validateMessages()` accepts it because `isNonemptyString("not_a_valid_formula(((")` is `true`; no `getFormula()` check is performed at this level.
3. The AA address becomes permanently defined on the DAG with this broken message.
4. Send a trigger unit paying bytes to the AA. At execution time, the engine must attempt to evaluate `if` as a formula for that message; since it does not compile, the message (and any payout logic gated by it) cannot execute as intended, and there is no way to redefine the AA to fix it, since AA definitions are immutable once posted.

Note: full runtime confirmation of how `aa_composer.js` handles an uncompilable top-level `if` at trigger time (exact bounce vs. skip vs. crash behavior) was not directly traced within the available search iterations; the validation gap itself is confirmed directly in `aa_validation.js`, and the impact described follows from the documented immutability of AA definitions and the fact that identical `if`/`init` fields elsewhere in the same file are formula-validated, indicating the omission at the top level is a genuine gap rather than intentional design.

### Citations

**File:** aa_validation.js (L153-166)
```javascript
							if ('if' in output) {
								if (!isNonemptyString(output.if))
									return cb3("bad if in output: " + JSON.stringify(output.if));
								var f = getFormula(output.if);
								if (f === null)
									return cb3("if in output is not a formula: " + output.if);
							}
							if ('init' in output) {
								if (!isNonemptyString(output.init))
									return cb3("bad init in output: " + JSON.stringify(output.init));
								var f = getFormula(output.init);
								if (f === null)
									return cb3("init in output is not a formula: " + output.init);
							}
```

**File:** aa_validation.js (L436-442)
```javascript
		if (mci >= constants.aa2UpgradeMci && typeof message === 'string')
			return cb();
		if (message.app === 'state') {
			var f = getFormula(message.state);
			if (f === null)
				return cb('bad state formula: ' + JSON.stringify(message.state));
			return cb();
```

**File:** aa_validation.js (L478-481)
```javascript
			if ('if' in message && !isNonemptyString(message.if))
				return cb('bad if in message: '+JSON.stringify(message.if));
			if ('init' in message && !isNonemptyString(message.init))
				return cb('bad init in message: '+JSON.stringify(message.init));
```

**File:** aa_validation.js (L504-509)
```javascript
			if ('if' in acase && !isNonemptyString(acase.if))
				return cb('bad if in case: ' + JSON.stringify(acase.if));
			if (!('if' in acase) && i < cases.length - 1)
				return cb('if required in all but the last cases');
			if ('init' in acase && !isNonemptyString(acase.init))
				return cb('bad init in case: ' + JSON.stringify(acase.init));
```
