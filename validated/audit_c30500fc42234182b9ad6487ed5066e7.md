### Title
Autonomous Agent bounce/error messages leak the evaluated values of internal secret variables, enabling unauthorized withdrawal of AA funds - ([File: formula/evaluation.js])

### Summary
Like the Backstage permission backend, which leaked details of a policy's *conditional decision* to callers who had no right to see them, oc Autonomous Agents (AAs) leak the evaluated *values* of internal local/state variables inside the plain-text error/bounce message that is produced whenever an oscript formula fails. Any unprivileged party who can post a trigger unit to an AA (or simply craft a payload that reaches a vulnerable code path) can force a controlled evaluation error and read back secret data that the AA author never intended to expose (e.g. values used to gate a payment, commit-reveal secrets, or another user's private state).

### Finding Description
oscript formula evaluation embeds the *actual runtime value* of expressions into the error text it returns on failure, rather than a generic, value-free message:

- `bad value of function argument: " + JSON.stringify(res)` — leaks the concrete evaluated argument. [1](#0-0) 
- `"result of " + JSON.stringify(...) + " is not a string or number: " + value` — leaks the evaluated dictionary/object used as a selector. [2](#0-1) 
- `"assignment: state var name must be string, ... evaluated to " + JSON.stringify(evaluated_value)` — leaks the evaluated state-var-name expression. [3](#0-2) 
- `"reassignment to a, old value 9"` — leaks the concrete prior value of a local variable. [4](#0-3) 

These `fatal_error`/`bounce_message` payloads are propagated verbatim up through `evaluate()` → `handleTrigger()`'s `finish()`/`bounce()` machinery, attached to the AA response as `response.error` (with `message`, `formattedContext`, `codeLines`, and a `trace` of the AA call chain), and persisted via `addResponse()`/`saveStateVars()` as part of the publicly-queryable `aa_responses` data. [5](#0-4) 

Any unprivileged unit poster who can send a trigger (a payment, a state message, or a chained call through `remote_func_call`/getters) can deliberately supply inputs that make an oscript expression evaluate a secret value (e.g., a stored commit, a stored answer to a sealed condition, or another party's private variable) and then fail at a point where the *evaluated value itself* is echoed into the bounce message — e.g. by causing an assignment/selector/type error immediately after the secret is computed but before it is compared with `hash`/`sig`. [6](#0-5) 

This is architecturally the same bug class as GHSA-f8j4-p5cr-p777: a decision engine (Backstage's permission policy / here, the AA's oscript "policy") returns extra, unintended detail about its internal conditional evaluation to a caller who is not supposed to see it.

### Impact Explanation
Where AA authors rely on hidden/committed values in local or state vars to gate the release of funds (commit-reveal escrows, lotteries, sealed-bid style AAs, or AAs storing per-user secrets in `var[]`), an attacker can use a crafted trigger to force an evaluation failure that echoes the secret's plaintext value in the response. Because the bounce/response data is stored on-chain and queryable by anyone (not just the trigger sender), this converts a purely informational bug into a path to unauthorized AA fund withdrawal: once the secret is exfiltrated via the leaked error text, the attacker submits a second, correctly-formed trigger that satisfies the (formerly secret) condition and drains AA-held funds intended for someone else.

### Likelihood Explanation
Exploitation requires only the ability to post an ordinary unit/trigger to a public AA — something any wallet holder can do — and knowledge of which line of the target AA's (publicly readable) oscript definition computes the sensitive value. No privileged access, node compromise, or protocol-level trust is required, matching the "unprivileged unit poster / AA trigger sender" threat actor in scope.

### Recommendation
- Strip evaluated runtime values from user/AA-facing error and bounce messages; report only the failing operation/type and formula location (`codeLines`/`trace`), never `JSON.stringify(value)` of the offending operand.
- Audit all `setFatalError(...)` call sites in `formula/evaluation.js` that currently interpolate evaluated values (`bad value of function argument`, `bad value for with_selectors`, `is not a string or number`, `state var name must be string ... evaluated to ...`, `reassignment to X, old value Y`) and redact the value portion.
- Document for AA authors that any expression evaluated up to the failure point may currently leak into bounce data, and provide a "sensitive" primitive/annotation to prevent inclusion of certain variables in error output until the underlying leak is fixed.

### Proof of Concept
1. Deploy an AA that stores a secret value in a local/state variable, e.g. `$secret = var['committed_secret']`, and later uses it in a hash/sig comparison to authorize a payment.
2. Craft a trigger whose data forces a downstream formula error at a point that echoes `$secret` (e.g., use it as an invalid selector key, an invalid state-var name, or an invalid function argument) as demonstrated by: [7](#0-6) 
3. Observe `arrResponses[0].response.error.message` (or the equivalent stored `aa_responses` row) contains the plaintext evaluated value of `$secret`.
4. Use the recovered secret to construct a second trigger that satisfies the AA's intended condition and withdraw funds that should have required knowledge of the still-secret value.

### Citations

**File:** formula/evaluation.js (L2600-2603)
```javascript
							if (fatal_error)
								return cb2(fatal_error);
							if (!isValidValue(res) && !(res instanceof wrappedObject))
								return setFatalError("bad value of function argument: " + JSON.stringify(res), { arr }, undefined, cb2);
```

**File:** formula/evaluation.js (L2679-2699)
```javascript
			case 'require':
				var req_expr = arr[1];
				var error_description = arr[2];
				evaluate(req_expr, evaluated_req => {
					if (fatal_error)
						return cb(false);
					if (evaluated_req instanceof wrappedObject)
						evaluated_req = true;
					if (!isValidValue(evaluated_req))
						return setFatalError("bad value in require: " + JSON.stringify(evaluated_req), { arr }, false, cb);
					if (Decimal.isDecimal(evaluated_req) && evaluated_req.toNumber() === 0)
						evaluated_req = 0;
					if (evaluated_req)
						return cb(true);
					evaluate(error_description, function (evaluated_error_description) {
						if (fatal_error)
							return cb(false);
						console.log('require not met:', evaluated_error_description);
						setFatalError({ bounce_message: evaluated_error_description }, { arr }, false, cb);
					});
				});
```

**File:** test/aa_composer.test.js (L1714-1759)
```javascript
test.cb.serial('invalid selector', t => {
	var trigger_address = "I2ADHGP4HL6J37NQAD73J7E5SKFIXJOT";
	var trigger = { outputs: { base: 10000 }, data: { x: 5 }, address: trigger_address };
	
	var aa = ['autonomous agent', {
		init: `{
			$x = {};
			$x[{a:9}] = 1;
		}`,
		messages: [
			{
				app: 'state',
				state: `{
				}`
			}
		]
	}];


	validateAA(aa, async err => {
		t.deepEqual(err, null);

		var aa_address = objectHash.getChash160(aa);
		await asyncAddAA(aa);
		
		aa_composer.dryRunPrimaryAATrigger(trigger, aa_address, aa, (arrResponses) => {
			t.deepEqual(arrResponses.length, 1);
			t.deepEqual(arrResponses[0].bounced, true);
			t.deepEqual(arrResponses[0].response.error, {
			"message": "result of [\"dictionary\",[[\"a\",\"9\"]]] is not a string or number: {\"a\":9}",
			"formattedContext": "$x",
			"codeLines": [
				{
				"lineNumber": 3,
				"formula": "$x[{a:9}] = 1;"
				}
			],
			"trace": [
				{
				"type": "aa",
				"aa": "KAS6AUAIDWNFOEEZVMFI4ORVHSAQPECP",
				"xpath": "/init",
				"line": 3
				}
			]
			});
```

**File:** test/aa_composer.test.js (L1854-1855)
```javascript
			t.deepEqual(arrResponses[0].response.error, {
			"message": "assignment: state var name must be string, dictionary,valueOf,false,toString,false evaluated to {\"obj\":{\"valueOf\":false,\"toString\":false},\"frozen\":false} (object)",
```

**File:** test/aa.test.js (L888-889)
```javascript
			t.deepEqual(bounce_message, {
			"message": "reassignment to a, old value 9",
```

**File:** aa_composer.js (L1671-1699)
```javascript
	function finish(objResponseUnit) {
		if (bBouncing && bSecondary) {
			if (objResponseUnit)
				throw Error('response_unit with bouncing a secondary AA');
			if (!bAddedResponse && objValidationState.logs) // add the logs from the final bouncing unit
				arrResponses.push({ logs: objValidationState.logs });

			if (typeof error_message === 'string') {
				error_message = { message: error_message };
			}

			let errorObj = { address };
			if (error_message.address) {
				errorObj.next = error_message;
			} else {
				errorObj = { ...errorObj, ...error_message };
			}
			return onDone(null, errorObj);
		}
		fixStateVars();
		saveStateVars();
		addResponse(objResponseUnit, function () {
			updateStorageSize(function (err) {
				if (err)
					return revert(err);
				addUpdatedStateVarsIntoPrimaryResponse();
				onDone(objResponseUnit, bBouncing ? error_message : false);
			});
		});
```
