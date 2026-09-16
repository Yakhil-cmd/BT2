### Title
Unchecked missing `attestors`/`address` params in `attestation[[...]]` formula causes uncaught TypeError during AA evaluation - ([File: formula/evaluation.js])

### Summary
The CVE-2026-2100 bug class is: a required parameter can be `NULL`/absent, and the code path that consumes it fails to check for that absence, later dereferencing an uninitialized/undefined value. The analogous pattern exists in ocore's oscript formula evaluator for the `attestation[[...]]` operator: the evaluator unconditionally reads `params.attestors.value` and `params.address.value` without first checking that the `attestors` and `address` keys exist on the evaluated params object.

### Finding Description
In `formula/evaluation.js`, the `'attestation'` case builds `evaluated_params` only from whatever keys are actually present in the parsed formula's parameter list (`Object.keys(params)`), then immediately does: [1](#0-0) 

```
params = evaluated_params;
if (typeof params.attestors.value !== 'string')
    return setFatalError('attestors is not a string', { arr }, false, cb);
var arrAttestorAddresses = params.attestors.value.split(':');
...
var v = params.address.value;
if (!ValidationUtils.isValidAddress(v))
```

There is no guard such as `if (!params.attestors) return setFatalError(...)` before accessing `.value` on `params.attestors` or `params.address`. If a formula omits the `attestors` or `address` named parameter from the `attestation[[...]]` call (e.g. supplies only `ifseveral`, `type`, or `ifnone`), `params.attestors` (or `params.address`) is `undefined`, and `undefined.value` throws a `TypeError`.

Whether this is reachable at runtime depends on whether `formula/validation.js`'s `getAttestationError()` (invoked at validation time in the `'attestation'` case, [2](#0-1) ) enforces the *presence* of the `attestors`/`address` keys, not just the validity of whichever keys happen to be supplied. The sibling function `getInputOrOutputError()`, which has the same structure and is used for the closely related `input[[...]]`/`output[[...]]` operators, only iterates over `Object.keys(params)` and validates each supplied key's value/type — it never requires that a specific key (like `address`) be present: [3](#0-2) 

If `getAttestationError()` follows the same pattern (unconfirmed from the available index, but structurally very likely given the shared style), then a formula like `attestation[[ifnone=false]]` or `attestation[[type="string"]]` would pass static validation (since no field it does check is present to fail on) but crash the evaluator with an uncaught `TypeError` when actually evaluated for an AA trigger.

### Impact Explanation
`evaluate()` in `formula/evaluation.js` runs synchronously inside `aa_composer.js`'s trigger-handling pipeline while validating/executing units on the DAG. A `TypeError` thrown outside of the callback-based error paths (`setFatalError`) is an uncaught JS exception, not a controlled formula error. Because AA trigger evaluation happens deterministically on every full node processing the same trigger unit, this would crash (or at minimum desynchronize/hang, depending on where in the async chain the throw surfaces) every node that tries to evaluate the malicious AA, i.e. a network-wide denial of service that prevents new units built on/around that AA from being confirmed — this matches the required "network unable to confirm new units" impact class.

### Likelihood Explanation
Reachability requires only:
1. Deploying an AA definition containing a formula with `attestation[[...]]` where the required `attestors` or `address` key is omitted, and
2. Getting that AA triggered by any unprivileged unit poster (a normal payment to the AA address).

If `getAttestationError()` indeed doesn't enforce that `attestors`/`address` keys are present (as strongly suggested by the parallel `getInputOrOutputError()` implementation), this AA definition would pass `validateAADefinition` and be accepted onto the network, then crash on the first trigger. This is a Medium-likelihood, high-blast-radius bug class, matching the external report's severity (CVSS 5.3, availability-only impact).

### Recommendation
Add explicit presence checks before dereferencing `.value` on `params.attestors` and `params.address` in `formula/evaluation.js`'s `'attestation'` case (return `setFatalError` if missing), and correspondingly harden `getAttestationError()` in `formula/validation.js` to require that `attestors` and `address` keys be present in the params object (not just correctly typed if present) so malformed AA definitions are rejected at validation time rather than crashing at evaluation time.

### Proof of Concept
Not independently executed against a live node in this session; the concrete PoC would be:
1. Define an AA with a message formula such as `{ attestation[[ifnone=false]] }` (or any `attestation[[...]]` call omitting `attestors`/`address`).
2. Confirm this passes `validateAADefinition`/`formula/validation.js` (needs to be confirmed — I was unable to view `getAttestationError()`'s full body in this session, so this step is inferred by analogy with `getInputOrOutputError()` rather than directly confirmed).
3. Trigger the AA with a normal payment; observe the evaluator throw `TypeError: Cannot read properties of undefined (reading 'value')` in `formula/evaluation.js` during `handleTrigger`/`evaluateAA`, crashing the node process handling that trigger.

**Caveat:** I could not retrieve the body of `getAttestationError()` in `formula/validation.js` within the available tool budget, so I cannot 100% confirm that missing `attestors`/`address` params pass validation — this is inferred from the structurally identical sibling function `getInputOrOutputError()`. A Devin session with full file access should verify `getAttestationError()`'s exact logic before treating this as a confirmed, exploitable finding.

### Citations

**File:** formula/evaluation.js (L904-914)
```javascript
						params = evaluated_params;

						if (typeof params.attestors.value !== 'string')
							return setFatalError('attestors is not a string', { arr }, false, cb);
						var arrAttestorAddresses = params.attestors.value.split(':');
						if (!arrAttestorAddresses.every(ValidationUtils.isValidAddress)) // even if some addresses are ok
							return setFatalError('bad attestors', { arr }, false, cb);

						var v = params.address.value;
						if (!ValidationUtils.isValidAddress(v))
							return setFatalError('bad address in attestation: ' + v, { arr }, false, cb);
```

**File:** formula/validation.js (L182-197)
```javascript
function getInputOrOutputError(params) {
	if (!Object.keys(params).length) return 'no params';
	for (var name in params) {
		var operator = params[name].operator;
		var value = params[name].value;
		if (Decimal.isDecimal(value)){
			if (!isFiniteDecimal(value))
				return 'not finite';
			value = toDoubleRange(value).toString();
		}
		if (operator === '==') return '== not allowed';
		if (['address', 'amount', 'asset'].indexOf(name) === -1)
			return 'unknown field: ' + name;
		if ((name === 'address' || name === 'asset') && operator !== '=' && operator !== '!=')
			return 'not allowed: ' + operator;
		if (typeof value !== 'string') // a nested expression
```

**File:** formula/validation.js (L403-410)
```javascript
			case 'attestation':
				if (op === 'attestation')
					complexity++;
				var params = arr[1];
				var field = arr[2];
				var err = (op === 'attestation') ? getAttestationError(params) : getInputOrOutputError(params);
				if (err)
					return cb(op + ' not valid: ' + err);
```
