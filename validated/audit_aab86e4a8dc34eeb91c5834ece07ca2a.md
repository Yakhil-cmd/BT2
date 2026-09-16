### Title
Unguarded `throw` on null trigger-data field crashes the node's AA-trigger evaluator - ([File: formula/evaluation.js])

### Summary
The CVE describes a NULL-pointer dereference in an untrusted-input parser that crashes the process. The closest reachable analog in ocore is in the oscript/AA formula evaluator: `selectSubobject()` in `formula/evaluation.js` throws an unguarded `Error` when a selector resolves to a JavaScript `null` value, a state easily reachable by any address that can send a message/trigger to an AA with attacker-controlled JSON payload (`trigger.data`).

### Finding Description
`selectSubobject()` walks a chain of selector keys over the message/trigger data object [1](#0-0) . After the walk finishes without an "err" (e.g. the key exists but its value is `null`), the result is dispatched by type:

```
else if (typeof value === 'object' && value !== null) {
    let wob = new wrappedObject(value);
    ...
}
else
    throw Error("unknown type of subobject: " + value);
``` [2](#0-1) 

Because `typeof null === 'object'`, the `value !== null` guard excludes `null` from the object branch, and it falls into the final `else`, which unconditionally `throw`s a plain JS `Error` — not routed through the evaluator's `setFatalError`/`callback(err)` error-handling convention used everywhere else in this file. An attacker only needs to post a unit/trigger whose `data` payload contains a field explicitly set to `null` (perfectly valid JSON/oscript data) and have the AA's formula reference that field via a selector (`trigger.data.someField` or similar dotted/computed selector), e.g. `hasOwnProperty(value, evaluated_key)` returns true for a key whose value is `null`, so no "no such key" error is produced [3](#0-2) .

Formula evaluation for AA triggers happens on every full node while processing/responding to AA triggers (part of the normal, unprivileged trigger/AA response pipeline in `aa_composer.js`, which requires the formula evaluator `formula/evaluation.js`) [4](#0-3) . Unlike most other error paths in the evaluator, which properly call `setFatalError(...)` to report a soft/AA-level failure, this specific branch raises a hard JavaScript exception. If this exception is not caught synchronously by the calling stack, it propagates to Node's top-level `uncaughtException` handler in `network.js`, which deliberately re-throws to crash the whole process: `throw err; // crash the process to avoid ending up in an inconsistent state` [5](#0-4) .

### Impact Explanation
If the crash is not swallowed by an enclosing `try/catch` at the AA-trigger-processing call site, any single unprivileged unit poster can craft a trigger whose data contains a `null`-valued field referenced by the AA's own formula (or, more importantly, by a shared/well-known AA formula pattern), causing every full node that evaluates that trigger to hit the unguarded `throw` and crash via the global `uncaughtException` handler. Because AA trigger processing is mandatory, deterministic node behavior needed to advance the DAG/stabilize units, a reproducible crash here can stop affected nodes from continuing to validate/confirm new units — matching the "network unable to confirm new units" impact bar. This is a Medium/High-severity DoS class, directly analogous to the CVE's "crafted input → NULL dereference → application crash."

### Likelihood Explanation
Likelihood is moderate: it requires (a) an AA whose oscript formula dereferences a trigger-data field with a selector, and (b) the attacker being able to send a trigger where that field is explicitly `null` (trivial, since JSON payload fields are attacker controlled) and (c) that the crash-triggering exception is not intercepted by a wrapping `try/catch` somewhere up the call chain in `aa_composer.js`. I was not able to fully verify, within the available search budget, whether `aa_composer.js` wraps its calls to `formulaParser.evaluate` in a `try/catch` that would downgrade this to a soft AA failure rather than a full crash — this is the main open uncertainty. If such a wrapping exists, the practical impact is reduced to per-trigger evaluation failure rather than a full node crash.

### Recommendation
In `formula/evaluation.js`, `selectSubobject()` should treat a resolved `null` value the same way other invalid/empty results are handled — via `setFatalError(...)`/soft failure — instead of throwing a raw `Error`. More broadly, audit `formula/evaluation.js` for other bare `throw Error(...)` statements inside async callback chains (e.g., `throw Error("unknown type of subobject: " + value)`) and convert them to the `setFatalError`/`cb(err)` pattern used elsewhere in the file so a malformed trigger can never surface as an uncaught exception. Additionally, ensure the AA-trigger execution path in `aa_composer.js` wraps calls into the formula evaluator in `try/catch` so that any residual unexpected exception degrades gracefully (bounce/skip the trigger) rather than propagating to the process-level `uncaughtException` handler in `network.js` that intentionally crashes the process.

### Proof of Concept
1. Deploy (or use an existing) AA whose formula includes a data-selector, e.g.:
   ```
   { ... $x = trigger.data.foo; ... }
   ```
2. Send a trigger unit to this AA with payload `{"foo": null}` — perfectly valid JSON accepted by unit validation.
3. When any full node evaluates the formula for this trigger, `selectSubobject` resolves `value = null` for key `"foo"`, bypasses the `object && !== null` branch, and executes `throw Error("unknown type of subobject: null")`.
4. If uncaught up the call stack, this bubbles to the global handler in `network.js` and crashes the node process (`throw err;`), denying that node the ability to process further AA triggers/units until restarted.

*(Note: full confirmation that the crash is not swallowed by a `try/catch` in `aa_composer.js`'s trigger-handling code could not be completed within the available search scope; this should be verified directly against `aa_composer.js`'s formula-evaluation call sites before treating this as a confirmed unguarded crash path.)*

### Citations

**File:** formula/evaluation.js (L2908-2946)
```javascript
	function selectSubobject(value, arrKeys, arr, cb) {
		if (value instanceof wrappedObject) {
			var frozen = value.frozen;
			value = value.obj;
		}
		async.eachSeries(
			arrKeys || [],
			function (key, cb2) {
				if (typeof value !== 'object' || Decimal.isDecimal(value))
					return cb2('not an object while trying to access key ' + JSON.stringify(key));
				if (ValidationUtils.isArrayOfLength(key, 2) && key[0] === 'search_param_list') {
					var arrPairs = key[1];
					filterBySearchCriteria(value, arrPairs, function (err, filtered_array) {
						if (fatal_error)
							return cb2(fatal_error);
						if (err)
							return cb2(err);
						value = filtered_array;
						cb2();
					});
					return;
				}
				evaluate(key, function (evaluated_key) {
					if (fatal_error)
						return cb2(fatal_error);
					if (Decimal.isDecimal(evaluated_key)) {
						evaluated_key = evaluated_key.toNumber();
						if (!ValidationUtils.isNonnegativeInteger(evaluated_key))
							return setFatalError("bad selector key: " + evaluated_key, { arr }, undefined, cb2);
					}
					else if (typeof evaluated_key !== 'string')
						return setFatalError("result of " + JSON.stringify(key) + " is not a string or number: " + evaluated_key, { arr }, undefined, cb2);
					if (typeof evaluated_key === 'string')
						value = unwrapOneElementArrays(value);
					if (!hasOwnProperty(value, evaluated_key) || Decimal.isDecimal(value))
						return cb2("no such key in data");
					value = value[evaluated_key];
					cb2();
				});
```

**File:** formula/evaluation.js (L2966-2974)
```javascript
				}
				else if (typeof value === 'object' && value !== null) {
					let wob = new wrappedObject(value);
					wob.frozen = frozen; // inherits from the enclosing object
					cb(wob);
				}
				else
					throw Error("unknown type of subobject: " + value);
			}
```

**File:** aa_composer.js (L14-16)
```javascript
var validation = require("./validation.js");
var formulaParser = require('./formula/evaluation.js');
var kvstore = require('./kvstore.js');
```

**File:** network.js (L4530-4543)
```javascript
process.on('uncaughtException', (err) => {
	console.log('Uncaught exception:', err);
	console.error('Uncaught exception:', err);
	if (!conf.bLight) {
		let hosts = [...Object.keys(messagesInWork), ...Object.keys(requestsInWork)];
		if (currentJointHost)
			hosts.push(currentJointHost);
		console.log('Clients with pending requests/messages at the time of uncaught exception:', hosts);
		const fs = require('fs');
		const app_data_dir = require('./desktop_app.js').getAppDataDir();
		fs.writeFileSync(`${app_data_dir}/uncaught_exception_clients.txt`, hosts.concat(Object.keys(assocBlockedPeers)).join('\n'), 'utf8');
	}
	throw err; // crash the process to avoid ending up in an inconsistent state
});
```
