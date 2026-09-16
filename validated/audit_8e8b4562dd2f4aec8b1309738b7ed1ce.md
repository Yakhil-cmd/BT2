## Title
Reachable `throw Error()` inside AA formula evaluation crashes the whole node (uncaught exception → process termination) - ([File: formula/evaluation.js])

### Summary
The external report describes a memory-safety bug in server-side JS aggregation expressions that lets an authenticated, low-privileged user crash the `mongod` process. The structural analog in `ocore` is that the AA (Autonomous Agent) `oscript` formula evaluator, `exports.evaluate` in [1](#0-0) , contains multiple `throw Error(...)` statements reachable purely from attacker-controlled trigger/state data, and these calls occur deep inside an async/callback chain driven from `aa_composer.js` with **no surrounding `try/catch`**. Because the whole unit/AA-trigger processing pipeline is callback-based, a thrown exception here escapes as a Node.js `uncaughtException`, which is explicitly re-thrown by the global handler in `network.js` to intentionally crash the process.

### Finding Description
`handlePrimaryAATrigger` → `handleTrigger` → `evaluateAA`/`replace`/`executeStateUpdateFormula` all invoke `formulaParser.evaluate(opts, ...)` with plain callbacks and no `try { } catch { }` wrapper, e.g.: [2](#0-1) [3](#0-2) 

Inside `formula/evaluation.js`, the recursive `evaluate()` closure processes the AST and for several opcodes falls back to a raw `throw Error(...)` instead of routing through `setFatalError(...)`, which is the mechanism designed to safely convert failures into a callback-reported error: [4](#0-3) 

Specifically, in the `ifelse` case, once `res` is not a `wrappedObject` (already normalized to `true`) and is not a valid `Decimal`, string, or boolean, hitting `typeof res === 'object'` throws synchronously:
```
else if (typeof res === 'object')
    throw Error("test evaluated to object " + res);
```
This is not caught anywhere in the call chain, since `evaluate()` is invoked recursively via plain callback closures (`evaluate(test, function (res) {...})`), not from a synchronous stack that any caller wraps in `try/catch`. The `isValidValue(res)` check before it does not exclude every non-Decimal object value (e.g. `null`), so a formula path that can produce `null` (or another bare object) as the value of an `if`/`ifelse` test condition reaches the `throw`. Similar unguarded `throw Error(...)` statements exist throughout `formula/evaluation.js` (49 occurrences total), including in `callGetter` (`"args is not an array"`, [5](#0-4) ) and `callFunction` (`"function called after a return"`, [6](#0-5) ), all reachable from AA definitions/triggers that a single unprivileged unit poster or AA trigger sender fully controls.

Once thrown, the exception propagates out of the async chain up to Node's `uncaughtException` handler: [7](#0-6) 
which logs it and then deliberately re-`throw`s to terminate the process ("crash the process to avoid ending up in an inconsistent state"). This mirrors the report's "cause the ... process to be terminated through certain ... expressions" root cause, except here the trigger is an oscript/AA formula expression evaluated server-side instead of a JS aggregation expression.

### Impact Explanation
Any full node (including hub/witness nodes) that processes AA triggers evaluates untrusted, attacker-supplied `oscript` formulas from AA definitions and unit trigger data. A single unprivileged unit poster or AA trigger sender who crafts a payload that drives the evaluator into one of these unguarded `throw Error(...)` branches can force the target node process to crash via the `uncaughtException` handler. Because AA trigger processing runs on every full node that tracks AA units, this is a network-wide, repeatable denial-of-service against nodes (not just a single victim), and it directly prevents the network from continuing to confirm/process units that depend on AA execution while affected nodes restart — matching the "network unable to confirm new units" impact bar. This is High severity, analogous to the reported issue.

### Likelihood Explanation
Likelihood is High: crafting an oscript formula is entirely within the capability of anyone who can define an AA and send a triggering unit (no special privileges, keys, or network position needed), the `evaluate()` function processes every trigger/getter/state-update formula for every registered AA, and the guard checks (`isValidValue`, `Decimal.isDecimal`) do not appear to comprehensively exclude all "object-typed but not wrappedObject/Decimal" results (e.g., `null`) from reaching the `throw` in the `ifelse` branch. The precise formula construct needed to make `evaluate(test, ...)` yield a bare non-Decimal, non-wrappedObject object value (rather than being caught earlier by `setFatalError`) would need confirmation via testing/tracing every path that can produce such a `res`, which could not be fully enumerated with static reading alone.

### Recommendation
- Replace every unguarded `throw Error(...)` inside `formula/evaluation.js`'s `evaluate`/`callFunction`/`callGetter` that can be triggered by attacker-controlled formula/data (as opposed to genuine internal-invariant violations) with `setFatalError(...)` so the error is reported via the callback instead of thrown synchronously.
- Wrap the top-level `formulaParser.evaluate(...)` invocation sites in `aa_composer.js` (`evaluateAA`, `replace`, `executeStateUpdateFormula`, and all other call sites) in a `try/catch` (or use `domain`/`process.nextTick` isolation) so that any unexpected synchronous throw during AA processing bounces the trigger instead of crashing the whole node.
- Add/expand fuzz or property-based tests that exercise `ifelse`, `func_call`, `remote_func_call`, and getter-call paths with edge-case values (`null`, exotic objects) to ensure none of them reach a raw `throw` instead of `setFatalError`.

### Proof of Concept
Not independently verified end-to-end (would require confirming a concrete oscript formula string that makes an `evaluate(test, cb)` callback for an `ifelse` node's condition receive a bare object `res` — e.g., a value derived from an edge-case getter or `local_var` path not converted to `Decimal`/`wrappedObject`/string/boolean before the `typeof res === 'object'` check). Conceptually:
1. Define an AA whose `messages` block contains an `if`/`ifelse` condition formula crafted so its evaluated result is a JS object other than a `wrappedObject` or `Decimal` (candidate: exploiting a code path returning `null`, since `isValidValue(null)` and `Decimal.isDecimal(null)` are both false but `typeof null === 'object'`).
2. Post a unit that triggers this AA.
3. When `handleTrigger` evaluates the AA's messages via `formulaParser.evaluate`, the `ifelse` branch hits `throw Error("test evaluated to object " + res)`.
4. The throw is uncaught inside the async callback chain and surfaces in `network.js`'s global `uncaughtException` handler, which re-throws and terminates the node process. [8](#0-7) [7](#0-6)

### Citations

**File:** formula/evaluation.js (L64-65)
```javascript
exports.evaluate = function (opts, astTrace, xpath, callback) {
	var conn = opts.conn;
```

**File:** formula/evaluation.js (L1458-1478)
```javascript
			case 'ifelse':
				var test = arr[1];
				var if_block = arr[2];
				var else_block = arr[3];
				evaluate(test, function (res) {
					if (fatal_error)
						return cb(false);
					if (res instanceof wrappedObject)
						res = true;
					if (!isValidValue(res))
						return setFatalError("bad value in ifelse: " + res, { arr }, false, cb);
					if (Decimal.isDecimal(res))
						res = (res.toNumber() !== 0);
					else if (typeof res === 'object')
						throw Error("test evaluated to object " + res);
					if (!res && !else_block)
						return cb(true);
					var block = res ? if_block : else_block;
					evaluate(block, cb);
				});
				break;
```

**File:** formula/evaluation.js (L3063-3064)
```javascript
		if (early_return !== undefined)
			throw Error("function called after a return");
```

**File:** formula/evaluation.js (L3340-3341)
```javascript
			if (!Array.isArray(args))
				throw Error("args is not an array");
```

**File:** aa_composer.js (L610-614)
```javascript
		formulaParser.evaluate(opts, [], '/getters', function (err, res) {
			if (res === null)
				return cb(err.formattedError || "formula " + f + " failed: " + err);
			replace(arrDefinition, 1, '', locals, '', cb);
		});
```

**File:** aa_composer.js (L1454-1462)
```javascript
		formulaParser.evaluate(opts, [], objStateUpdate.xpath, function (err, res) {
		//	console.log('--- state update formula', objStateUpdate.formula, '=', res);
			if (res === null)
				return cb(err.formattedError || "formula " + objStateUpdate.formula + " failed: "+err);
			const rv_len = getResponseVarsLength();
			if (rv_len > constants.MAX_RESPONSE_VARS_LENGTH)
				return cb(`response vars too long: ${rv_len}`);
			cb();
		});
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
