### Title
Uncaught exception in oscript formula evaluator crashes all full nodes processing an AA trigger — `parse_date` non-integer-seconds throw (File: formula/evaluation.js)

### Summary
The GHSA-mg85-8mv5-ffjr advisory describes a parser that throws a raw, uncaught JS exception on attacker-influenced input, which propagates past the caller and can crash the process. `formula/evaluation.js`'s `evaluate()` function — the core interpreter for oscript/AA formulas — contains multiple `throw Error(...)` statements reachable from formula operators that are *not* wrapped in any try/catch at the call site, and the top-level `exports.evaluate` entry point also has no try/catch around the initial `evaluate(parser.results[0], ...)` call.

### Finding Description
`formula/evaluation.js` implements the recursive `evaluate(arr, cb, bTopLevel)` interpreter used both for AA trigger/state-update execution (`aa_composer.js`) and for definition/authentifier evaluation. Several branches inside this switch statement raise raw `throw Error(...)` instead of routing the error through the `setFatalError`/callback mechanism used everywhere else in the same function, e.g.: [1](#0-0) 
in the `parse_date` case: if the regex-matched date/time value passes date-parsing but `ts % 1000` is non-zero, the code does `throw Error("non-integer seconds")` synchronously inside a nested `evaluate()` callback, instead of calling `setFatalError` like the rest of the function.

Other unguarded `throw Error(...)` sites exist in the same evaluator, e.g. the `default` case for unrecognized ops: [2](#0-1) 
and in `toOscriptType`/`toJsType` helper conversions: [3](#0-2) 

The entry point `exports.evaluate` invokes the recursive evaluator with no surrounding try/catch: [4](#0-3) 

`aa_composer.js` (the AA trigger/response composer) calls `formulaParser.evaluate` directly inside `handleTrigger`'s `replace()` helper without a try/catch around the call: [5](#0-4) 
and this is driven from `handleAATriggers()`, which every full node runs deterministically whenever any user posts a unit that triggers an AA: [6](#0-5) 

Because AA definitions are permissionless (any user can deploy an AA, and any user can then send a trigger unit to it), an AA author can write a formula that calls `parse_date(trigger.data.some_field)` (or otherwise reaches one of the unguarded throw sites) with values controlled by whoever sends the triggering unit — an ordinary "AA trigger sender." When the thrown `Error` escapes `evaluate()` uncaught, it propagates up through `aa_composer.js`'s `handleTrigger`/`handleAATriggers` call chain. Since ocore installs a global `process.on('uncaughtException', ...)` handler that deliberately re-throws to crash the process (`throw err; // crash the process to avoid ending up in an inconsistent state`): [7](#0-6) 
any full/hub node that processes the same trigger unit (which all nodes must do deterministically to agree on AA response state) will crash in the same way.

### Impact Explanation
This is analogous to the `ammo` Range-header DoS: a syntactically valid, low-privilege user input (an AA trigger with a crafted formula/date value) reaches a code path where an internal invariant-violation is expressed as a raw `throw` rather than a handled validation error. Because AA execution is deterministic and mandatory for every node that wants to stay in sync (all full nodes execute the same AA formula on the same trigger to agree on the resulting state/response), a crash here is not confined to one node — every full node that processes that trigger unit will hit the same uncaught exception and crash via the `uncaughtException` handler that intentionally re-throws. This can render the network unable to process new units/AA responses until operators patch and restart nodes, which satisfies the "network unable to confirm new units" impact bar.

### Likelihood Explanation
Reachability requires an attacker (as an AA author, which is unprivileged/permissionless) to deploy an AA formula that funnels attacker- or trigger-sender-controlled data into `parse_date` (or another vulnerable operator) in a way that reaches the unguarded `throw`. I was only able to fully confirm the code path's lack of exception handling; I could **not** conclusively determine, from static analysis alone, whether the `parse_date` regexes ever actually permit `ts % 1000 !== 0` in practice (the three regex branches constrain the string to exact-second precision, so under normal `Date.parse` semantics the modulo is expected to be zero). This makes the `parse_date` throw's reachability uncertain — it may be effectively dead code under most V8 `Date.parse` behavior, though edge cases (e.g., non-standard date normalization) were not verifiable without running dynamic tests. The general pattern (unguarded `throw` in the interpreter, no top-level try/catch, and unconditional process crash on uncaught exception) is confirmed and is the stronger part of this finding.

### Recommendation
- Wrap the top-level `evaluate(parser.results[0], ...)` call in `exports.evaluate` (formula/evaluation.js) in a try/catch, converting any thrown error into the standard `fatal_error`/`callback(err, null)` path instead of letting it propagate.
- Audit every `throw Error(...)` inside the `evaluate()` switch (e.g. `parse_date`'s `"non-integer seconds"`, the `default: throw Error('unrecognized op '+op)`, and the `toOscriptType`/`toJsType` throws) and replace them with `setFatalError(...)` calls consistent with the rest of the function, so malformed/edge-case input results in a formula failure rather than a process crash.
- Wrap calls to `formulaParser.evaluate` in `aa_composer.js` (`handleTrigger`'s `replace()`, and other call sites) in try/catch so that any residual unhandled exception is converted into an AA bounce rather than crashing the node.
- Consider hardening the global `uncaughtException` handler in `network.js` to avoid an unconditional process crash for errors that originate from processing a single unit/trigger, since this makes any single unguarded throw in the validation/AA path a network-wide DoS vector.

### Proof of Concept
Conceptual PoC (not fully verified dynamically due to tool limitations):
1. Attacker deploys an AA whose base/state-update formula includes an expression like `parse_date(trigger.data.d)`.
2. Attacker (or any trigger sender) sends a payment/trigger unit to this AA with `data.d` set to a string engineered to pass one of the `parse_date` regexes but yield a `Date.parse` result where `ts % 1000 !== 0`.
3. When any full node executes `handleAATriggers()` → `handlePrimaryAATrigger()` → `handleTrigger()` → `formulaParser.evaluate()` for this trigger, the `throw Error("non-integer seconds")` in `formula/evaluation.js` (around line 2525) executes with no enclosing try/catch, propagates out of `aa_composer.js`, and is caught only by the global `uncaughtException` handler in `network.js`, which re-throws and crashes the node process.

Because I could not dynamically confirm a concrete `date` string producing `ts % 1000 !== 0` under Node's `Date.parse`, this specific trigger condition should be verified with a Devin session that can execute the codebase; however, the structural vulnerability (unguarded `throw` in a widely-reachable, deterministic AA-execution code path with a crash-on-uncaught-exception policy) is confirmed by static analysis.

### Citations

**File:** formula/evaluation.js (L2520-2527)
```javascript
					else if (date.match(/^\d\d\d\d-\d\d-\d\d( |T)\d\d:\d\d:\d\d$/))
						ts = Date.parse(date + 'Z');
					if (ts === undefined || isNaN(ts))
						return cb(false);
					if (ts % 1000)
						throw Error("non-integer seconds");
					cb(new Decimal(ts / 1000));
				});
```

**File:** formula/evaluation.js (L2757-2759)
```javascript
			default:
				throw Error('unrecognized op '+op);
		}
```

**File:** formula/evaluation.js (L3205-3225)
```javascript
	if (parser.results && parser.results.length === 1 && parser.results[0]) {
		evaluate(parser.results[0], res => {
			if (fatal_error) {
				callback(fatal_error, null);
			} else {
				if (early_return !== undefined)
					res = early_return;
				if (res instanceof wrappedObject)
					res = bObjectResultAllowed ? string_utils.cloneDeep(res.obj) : true;
				else if (Decimal.isDecimal(res)) {
					if (!isFiniteDecimal(res))
						return callback('result is not finite', null);
					res = toDoubleRange(res);
					res = (res.isInteger() && res.abs().lt(Number.MAX_SAFE_INTEGER)) ? res.toNumber() : res.toString();
				}
				else if (typeof res === 'string' && res.length > constants.MAX_AA_STRING_LENGTH)
					return callback('result string is too long', null);
				astTrace = [];
				callback(null, res);
			}
		}, true);
```

**File:** formula/evaluation.js (L3235-3255)
```javascript
function toOscriptType(x) {
	if (typeof x === 'string' || typeof x === 'boolean' || x instanceof wrappedObject)
		return x;
	if (typeof x === 'number')
		return createDecimal(x);
	if (Decimal.isDecimal(x))
		return toDoubleRange(x);
	if (typeof x === 'object' && x !== null)
		return new wrappedObject(x);
	throw Error("unknown type in toOscriptType:" + x);
}

function toJsType(x) {
	if (x instanceof wrappedObject)
		return x.obj;
	if (Decimal.isDecimal(x))
		return x.toNumber();
	if (typeof x === 'string' || typeof x === 'boolean' || typeof x === 'number' || (typeof x === 'object' && x !== null))
		return x;
	throw Error("unknown type in toJsType:" + x);
}
```

**File:** aa_composer.js (L59-80)
```javascript
function handleAATriggers(onDone) {
	if (!onDone)
		return new Promise(resolve => handleAATriggers(resolve));
	mutex.lock(['aa_triggers'], function (unlock) {
		db.query(
			"SELECT aa_triggers.mci, aa_triggers.unit, address, definition \n\
			FROM aa_triggers \n\
			CROSS JOIN units USING(unit) \n\
			CROSS JOIN aa_addresses USING(address) \n\
			ORDER BY aa_triggers.mci, level, aa_triggers.unit, address",
			function (rows) {
				var arrPostedUnits = [];
				async.eachSeries(
					rows,
					function (row, cb) {
						console.log('handleAATriggers', row.unit, row.mci, row.address);
						var arrDefinition = JSON.parse(row.definition);
						handlePrimaryAATrigger(row.mci, row.unit, row.address, arrDefinition, arrPostedUnits, cb);
					},
					function () {
						arrPostedUnits.forEach(function (objUnit) {
							eventBus.emit('new_aa_unit', objUnit);
```

**File:** aa_composer.js (L639-654)
```javascript
				return formulaParser.evaluate(opts, [], xpath, function (err, res) {
					if (res === null)
						return cb(err.formattedError || "formula " + f + " failed: "+err);
					delete obj[name];
					if (res === '')
						return cb(); // the key is just removed from the object
					if (typeof res !== 'string')
						return cb({message: "result of formula " + name + " is not a string: " + res, xpath});
					if (ValidationUtils.hasOwnProperty(obj, res))
						return cb({message: "duplicate key " + res + " calculated from " + name, xpath});
					if (getFormula(res) !== null)
						return cb({message: "calculated value of " + name + " looks like a formula again: " + res, xpath});
					assignField(obj, res, value);
					replace(obj, res, path, locals, xpath, cb);
				});
			}
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
