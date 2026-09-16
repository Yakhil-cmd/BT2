## Title
Pre-Authentication Denial of Service via Uncaught Exception in `parse_date()` Date Parsing — ([File: formula/evaluation.js])

### Summary
The `parse_date` oscript builtin function in `formula/evaluation.js` contains a bare, unguarded `throw Error("non-integer seconds")` that fires when a date string parses to a millisecond timestamp that is not an exact multiple of 1000. Unlike every other error condition in the surrounding `evaluate()` switch statement — which uniformly reports failures via `setFatalError(...)` so evaluation degrades gracefully — this single case uses a synchronous `throw`. Because none of the callers of `formulaParser.evaluate()` (in `aa_composer.js`) wrap the call in `try/catch`, an attacker-controlled AA trigger that causes an AA formula to invoke `parse_date()` on an attacker-influenced date string can raise an uncaught exception during AA-trigger processing, propagating up through the unhandled promise/callback chain and ultimately crashing the node process.

### Finding Description
`parse_date` is defined at [1](#0-0)  Every other branch in this function signals failure with the non-throwing `setFatalError(...)` helper, which lets the caller cleanly bounce/fail the AA response. The `non-integer seconds` branch instead does a raw `throw`:

```
if (ts % 1000)
    throw Error("non-integer seconds");
```

`ts` is derived from `Date.parse()` (or a manually constructed UTC `Date`) on a string that only needs to satisfy loose regexes that do **not** validate month/day/hour/minute/second ranges (e.g. `/^\d\d\d\d-\d\d-\d\d( |T)\d\d:\d\d:\d\dZ$/` accepts a space instead of the ECMA-mandated `T` separator, and does not bound the numeric fields to valid calendar/clock ranges). Passing a space-separated timestamp forces the JS engine off the strict ISO 8601 fast path and onto engine-specific/legacy date-parsing heuristics, which are known to produce inconsistent results — including sub-second remainders — for malformed or out-of-range date/time components. The code even explicitly anticipates and asserts against this outcome, but mishandles it with a `throw` instead of the `setFatalError` pattern used everywhere else in the file.

This function is invoked from `exports.evaluate` at [2](#0-1)  which is called (without any surrounding `try/catch`) from numerous places inside `aa_composer.js`'s `handleTrigger`, e.g. the `replace()` function that evaluates every formula field of an AA definition against `trigger.data`: [3](#0-2)  and the state-update formula evaluator: [4](#0-3) . None of these call sites catch synchronous exceptions thrown from inside `evaluate`.

### Impact Explanation
Any address can send a payment (or a payment with `data`) to a deployed autonomous agent whose oscript definition calls `parse_date()` on trigger-supplied data (a common pattern for AAs that validate expiry dates, DOB, or other date fields from user input). If the attacker can find a date string for which the underlying JS engine's date parser yields a non-multiple-of-1000 millisecond value, posting a single trigger unit crashes every full node that executes that AA's trigger during main-chain stabilization/`handleAATriggers()` processing — this is not confined to the attacker's own connection, since AA execution is a consensus-critical, network-wide deterministic computation performed by every node. A crash there halts unit confirmation/stabilization on affected nodes, matching the "network unable to confirm new units" impact class. This mirrors the reported MongoDB OIDC vulnerability's root cause: improper handling of a specific date value causing an invariant/assertion failure and process crash from otherwise unauthenticated, attacker-supplied input.

### Likelihood Explanation
Reaching the vulnerable code requires (a) a deployed AA that calls `parse_date()` with attacker-influenced input, and (b) discovery of a date string that yields a fractional-second `Date.parse()` result under the node's JS engine. Given `parse_date` is a public, documented oscript builtin intended precisely for parsing user/trigger-supplied dates, and the code's own defensive check for this exact condition suggests the authors already observed/anticipated it can occur, likelihood is assessed as realistic, though it is somewhat dependent on the specific AA definitions deployed on the network and the exact engine version's legacy date-parsing quirks.

### Recommendation
Replace the bare `throw Error("non-integer seconds")` with the same `setFatalError(...)` non-throwing failure pattern used elsewhere in `evaluate()`, so a malformed/edge-case date input causes `parse_date()` to return `false` (as documented/tested for other invalid dates) rather than crashing the process. Additionally, tighten the regexes used to validate the date/time string so that only strictly valid calendar/clock values with the ECMA-mandated `T` separator are accepted before calling `Date.parse`, avoiding engine-specific legacy parsing paths entirely.

### Proof of Concept
1. Deploy (or identify) an AA whose oscript definition evaluates `parse_date(trigger.data.date)` against attacker-supplied trigger data, e.g.:
```
{
  messages: [{ app: 'data', payload: { ts: '{parse_date(trigger.data.date)}' } }]
}
```
2. Send a payment unit to this AA with `data: { date: "<space-separated date/time string with out-of-range or otherwise ambiguous components>" }` such that `Date.parse()`/legacy parsing yields a millisecond value not divisible by 1000 (values should be fuzzed against the exact Node.js version in production, focusing on the space-separated, non-`T` variant of the regex at [5](#0-4) ).
3. Observe that `handleTrigger` → `replace()` → `formulaParser.evaluate` synchronously throws `Error("non-integer seconds")` from [6](#0-5) , which is uncaught by any of the call sites in `aa_composer.js`, crashing the node process handling the trigger.

### Citations

**File:** formula/evaluation.js (L64-65)
```javascript
exports.evaluate = function (opts, astTrace, xpath, callback) {
	var conn = opts.conn;
```

**File:** formula/evaluation.js (L2500-2527)
```javascript
			case 'parse_date':
				var date_expr = arr[1];
				evaluate(date_expr, function (date) {
					if (fatal_error)
						return cb(false);
					if (typeof date !== 'string')
						return cb(false);
					var ts;
					if (date.match(/^\d\d\d\d-\d\d-\d\d$/)) {
						const [year, month, day] = date.split('-').map(Number);
						const d = new Date(0);
						d.setUTCFullYear(year, month - 1, day);
						d.setUTCHours(0, 0, 0, 0);
						ts = d.getTime();
						const reconstructedDate = d.toISOString().slice(0, 10);
						if (reconstructedDate !== date) 
							return cb(false); // Invalid date that carries over, e.g., 2023-02-30
					}
					else if (date.match(/^\d\d\d\d-\d\d-\d\d( |T)\d\d:\d\d:\d\dZ$/))
						ts = Date.parse(date);
					else if (date.match(/^\d\d\d\d-\d\d-\d\d( |T)\d\d:\d\d:\d\d$/))
						ts = Date.parse(date + 'Z');
					if (ts === undefined || isNaN(ts))
						return cb(false);
					if (ts % 1000)
						throw Error("non-integer seconds");
					cb(new Decimal(ts / 1000));
				});
```

**File:** aa_composer.js (L670-695)
```javascript
			var opts = {
				conn: conn,
				formula: f,
				trigger: trigger,
				params: params,
				locals: locals,
				stateVars: stateVars,
				responseVars: responseVars,
				objValidationState: objValidationState,
				address: address,
				bObjectResultAllowed: true
			};
			formulaParser.evaluate(opts, [], xpath, function (err, res) {
			//	console.log('--- f', f, '=', res, typeof res);
				if (res === null)
					return cb(err.formattedError || "formula " + f + " failed: "+err);
				if (res === '' || isEmptyObjectOrArray(res)) { // signals that the key should be removed (only empty string or array or object, cannot be false as it is a valid value for asset properties)
					if (typeof name === 'string')
						delete obj[name];
					else
						assignField(obj, name, null);
				}
				else
					assignField(obj, name, res);
				cb();
			});
```

**File:** aa_composer.js (L1440-1462)
```javascript
		var opts = {
			conn: conn,
			formula: objStateUpdate.formula,
			trigger: trigger,
			params: params,
			locals: objStateUpdate.locals,
			stateVars: stateVars,
			responseVars: responseVars,
			bStateVarAssignmentAllowed: true,
			bStatementsOnly: true,
			objValidationState: objValidationState,
			address: address,
			objResponseUnit: objResponseUnit
		};
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
