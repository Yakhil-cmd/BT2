### Title
Uncaught exception in `parse_date` formula function crashes AA-processing node - ([File: formula/evaluation.js])

### Summary
The `parse_date` oscript function used in Autonomous Agent (AA) formulas checks `Date.parse()` output for `NaN` but then unconditionally `throw`s a plain JS `Error` if the parsed timestamp is not an exact multiple of 1000 ms, without ever catching that exception anywhere in the AA execution pipeline. This mirrors the root cause class of CVE-2015-8720 (Wireshark's `dissect_ber_GeneralizedTime`): a date/time parsing helper's return value is checked in some but not all cases, and the unchecked/mis-handled branch throws/crashes instead of failing gracefully.

### Finding Description
`parse_date` is implemented in `formula/evaluation.js`: [1](#0-0) 

```
case 'parse_date':
    ...
    else if (date.match(/^\d\d\d\d-\d\d-\d\d( |T)\d\d:\d\d:\d\dZ$/))
        ts = Date.parse(date);
    else if (date.match(/^\d\d\d\d-\d\d-\d\d( |T)\d\d:\d\d:\d\d$/))
        ts = Date.parse(date + 'Z');
    if (ts === undefined || isNaN(ts))
        return cb(false);
    if (ts % 1000)
        throw Error("non-integer seconds");
    cb(new Decimal(ts / 1000));
```

The code carefully guards against `NaN` (an unparseable date), but the very next check does not return an error result through the normal `cb(false)` / `setFatalError` path used everywhere else in this evaluator; instead it `throw`s a raw JS exception synchronously inside the `evaluate()` callback.

Critically, the regexes accept a **space** as an alternate date/time separator (`( |T)`), which is *not* the ISO-8601 extended format that `Date.parse` is required by ECMA-262 to support deterministically. For any format other than the exact ISO extended format, `Date.parse` behavior is explicitly implementation-defined by the spec, meaning different JavaScript engine/Node.js versions are not guaranteed to parse `"2021-01-01 00:00:00Z"` identically or to always return a value that is an exact multiple of 1000.

This function is invoked from `formula/evaluation.js`'s `evaluate()` engine which is called by `aa_composer.js`'s `handleTrigger()`/`evaluateAA()`/`replace()`/`executeStateUpdateFormula()` whenever an AA definition or state-update formula containing `parse_date(...)` runs: [2](#0-1) [3](#0-2) 

None of these call sites wrap `formulaParser.evaluate(...)` in a `try/catch`, and `handleAATriggers()` (`aa_composer.js:59-89`) that drives trigger processing from the DB queue likewise has no surrounding try/catch: [4](#0-3) 

A synchronously-thrown `Error` from deep inside `evaluate()` therefore propagates unguarded up through the whole AA-trigger processing call stack. Because there is no global `uncaughtException`/domain handler wrapping this logic path (only `network.js` references such handlers, unrelated to AA trigger processing), the thrown exception is fatal to the Node.js process.

### Impact Explanation
Any user can define an AA whose formula (or getter, or state-update formula) calls `parse_date()` with a value evaluated at trigger time. Whenever this triggers the divergent modulo branch (or a future/engine-dependent parse discrepancy), the responding full node's AA-processing worker throws an uncaught exception and crashes the node process while it is in the middle of writing AA trigger results (`handlePrimaryAATrigger`/`handleTrigger`). This is a denial-of-service against any full node that executes AA triggers, and — because `Date.parse` is not guaranteed spec-consistent for the accepted space-separated format — different node versions could also diverge on whether a given `parse_date` call succeeds or throws, creating a **node disagreement on AA-response validity/state**, matching the “node disagreement on validity or stability” impact criterion.

### Likelihood Explanation
Likelihood is high for the crash path being reachable: any unprivileged account can post a unit that triggers an AA containing `parse_date(...)` in its definition, and AA definitions/formulas are attacker-authorable content (an attacker can even deploy their own malicious AA). No special privilege beyond normal unit/trigger posting is required. The exact date-string input required to hit the `ts % 1000` branch on a given Node/V8 build is engine-dependent and not something the report can fully verify without executing on the target Node.js version, but the code path itself (an unguarded `throw` reachable from user-controlled formula content) is confirmed by static analysis of `formula/evaluation.js:2524-2525` and the absence of any enclosing try/catch through `aa_composer.js`.

### Recommendation
- Replace `throw Error("non-integer seconds")` with the same fatal/negative-result convention used elsewhere in `parse_date` (`return cb(false);` or `setFatalError(...)`), so malformed/edge-case dates are treated as ordinary evaluation failures rather than crashing the process.
- Restrict `parse_date`'s regexes to the strict ISO-8601 extended format only (require `T`, disallow the ambiguous space separator) to avoid implementation-defined `Date.parse` behavior that can vary across JS engines/Node versions and threaten determinism.
- Add a top-level guard (try/catch) around formula evaluation entry points in `aa_composer.js` (`evaluateAA`, `replace`, `executeStateUpdateFormula`, and `handlePrimaryAATrigger`) so that any unexpected internal exception in the formula evaluator degrades to an AA bounce/error rather than crashing the node.

### Proof of Concept
1. Deploy an AA whose response/state-update formula includes: `parse_date(trigger.data.d)`.
2. Post a trigger unit with `data.d` set to a date string matching `^\d\d\d\d-\d\d-\d\d( |T)\d\d:\d\d:\d\dZ$` (e.g. a space-separated ISO date/time) chosen such that on the target node's Node.js/V8 build `Date.parse()` yields a non-multiple-of-1000 millisecond value.
3. When the trigger is processed by `handleAATriggers` → `handleTrigger` → `evaluateAA`/`replace`/`executeStateUpdateFormula` → `formula/evaluation.js` `evaluate()`, the `case 'parse_date'` branch executes `throw Error("non-integer seconds")`, which is never caught anywhere in the call chain, crashing the AA-processing Node.js process.

### Citations

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

**File:** aa_composer.js (L59-89)
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
						});
						unlock();
						onDone();
					}
				);
			}
		);
	});
}
```

**File:** aa_composer.js (L1454-1457)
```javascript
		formulaParser.evaluate(opts, [], objStateUpdate.xpath, function (err, res) {
		//	console.log('--- state update formula', objStateUpdate.formula, '=', res);
			if (res === null)
				return cb(err.formattedError || "formula " + objStateUpdate.formula + " failed: "+err);
```

**File:** aa_composer.js (L1865-1867)
```javascript
		evaluateAA(arrDefinition, function (err) {
			if (err)
				return bounce(err);
```
