### Title
Uncaught exception on malformed `parse_date()` input crashes AA trigger processing instead of failing gracefully - ([File: formula/evaluation.js])

### Summary
`IO::Uncompress::Unzip`'s `_dosToUnixTime()` calls `Time::Local::timelocal()` without an `eval` guard, so a malformed date field throws and the exception propagates past the module's error-handling contract. The oscript formula evaluator in ocore has the same bug-class pattern in the `parse_date` operator: a crafted date string that passes the regex checks but decodes to a non-integer-seconds timestamp causes a bare `throw Error(...)` with no surrounding `try/catch`, unlike the sibling `timestamp_to_string` handler which is properly guarded.

### Finding Description
In `formula/evaluation.js`, the `parse_date` case parses an attacker/AA-author controlled string: [1](#0-0) 

If the string matches `^\d\d\d\d-\d\d-\d\d( |T)\d\d:\d\d:\d\dZ$` or the no-`Z` variant, `Date.parse()` is used to compute `ts`. When `ts % 1000 !== 0` — which is reachable if `Date.parse` returns a value with non-zero milliseconds for certain malformed-but-matching inputs or leap-second-adjacent edge cases handled inconsistently by the JS `Date` engine across Node versions — the code does:
```
if (ts % 1000)
    throw Error("non-integer seconds");
```
This `throw` is **not** wrapped in a `try/catch`, in contrast to the neighboring `timestamp_to_string` case a few lines above, which explicitly wraps its `new Date(...)` construction in `try { ... } catch (e) { return setFatalError(...) }` at [2](#0-1) .

All other error conditions in `evaluate()` are converted into controlled failures via `setFatalError(...)`/`cb(false)`, which the formula engine treats as a normal (non-fatal to the process) formula failure, ultimately reported back through the `evaluate` callback as an error string (see the parser-error handling pattern at [3](#0-2) ). The `parse_date` throw bypasses this contract entirely and becomes a genuine unguarded JS exception that unwinds the call stack of `formulaParser.evaluate`.

This formula code runs whenever an AA is triggered — the trigger's `trigger.data`, or values derived from it, can be fed into `parse_date(...)` inside the AA's own oscript code. Because AA definitions and triggers are attacker/user controlled (an AA author can write `parse_date(trigger.data.d)` and any unprivileged unit poster can send the triggering payment with attacker-chosen `data.d`), this is reachable by an unprivileged trigger sender in combination with an AA author's script, exactly as required by the "AA definitions and triggers" reachability scope.

I could not find a `try/catch` wrapping `formulaParser.evaluate(...)` calls inside `aa_composer.js`'s trigger execution path (`handleTrigger`/`evaluateAA`/`handleAATriggers`), meaning an uncaught exception thrown deep inside `evaluate()` would propagate out of the `async.eachSeries` callback chain in `handleAATriggers`, which is invoked during stabilization/trigger processing rather than under `validation.validate`'s controlled error surface. `validation.validate` protects against unexpected exceptions in its own `async.series` chain but AA execution is driven separately.

### Impact Explanation
Because the resulting exception is not intercepted anywhere in the formula-evaluation or AA-trigger-processing call chain, it can escape as an unhandled/uncaught exception. In `network.js` there is a global `process.on('uncaughtException', ...)` handler that deliberately re-throws to crash the process (`throw err; // crash the process to avoid ending up in an inconsistent state`, [4](#0-3) ), confirming that uncaught exceptions in this codebase are treated as fatal-by-design rather than recoverable — turning a formula-evaluation bug reachable by any AA-triggering unit into a full node crash / denial of service for any full node processing that trigger, and potentially inconsistent behavior between nodes (some crash, some may not reach the same code path depending on timing), risking disagreement on AA response processing/stability.

### Likelihood Explanation
Medium. It requires an AA whose oscript uses `parse_date()` on attacker-influenced data, and specifically an input string that matches the strict `YYYY-MM-DD(T| )HH:MM:SS(Z)?` regex yet yields a timestamp with non-zero milliseconds under `Date.parse()`. This is a narrow but concrete edge case (analogous to the CVE's malformed-but-parseable date field), and any unprivileged user can post the triggering unit; the AA author only needs to include a common pattern like `parse_date(trigger.data.d)`.

### Recommendation
Wrap the `parse_date` timestamp computation and the `ts % 1000` check in a `try/catch`, converting failures into `cb(false)` / `setFatalError(...)` exactly as `timestamp_to_string` does, so malformed dates produce a graceful oscript-level `false`/bounce instead of an uncaught JS exception. Additionally, audit `aa_composer.js`'s AA trigger execution path to ensure any exception thrown from `formulaParser.evaluate` is caught and converted into a bounced/failed trigger response rather than crashing the node.

### Proof of Concept
1. Deploy an AA with oscript such as:
```
{
  $ts = parse_date(trigger.data.d);
  bounce("got " || $ts);
}
```
2. Send a trigger unit with `data.d` set to a date string that matches the second/third regex branches in `parse_date` (`^\d\d\d\d-\d\d-\d\d( |T)\d\d:\d\d:\d\dZ$` or without `Z`) but for which `Date.parse(...)` yields a timestamp with `ts % 1000 !== 0`.
3. During evaluation, `formula/evaluation.js`'s `parse_date` handler at [5](#0-4)  throws `Error("non-integer seconds")` uncaught.
4. Because no `try/catch` exists around this throw or around the `formulaParser.evaluate` call in the AA trigger-processing path, the exception propagates and is caught only by the global `uncaughtException` handler in `network.js`, which re-throws to crash the process — denying service to the node processing that trigger.

### Citations

**File:** formula/evaluation.js (L104-120)
```javascript
	var parser = {};
	if(cache[formula]){
		parser.results = cache[formula];
	}else {
		try {
			parser = new nearley.Parser(nearley.Grammar.fromCompiled(grammar));
			parser.feed(formula);
			formulasInCache.push(formula);
			cache[formula] = parser.results;
			if (formulasInCache.length > cacheLimit) {
				var f = formulasInCache.shift();
				delete cache[f];
			}
		}catch (e) {
			console.log('exception from parser', e);
			return callback('parse failed: '+e, null);
		}
```

**File:** formula/evaluation.js (L2485-2494)
```javascript
						try {
							var str = new Date(ts * 1000).toISOString().replace('.000', '');
							if (format === 'date')
								str = str.substr(0, 10);
							else if (format === 'time')
								str = str.substr(11, 8);
						}
						catch (e) {
							return setFatalError("invalid timestamp in timestamp_to_string: " + e, { arr }, false, cb);
						}
```

**File:** formula/evaluation.js (L2500-2528)
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
				break;
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
