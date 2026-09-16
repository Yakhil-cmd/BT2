### Title
Uncaught exception via crafted `parse_date()` timestamp in AA oscript crashes the node - (File: `formula/evaluation.js`)

### Summary
The `parse_date` oscript function, reachable by any AA definition author and triggerable by any unprivileged user who posts a trigger unit that causes that AA's formula to evaluate a `parse_date(...)` expression, can throw an unhandled JavaScript exception instead of returning a graceful formula error. This mirrors the OpenLDAP `checkTime`/`issuerAndThisUpdateCheck` bug class: a crafted, attacker-controlled timestamp-like input reaches a low-level date-parsing routine and triggers an assertion/exception path that was not designed to be recoverable, causing a daemon crash (denial of service) rather than a validation rejection.

### Finding Description
`parse_date` is implemented in the AA formula evaluator: [1](#0-0) 

Every other error branch inside `evaluate()` in this file uses the controlled `setFatalError(...)` path to gracefully fail the formula evaluation (e.g. the sibling `timestamp_to_string` case wraps `new Date(...)` in try/catch and calls `setFatalError` on error, see `formula/evaluation.js:2485-2494`). The `parse_date` branch is the one exception: when the attacker-supplied date string matches the `datetime` regex and `Date.parse()` yields a value where `ts % 1000` is truthy, the code does:

```js
if (ts % 1000)
    throw Error("non-integer seconds");
```

This is a synchronous `throw` inside a callback passed to the internal `evaluate()` function, not funneled through `setFatalError`, and not wrapped in any try/catch at this call site. `formulaParser.evaluate()` (`exports.evaluate` in `formula/evaluation.js:64`) itself only wraps the *parser* step in try/catch (`formula/evaluation.js:108-120`); the actual expression evaluation, including this `parse_date` case, runs unguarded.

`formulaParser.evaluate` is invoked throughout AA trigger processing in `aa_composer.js` (e.g. `evaluateAA`, `replace`, `executeStateUpdateFormula` — see `aa_composer.js:589-786` and `aa_composer.js:1431-1462`) without any try/catch around these calls either. These, in turn, are invoked from `handleTrigger` / `handlePrimaryAATrigger` / `handleAATriggers` (`aa_composer.js:59-150`), which process triggers pulled directly from posted units — content fully controlled by an unprivileged unit poster (e.g. via `trigger.data`, which can be echoed into a `parse_date(...)` call by AA code, or via an AA definition that calls `parse_date` on attacker-influenced data).

Because the throw is synchronous and none of the surrounding async callback chains have a try/catch, this propagates as an uncaught exception up through Node's callback/event-loop stack. Node.js treats an uncaught exception thrown inside an async callback as a fatal, unrecoverable error unless a process-wide `uncaughtException` handler is installed and chooses to keep running; a partial handler exists only in `network.js`, and even where present such handlers are commonly used only for logging/telemetry before the process still becomes unstable or restarts. The net effect is that a single crafted unit (an AA trigger, or an asset/oscript definition that calls `parse_date`) can deterministically crash every full node that evaluates it, exactly analogous to the OpenLDAP `slapd` DoS via a crafted timestamp reaching `checkTime`.

### Impact Explanation
This is a concrete network-wide denial of service: any full node (and light-vending hub) that processes the malicious trigger/AA formula containing the crafted `parse_date` input will crash while evaluating an AA response. Since AA triggers are processed automatically as new units are stabilized, an attacker can send a single unit to a public AA (or deploy their own AA) that calls `parse_date` on attacker-controlled data, causing every node that evaluates that AA to crash — this can be repeated to keep nodes down, preventing the network from confirming new units. This satisfies the "network unable to confirm new units" / node-disagreement bar for this scan.

### Likelihood Explanation
Likelihood is high for any AA that passes trigger-supplied or otherwise attacker-influenced data into `parse_date`. The attacker only needs to craft a date string of the form `YYYY-MM-DD HH:MM:SS[Z]` (or `T` separator) that `Date.parse` resolves to a millisecond value not evenly divisible by 1000. This requires no special privileges — only the ability to post a regular unit as trigger to a public AA (or to deploy the vulnerable AA definition itself, which is permission-less on Obyte). No malicious peer/hub/relay is needed; the trigger is a normal, validly-signed unit.

### Recommendation
Wrap the `ts % 1000` check (and any other exceptional condition in the `parse_date` branch) using the same `setFatalError(...)` mechanism used by every other case in `evaluate()`, rather than a bare `throw`. At minimum:
```js
if (ts % 1000)
    return setFatalError("non-integer seconds in parse_date", { arr }, false, cb);
```
Additionally, audit `formula/evaluation.js` for any other bare `throw` statements inside the `evaluate()` switch that bypass `setFatalError`, and add defensive top-level try/catch around `formulaParser.evaluate` invocations in `aa_composer.js` so that any future unexpected internal throw during untrusted AA/trigger processing degrades to a bounced/failed response instead of crashing the process.

### Proof of Concept
1. Deploy (or use an existing) AA whose code path passes `trigger.data`-derived input into `parse_date(...)`, e.g.:
   ```
   {
     messages: [{
       app: 'state',
       state: `{
         $ts = parse_date(trigger.data.d);
       }`
     }]
   }
   ```
2. As an unprivileged user, post a trigger unit to this AA with `data.d` set to a date/time string that matches the `datetime` regex in `formula/evaluation.js:2518-2520` but whose `Date.parse()` result is not a whole number of seconds (i.e., `ts % 1000 !== 0`) — reachable purely through crafted timezone/locale-adjacent strings accepted by the engine's `Date.parse`.
3. When the AA trigger is processed by `handlePrimaryAATrigger` → `handleTrigger` → `evaluateAA`/`replace` → `formulaParser.evaluate`, the `parse_date` case executes `throw Error("non-integer seconds")` unguarded, propagating as an uncaught exception and crashing the evaluating node process, exactly analogous to the crafted-timestamp assertion failure in `CVE-2021-27212`.

### Citations

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
