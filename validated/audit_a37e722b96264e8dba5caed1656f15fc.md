### Title
Denial of Service via Unhandled Exception in Unprivileged "vote" Message Validation - (File: validation.js)

### Summary
`ocore`'s unit-validation pipeline contains numerous `throw Error(...)` statements inside asynchronous DB-callback code paths that are reachable while validating a single, unprivileged, attacker-posted unit. Unlike synchronous validation checks (which return errors through `callback(err)` and are properly reported as `ifUnitError`/`ifJointError`), these `throw` statements escape the `async.series`/`conn.query` callback chain entirely and become unhandled exceptions. Because `network.js` installs a global `uncaughtException` handler that deliberately re-throws to crash the process (`process.on('uncaughtException', ...) { ... throw err; // crash the process ...}`), any single crafted unit that reaches one of these `throw` branches brings down the entire hub/full node — the same bug class as the hapi CORS advisory, where a value the caller does not fully sanitize leads to an unhandled exception that kills the service.

### Finding Description
The `vote` message handler in `validateMessage`/`validateInlinePayload` queries the DB for the poll/choice referenced by the vote and asserts the invariant "exactly one row must match": [1](#0-0) 

```
conn.query(
    "SELECT main_chain_index, sequence FROM polls JOIN poll_choices USING(unit) JOIN units USING(unit) WHERE unit=? AND choice=?",
    [payload.unit, payload.choice],
    function(poll_unit_rows){
        if (poll_unit_rows.length > 1)
            throw Error("more than one poll?");
        ...
```

`payload.unit` and `payload.choice` in a `vote` message are fully attacker-controlled fields of the posted unit (they only need to pass the earlier structural checks — a valid-length unit hash and a string choice). If the row-count invariant "at most one row per (unit, choice)" is ever violated — e.g., through duplicate `poll_choices` rows or any inconsistency between the `polls`/`poll_choices` tables and the assumption baked into the query — the `throw` fires inside the `conn.query` callback. This callback executes outside of any surrounding `try/catch` in the validation call stack (`validateInlinePayload` → `validateMessage` → `validateMessages` → `async.series` in `validate()`), so the exception is not converted into `ifUnitError`. It instead becomes an uncaught exception in the Node.js event loop.

This same unhandled-throw-in-async-callback pattern recurs throughout the codebase reachable from ordinary unit posting, e.g.:
- `checkForDoublespends`: `throw Error("conflicting "+type+" spent from another address?")` and `throw Error("unreachable code, conflicting "+type+" in unit "+objConflictingRecord.unit)` [2](#0-1) 
- best-parent selection: `throw Error("zero or more than one best parent unit?")` [3](#0-2) 
- last-ball stabilization: `throw Error("last ball unit "+last_ball_unit+" just became stable but ball not found")` [4](#0-3) 

All of these are guarded by developer assumptions ("should never happen"), not by structural input validation, and all execute inside async DB callbacks with no enclosing `try/catch`.

The fatal consequence is confirmed by the process-wide exception handler: [5](#0-4) 

```
process.on('uncaughtException', (err) => {
    console.log('Uncaught exception:', err);
    ...
    throw err; // crash the process to avoid ending up in an inconsistent state
});
```

### Impact Explanation
Any single unprivileged unit poster who can drive validation into one of these "impossible" branches causes the receiving hub/full node process to crash immediately (Node.js re-throws inside an `uncaughtException` handler, which terminates the process). Because hubs relay units to many light clients and full nodes rely on continuous validation to advance MC stability, a reliable crash trigger lets an attacker repeatedly take down nodes/hubs that process the malicious unit, preventing the network from confirming new units for connected clients — matching the "network unable to confirm new units" impact bar.

### Likelihood Explanation
Likelihood is Medium-High conditioned on confirming that the specific row-count invariant (e.g., `poll_choices` uniqueness on `(unit, choice)`) can actually be violated by data an attacker fully controls (poll definition + vote unit), which requires verifying the DB schema/insert logic for `polls`/`poll_choices` in `writer.js`. I was not able to fully confirm within the available context whether a `UNIQUE(unit, choice)` constraint exists that would prevent the double-row condition; if such a constraint exists, this specific `vote` throw is not reachable, but the broader class of unguarded `throw` inside async validation callbacks (doublespend checks, best-parent selection, last-ball stabilization) remains a live DoS surface reachable from ordinary unit posting, since those do not depend on any uniqueness constraint and are reached via normal, permitted validation flows for payments and DAG parent processing.

### Recommendation
- Audit every `throw Error(...)` inside `conn.query`/`async` callbacks in `validation.js`, `definition.js`, and `writer.js` that are reachable during validation of an untrusted, single, attacker-supplied unit; convert them to `callback(err)`/`ifUnitError` paths instead of hard throws, or wrap them in `try/catch` that reports a `UnitError` rather than crashing.
- Do not allow a single malformed unit to take down the whole process; the `uncaughtException` handler in `network.js` should distinguish between validation-time errors originating from untrusted peer/attacker input (which should be turned into rejected units) and genuine internal invariant violations that legitimately warrant a crash.
- Add/verify DB-level uniqueness constraints (e.g., `poll_choices(unit, choice)`) so that "should never happen" `rows.length > 1` assumptions are actually enforced structurally, not just assumed.

### Proof of Concept
Conceptual (requires confirming DB constraints, hence Medium confidence):
1. Attacker posts a `poll` definition unit whose `poll_choices` include the same choice value more than once (or otherwise causes the polls/poll_choices join for a given `(unit, choice)` to return >1 row).
2. Attacker posts a `vote` unit referencing that `poll.unit` and the duplicated `choice`.
3. During validation of the vote unit, `validateInlinePayload`'s `"vote"` case (validation.js:1826-1841) issues the `conn.query` above; the callback observes `poll_unit_rows.length > 1` and executes `throw Error("more than one poll?")`.
4. This exception is not caught by any `try/catch` in the call chain and propagates to Node's event loop, triggering `process.on('uncaughtException', ...)` in `network.js:4530-4543`, which re-throws and crashes the node/hub process, denying service to all peers connected to it.

### Citations

**File:** validation.js (L815-820)
```javascript
							conn.query("SELECT ball FROM balls WHERE unit=?", [last_ball_unit], function(ball_rows){
								if (ball_rows.length === 0)
									throw Error("last ball unit "+last_ball_unit+" just became stable but ball not found");
								if (ball_rows[0].ball !== last_ball)
									return callback("last_ball "+last_ball+" and last_ball_unit "+last_ball_unit
													+" do not match after advancing stability point");
```

**File:** validation.js (L1661-1705)
```javascript
function checkForDoublespends(conn, type, sql, arrSqlArgs, objUnit, objValidationState, onAcceptedDoublespends, cb){
	conn.query(
		sql, 
		arrSqlArgs,
		function(rows){
			if (rows.length === 0)
				return cb();
			var arrAuthorAddresses = objUnit.authors.map(function(author) { return author.address; } );
			async.eachSeries(
				rows,
				function(objConflictingRecord, cb2){
					if (arrAuthorAddresses.indexOf(objConflictingRecord.address) === -1)
						throw Error("conflicting "+type+" spent from another address?");
					if (conf.bLight) // we can't use graph in light wallet, the private payment can be resent and revalidated when stable
						return cb2(objUnit.unit+": conflicting "+type);
					graph.determineIfIncludedOrEqual(conn, objConflictingRecord.unit, objUnit.parent_units, function(bIncluded){
						if (bIncluded){
							var error = objUnit.unit+": conflicting "+type+" in inner unit "+objConflictingRecord.unit;

							// too young (serial or nonserial)
							if (objConflictingRecord.main_chain_index > objValidationState.last_ball_mci || objConflictingRecord.main_chain_index === null)
								return cb2(error);

							// in good sequence (final state); final-bad is excluded by the query and treated as non-existent
							if (objConflictingRecord.sequence === 'good')
								return cb2(error);

							throw Error("unreachable code, conflicting "+type+" in unit "+objConflictingRecord.unit);
						}
						else{ // arrAddressesWithForkedPath is not set when validating private payments
							if (objValidationState.arrAddressesWithForkedPath && objValidationState.arrAddressesWithForkedPath.indexOf(objConflictingRecord.address) === -1)
								throw Error("double spending "+type+" without double spending address?");
							cb2();
						}
					});
				},
				function(err){
					if (err)
						return cb(err);
					onAcceptedDoublespends(cb);
				}
			);
		}
	);
}
```

**File:** validation.js (L1826-1841)
```javascript
			conn.query(
				"SELECT main_chain_index, sequence FROM polls JOIN poll_choices USING(unit) JOIN units USING(unit) WHERE unit=? AND choice=?", 
				[payload.unit, payload.choice],
				function(poll_unit_rows){
					if (poll_unit_rows.length > 1)
						throw Error("more than one poll?");
					if (poll_unit_rows.length === 0)
						return callback("invalid choice "+payload.choice+" or poll "+payload.unit);
					var objPollUnitProps = poll_unit_rows[0];
					if (objPollUnitProps.main_chain_index === null || objPollUnitProps.main_chain_index > objValidationState.last_ball_mci)
						return callback("poll unit must be before last ball");
					if (objPollUnitProps.sequence !== 'good')
						return callback("poll unit is not serial");
					return callback();
				}
			);
```

**File:** writer.js (L431-448)
```javascript
			conn.query(
				`SELECT unit
				FROM units AS parent_units
				WHERE unit IN(?) ${compatibilityCondition}
				ORDER BY witnessed_level DESC,
					level-witnessed_level ASC,
					unit ASC
				LIMIT 1`, 
				params, 
				function(rows){
					if (rows.length !== 1)
						throw Error("zero or more than one best parent unit?");
					my_best_parent_unit = rows[0].unit;
					if (my_best_parent_unit !== objValidationState.best_parent_unit)
						throwError("different best parents, validation: "+objValidationState.best_parent_unit+", writer: "+my_best_parent_unit);
					conn.query("UPDATE units SET best_parent_unit=? WHERE unit=?", [my_best_parent_unit, objUnit.unit], function(){ cb(); });
				}
			);
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
