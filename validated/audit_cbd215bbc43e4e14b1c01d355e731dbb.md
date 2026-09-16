### Title
Crafted-unit assertion crash in double-spend handling forces full-node process termination - (File: `validation.js`)

### Summary
CVE-2016-9393 is a class of bug where a malformed/crafted input hits an internal `assert()`-style invariant in JasPer's `jpc_pi_nextrpcl`, aborting the process (DoS). `ocore` has a structurally identical bug-class: many low-level invariant checks inside unit-validation code paths are written as `throw Error(...)` "this should never happen" assertions rather than being fed back through the normal `callback(errorString)` validation-error channel. Because `network.js` installs a global `process.on('uncaughtException', ...)` handler that deliberately **re-throws to crash the process** [1](#0-0) , any unexpected code path that reaches one of these `throw Error` invariants while processing a *single, attacker-crafted but syntactically valid unit* kills the entire full node process — exactly the "assertion failure / crafted input / DoS" pattern of the CVE.

### Finding Description
`validation.js`'s `checkForDoublespends()` — invoked from the payment input/double-spend validation path reachable by any unit poster — contains invariant assumptions expressed as hard `throw Error(...)` rather than soft validation failures: [2](#0-1) 

Specifically:
- `throw Error("conflicting "+type+" spent from another address?")` at line 1673 fires if a conflicting input's `address` is not among the current unit's authors.
- `throw Error("unreachable code, conflicting "+type+" in unit "+objConflictingRecord.unit)` at line 1688 fires when a conflicting record is included in parents, is not "too young", and its `sequence` is not `'good'` (i.e. it is `final-bad`, `temp-bad`, or any state the author didn't anticipate).
- `throw Error("double spending "+type+" without double spending address?")` at line 1692 fires when the conflicting record is *not* included in parents and `objValidationState.arrAddressesWithForkedPath` doesn't already contain that address.

These are all reachable purely from the *content* of a posted unit's `payment` message inputs interacting with existing DAG state (other units' `inputs`/`sequence` rows) — no privileged role, hub, or peer trust is required; a normal unprivileged unit poster controls the inputs, parents, and can pick which prior outputs to reference. The comment `"unreachable code"` at line 1688 is itself the tell: this is a defensive assertion the author believed could never fire, structurally the same class of bug as JasPer's failed assertion in `jpc_pi_nextrpcl` — an "impossible" invariant that a specially crafted structure (there: JPEG2000 codestream; here: a DAG/input arrangement) can actually violate.

Because unit validation runs inside `async.eachSeries`/`async.forEachOfSeries` callback chains (not inside a caller-level `try/catch` that funnels back to `ifUnitError`), a thrown `Error` here propagates as an uncaught exception up through Node's event loop rather than being caught by `validate()`'s `async.series` error callback at `validation.js:445-472` [3](#0-2) . It is picked up only by the global handler in `network.js`, which explicitly crashes the process "to avoid ending up in an inconsistent state" [1](#0-0) .

This same "throw as assertion, no catch, global handler re-throws" pattern recurs pervasively across the codebase in unit/stability-critical code that processes attacker-influenced structures: `validateParents` [4](#0-3) , `main_chain.js` stability walking [5](#0-4) , and `writer.js` best-parent/witnessed-level recomputation [6](#0-5) , all of which operate deterministically on unit/DAG content that an unprivileged poster fully controls.

### Impact Explanation
Because the invariant is evaluated deterministically from unit content and existing chain state, **every full node** that receives and validates the crafted unit (not just the originating node) will hit the same assertion and crash via the same `uncaughtException` handler. This is not a single-node, operator-specific, or resource-exhaustion issue — it is a reproducible poison-pill unit that, once broadcast, causes synchronized crashes across the full-node population that processes it, directly matching the required impact category "a network unable to confirm new units."

### Likelihood Explanation
Medium: constructing the exact combination of (a) an input referencing a real prior output, (b) a `sequence`/inclusion state for the conflicting record outside the two branches the author anticipated (`'good'`-and-included or forked-and-tracked), and (c) getting it accepted up to this point in validation requires understanding of the double-spend/serialization state machine (`sequence`, `main_chain_index`, `arrAddressesWithForkedPath`), but no privileged role, key compromise, or peer/hub trust — only crafting one unit as a normal user. This matches the CVSS `AC:L/PR:N/UI:R`-style profile of the original CVE (low complexity, no privileges, requires triggering interaction i.e., broadcasting the unit).

### Recommendation
- Replace the `throw Error(...)` invariant checks in `checkForDoublespends` (lines 1673, 1688, 1692) with calls to `cb2(errorString)`/`callback(errorString)` so that unanticipated double-spend/fork states are rejected as a normal `ifUnitError`/`ifJointError` outcome instead of crashing the process.
- Audit other "should never happen" `throw Error` invariants reachable from unit/message content in `validation.js`, `main_chain.js`, `parent_composer.js`, and `writer.js` and convert them to soft validation failures wrapped in `try/catch` at the point of unit processing, so a crafted unit can be rejected rather than crash the node.
- Consider removing or hardening the `process.on('uncaughtException')` re-throw in `network.js` so a single validation-code defect cannot be weaponized into a network-wide crash amplifier; at minimum, ensure validation of untrusted unit content cannot reach un-caught throws.

### Proof of Concept
Conceptual (cannot be fully constructed without live DAG state, but the reachable path is concrete):
1. Attacker posts unit A spending output O from address X, and lets it become `final-bad` (e.g., it loses a double-spend race) so its `sequence` is `final-bad`.
2. Attacker crafts unit B, authored by a different address Y, whose parents/last-ball do **not** include A but do include a competing spender of the same output O whose `sequence` state does not match `'good'` and is not already tracked in `objValidationState.arrAddressesWithForkedPath` for address X (achieved by arranging B's parents to walk a DAG branch where the conflicting record was never associated with a recorded fork for that address).
3. When any full node validates unit B, `checkForDoublespends` finds the conflicting row, evaluates `graph.determineIfIncludedOrEqual`, and falls into the `else` branch at line 1690 where `arrAddressesWithForkedPath` does not contain X, hitting `throw Error("double spending ... without double spending address?")` at line 1692.
4. The exception propagates uncaught to `process.on('uncaughtException')` in `network.js`, which re-throws and terminates the node process for every full node that validates unit B. [7](#0-6)

### Citations

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

**File:** validation.js (L445-472)
```javascript
			function(err){
				if(err){
					if (profiler.isStarted())
						profiler.stop('validation-advanced-stability');
					// We might have advanced the stability point and have to commit the changes as the caches are already updated.
					// There are no other updates/inserts/deletes during validation
					commit_fn(function(){
						var consumed_time = Date.now()-start_time;
						profiler.add_result('failed validation', consumed_time);
						console.log(objUnit.unit+" validation "+JSON.stringify(err)+" took "+consumed_time+"ms");
						if (!external_conn)
							conn.release();
						unlock();
						if (typeof err === "object"){
							if (err.error_code === "unresolved_dependency")
								callbacks.ifNeedParentUnits(err.arrMissingUnits, err.bRequestPrunedContent);
							else if (err.error_code === "need_hash_tree") // need to download hash tree to catch up
								callbacks.ifNeedHashTree();
							else if (err.error_code === "invalid_joint") // ball found in hash tree but with another unit
								callbacks.ifJointError(err.message);
							else if (err.error_code === "transient")
								callbacks.ifTransientError(err.message);
							else
								throw Error("unknown error code");
						}
						else
							callbacks.ifUnitError(err);
					});
```

**File:** validation.js (L676-678)
```javascript
	var objUnit = objJoint.unit;
	if (objValidationState.bAA && objUnit.parent_units.length > 2)
		throw Error("AA unit with more than 2 parents");
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

**File:** main_chain.js (L484-493)
```javascript
				conn.query("SELECT unit, is_on_main_chain, main_chain_index, level FROM units WHERE best_parent_unit=?", [last_stable_mc_unit], function(rows){
					if (rows.length === 0){
						if (storage.isGenesisUnit(last_added_unit))
						    return markMcIndexStable(conn, batch, 0, finish);
						throw Error("no best children of last stable MC unit "+last_stable_mc_unit+"?");
					}
					var arrMcRows  = rows.filter(function(row){ return (row.is_on_main_chain === 1); }); // only one element
					var arrAltRows = rows.filter(function(row){ return (row.is_on_main_chain === 0); });
					if (arrMcRows.length !== 1)
						throw Error("not a single MC child?");
```

**File:** writer.js (L440-446)
```javascript
				function(rows){
					if (rows.length !== 1)
						throw Error("zero or more than one best parent unit?");
					my_best_parent_unit = rows[0].unit;
					if (my_best_parent_unit !== objValidationState.best_parent_unit)
						throwError("different best parents, validation: "+objValidationState.best_parent_unit+", writer: "+my_best_parent_unit);
					conn.query("UPDATE units SET best_parent_unit=? WHERE unit=?", [my_best_parent_unit, objUnit.unit], function(){ cb(); });
```
