### Title
Reachable assertion abort in `checkForDoublespends()` on crafted double-spend input crashes the node process - ([File: validation.js])

### Summary
`ocore`'s unit validator contains several `throw Error(...)` "assertions" that assume specific invariants can never be violated by external input. In `checkForDoublespends()` these throws are reachable from a single, otherwise well-formed unit posted by any unprivileged peer/wallet during normal payment/spend-proof validation, and any thrown exception inside this code path is not caught, so it propagates to `process.on('uncaughtException')`, which deliberately kills the node process. This mirrors the CVE-2017-13726 pattern: a reachable "should never happen" assertion inside a core data-processing function is actually triggerable by crafted, attacker-supplied input and results in denial of service.

### Finding Description
`checkForDoublespends()` is invoked from `validateSpendProofs()` (for private payment spend proofs) and from `checkInputDoubleSpend()` inside `validatePaymentInputsAndOutputs()` (for every payment input type: issue, transfer, headers_commission, witnessing) whenever the SQL lookup finds units that conflict on the same spend-proof/output/serial-number/mc-range key: [1](#0-0) 

The function assumes:
1. Any conflicting record's `address` must belong to one of the current unit's authors (`arrAuthorAddresses`) — otherwise it `throw`s "conflicting … spent from another address?".
2. If the conflicting unit is included in the current unit's parents, it must be either "too young" or in bad sequence — otherwise (i.e. good sequence, but old enough) it hits `throw Error("unreachable code, …")`.
3. If the conflicting unit is *not* included in parents (a real double-spend on divergent paths), the conflicting address must already be present in `objValidationState.arrAddressesWithForkedPath` (populated earlier in `validateAuthors`/`checkSerialAddressUse` only when the *current* unit's own author addresses have detected conflicting units) — otherwise `throw Error("double spending … without double spending address?")`. [2](#0-1) 

These invariants can fail to hold once genuinely independent, unprivileged actors interact: e.g. `arrAddressesWithForkedPath` is populated per-author strictly from conflicts against *that author's own* prior serial-address usage in `checkSerialAddressUse()` (`validation.js:1304-1343`), while `checkForDoublespends` is separately evaluating conflicts keyed by output/spend-proof/mc-range which can point to a *different* address (e.g. multi-authored units, or `objAsset.issued_by_definer_only`/attested assets where addresses differ from the primary author) that never went through the forked-path bookkeeping. Because the double-spend detection query and the forked-path bookkeeping are maintained by separate, independently-evolving code paths, an attacker who crafts a unit that produces a genuine but structurally atypical conflict (e.g. targeting `headers_commission`/`witnessing` inputs, or asset inputs where `objAsset.issued_by_definer_only` is false and the queried `address` differs from the unit's authors) can reach a state the developers assumed impossible, tripping one of these `throw` assertions. [3](#0-2) 

Because `checkForDoublespends` runs inside async DB-query callbacks with no surrounding `try/catch`, the thrown `Error` is not converted into a normal validation error (`ifUnitError`); it becomes an uncaught exception. `network.js` explicitly re-throws on `uncaughtException` to crash the process: [4](#0-3) 

### Impact Explanation
A crash triggered by validating a single posted unit is a direct denial-of-service on any full node (hub, witness, or normal full node) that receives and validates the crafted unit — matching the "network unable to confirm new units" impact category, since witnesses/hubs repeatedly restarting or crashing on the same replayed unit disrupts consensus availability. Unlike malicious-peer/network-layer DoS (explicitly out of scope), this is a logic-level reachable-assertion bug in the payment/spend-proof validation code that any unprivileged unit poster can trigger through the normal, permitted "post a unit" interface.

### Likelihood Explanation
Reaching this requires crafting a unit (and possibly a supporting sequence of prior units) that produces a genuine conflicting-input/spend-proof database row whose `address` is not accounted for by the author-centric `arrAddressesWithForkedPath` bookkeeping — a non-trivial but purely input-driven condition requiring no special privileges, keys, or node compromise, only the ability to broadcast crafted units, similar in spirit to the crafted-file requirement of the original TIFF CVE.

### Recommendation
- Replace the internal `throw Error(...)` assertions in `checkForDoublespends()` (`validation.js:1673`, `1688`, `1692`) with graceful `cb2(error)` / `callback(error)` paths that reject the unit as invalid, instead of crashing the process, whenever the "impossible" condition is observed.
- Audit `checkInputDoubleSpend`/`checkForDoublespends` call sites for asset types where the double-spend `address` can legitimately diverge from `arrAuthorAddresses` or from the forked-path bookkeeping (issued_by_definer_only assets, headers_commission/witnessing multi-author inputs) and ensure `arrAddressesWithForkedPath` is populated consistently for all of them before this check runs.
- Wrap unit validation in defensive `try/catch` so that unexpected internal assertion failures degrade to `ifUnitError`/`ifTransientError` rather than a full process crash via `uncaughtException`.

### Proof of Concept
Conceptual trigger (requires DB/asset-state setup consistent with production validation flow):
1. Post a unit `U1` from address `A` that creates a headers_commission or witnessing input keyed by `(type, from_main_chain_index, address)`, or an asset input for an `issued_by_definer_only=false` asset, where the resulting `address` differs from the unit's own author addresses in the way permitted by `validatePaymentInputsAndOutputs` (`validation.js:2556-2567`).
2. Post a second unit `U2`, on a divergent (non-parent-including) path from `U1`, claiming the same `(type, from_main_chain_index, address)` key (or same spend-proof), with `U2`'s authors distinct from `A` and without `A` ever appearing in `U2`'s `arrAddressesWithForkedPath`.
3. When the validator processes the resulting conflict via `checkForDoublespends`, the `bIncluded` branch evaluates false, and since `objValidationState.arrAddressesWithForkedPath` for `U2` does not contain the conflicting `address`, it hits `throw Error("double spending witnessing without double spending address?")` at `validation.js:1692`, propagating to the global `uncaughtException` handler and crashing the node. [5](#0-4)

### Citations

**File:** validation.js (L1304-1343)
```javascript
	function checkSerialAddressUse(){
		var next = (objValidationState.last_ball_mci >= constants.pemCurvesFixMci || !objValidationState.hasBall && storage.getMinRetrievableMci() >= constants.pemCurvesFixMci) ? validateDefinition : checkNoPendingChangeOfDefinitionChash;
		findConflictingUnits(function(arrConflictingUnitProps){
			if (arrConflictingUnitProps.length === 0){ // no conflicting units
				// we can have 2 authors. If the 1st author gave bad sequence but the 2nd is good then don't overwrite
				objValidationState.sequence = objValidationState.sequence || 'good';
				return next();
			}
			var arrConflictingUnits = arrConflictingUnitProps.map(function(objConflictingUnitProps){ return objConflictingUnitProps.unit; });
			breadcrumbs.add("========== found conflicting units "+arrConflictingUnits+" =========");
			breadcrumbs.add("========== will accept a conflicting unit "+objUnit.unit+" =========");
			objValidationState.arrAddressesWithForkedPath.push(objAuthor.address);
			objValidationState.arrConflictingUnits = (objValidationState.arrConflictingUnits || []).concat(arrConflictingUnits);
			bNonserial = true;
			var arrUnstableConflictingUnitProps = arrConflictingUnitProps.filter(function(objConflictingUnitProps){
				return (objConflictingUnitProps.is_stable === 0);
			});
			// findConflictingUnits() already excludes final-bad rows, so any stable row left here is a real, good competitor
			var bConflictsWithStableUnits = arrConflictingUnitProps.some(function(objConflictingUnitProps){
				return (objConflictingUnitProps.is_stable === 1);
			});
			if (objValidationState.sequence !== 'final-bad') // if it were already final-bad because of 1st author, it can't become temp-bad due to 2nd author
				objValidationState.sequence = bConflictsWithStableUnits ? 'final-bad' : 'temp-bad';
			var arrUnstableConflictingUnits = arrUnstableConflictingUnitProps.map(function(objConflictingUnitProps){ return objConflictingUnitProps.unit; });
			// if we are (or already became, due to another author) final-bad, we are not a living competitor for this address either,
			// so there is no need to punish other pending units - they'll correctly resolve to 'good' on their own once stable
			if (objValidationState.sequence === 'final-bad')
				return next();
			if (arrUnstableConflictingUnits.length === 0)
				return next();
			conn.query("SELECT unit FROM units WHERE unit IN(?) AND +sequence='good'",[arrUnstableConflictingUnits],function(rows){
				if (rows.length > 0)
					objValidationState.arrUnitsGettingBadSequence = (objValidationState.arrUnitsGettingBadSequence || []).concat(rows.map(function(row){return row.unit}));
				// we don't modify the db during validation, schedule the update for the write
				objValidationState.arrAdditionalQueries.push(
				{sql: "UPDATE units SET sequence='temp-bad' WHERE unit IN(?) AND +sequence='good'", params: [arrUnstableConflictingUnits]});
				next();
				});
		});
	}
```

**File:** validation.js (L1661-1673)
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
```

**File:** validation.js (L1676-1694)
```javascript
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
