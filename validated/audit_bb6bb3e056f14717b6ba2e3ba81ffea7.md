### Title
Reachable `throw Error` (assertion-style crash) in double-spend detection - (File: validation.js)

### Summary
`checkForDoublespends()` in `validation.js` contains three internal-invariant assertions implemented as unconditional `throw Error(...)` instead of returning a normal validation error to the caller. Because these throws happen inside an `async.eachSeries` callback invoked from database-driven, attacker-influenced double-spend detection logic, a unit crafted to hit one of these "should never happen" branches will cause an uncaught exception that propagates out of the validation pipeline. [1](#0-0) 

### Finding Description
`checkForDoublespends()` queries the DB for other records that conflict with inputs/spend-proofs of the unit being validated, then iterates the conflicting rows and asserts three conditions that the author believed to be invariants:

- `if (arrAuthorAddresses.indexOf(objConflictingRecord.address) === -1) throw Error("conflicting "+type+" spent from another address?");`
- `throw Error("unreachable code, conflicting "+type+" in unit "+objConflictingRecord.unit);` when a conflicting record is included in parents, is stable, and has an unrecognized sequence value.
- `if (objValidationState.arrAddressesWithForkedPath && objValidationState.arrAddressesWithForkedPath.indexOf(objConflictingRecord.address) === -1) throw Error("double spending "+type+" without double spending address?");` [2](#0-1) 

This mirrors the JasPer `calcstepsizes()` bug class: an internal function encodes an assumption about the shape of validated input as a hard `assert`/`throw` rather than a graceful error path, and that assumption can be broken by attacker-controlled data (crafted double-spend/spend-proof/asset-issue combinations) reaching this code from a normally-processed, unprivileged unit submission. `validate()` (the top-level entry point reached from any posted unit, `network.js` `handleJoint`, private-payment validation, and AA trigger validation) calls into message/payload validation, which in turn invokes `checkForDoublespends()` for payment inputs, spend proofs, and asset issue conditions, all of which are reachable by an ordinary, unprivileged unit author. [3](#0-2) [4](#0-3) 

Unlike other error paths in this file that call `callback(err)` and are converted into normal `ifUnitError`/`ifJointError` results, an uncaught `throw` inside this async-callback context is not caught by `validate()`'s `async.series` error handling and will bubble up as an uncaught exception. `network.js` registers a global `uncaughtException` handler that explicitly re-throws to crash the whole node process to avoid an inconsistent state: [5](#0-4) 

### Impact Explanation
If an attacker can construct a unit (payment input, spend proof, or private/indivisible-asset payload) whose conflicting-record pattern violates one of these three hard-coded invariants, every full node that processes/relays the unit will hit the `throw`, causing an unhandled exception that the node's own `uncaughtException` handler converts into a forced process crash. This is a network-wide denial-of-service: nodes are unable to validate or confirm new units while repeatedly crashing/restarting on the same poisoned unit if it keeps propagating (a full node cannot silently reject and move on, since the process itself terminates).

### Likelihood Explanation
The likelihood cannot be judged as certain from static review alone: the three assertions are guarded by preceding checks (address membership, `main_chain_index`, `sequence`, and `arrAddressesWithForkedPath`) that are intended to make them unreachable in normal operation. Exploitability depends on finding a concrete double-spend / spend-proof / private-asset combination (e.g., multi-authored units, forked-path bookkeeping edge cases, or private fixed-denomination asset chains) that defeats these guards — analogous to how the JasPer assertion was only reachable via a very specific malformed JPEG 2000 stream. This would need to be confirmed with a concrete crafted-unit proof of concept in a runtime/test environment, which is outside the scope of static code search.

### Recommendation
Replace the three `throw Error(...)` statements in `checkForDoublespends()` (validation.js lines 1673, 1688, 1692) with calls to `cb2(err)`/`callback(err)` so that an unexpected invariant violation is treated as a normal unit validation failure (`ifUnitError`) instead of crashing the process. More generally, audit all `throw Error(...)` calls reachable from `validate()`, `validateAuthor()`, `validatePaymentInputsAndOutputs()`, and AA trigger/response validation paths (e.g., lines 2417, 2420, 2422, 2424, 2451, 2458 also throw on data assumptions) and convert genuinely input-dependent assertions into recoverable validation errors, reserving `throw` only for conditions that are truly impossible to reach from network-supplied data.

### Proof of Concept
Not constructed — a concrete PoC requires crafting a specific double-spend/spend-proof/private-asset unit sequence that defeats the preceding guard conditions in `checkForDoublespends()`, which requires interactive testing against a running ocore node/test harness rather than static analysis.

### Citations

**File:** validation.js (L118-138)
```javascript
function validate(objJoint, callbacks, external_conn) {
	
	var objUnit = objJoint.unit;
	if (typeof objUnit !== "object" || objUnit === null)
		throw Error("no unit object");
	if (!objUnit.unit)
		throw Error("no unit");
	
	console.log("\nvalidating joint identified by unit "+objJoint.unit.unit);
	
	if (!isStringOfLength(objUnit.unit, constants.HASH_LENGTH))
		return callbacks.ifJointError("wrong unit length");
	
	try{
		// UnitError is linked to objUnit.unit, so we need to ensure objUnit.unit is true before we throw any UnitErrors
		if (objectHash.getUnitHash(objUnit) !== objUnit.unit)
			return callbacks.ifJointError("wrong unit hash: "+objectHash.getUnitHash(objUnit)+" != "+objUnit.unit);
	}
	catch(e){
		return callbacks.ifJointError("failed to calc unit hash: "+e);
	}
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

**File:** network.js (L1174-1189)
```javascript
			validation.validate(objJoint, {
				ifUnitError: function(error){
					console.log(objJoint.unit.unit+" validation failed: "+error);
					clearHost();
					callbacks.ifUnitError(error);
					if (constants.bDevnet)
						throw Error(error);
					purgeJointAndDependenciesAndNotifyPeers(objJoint, error, function(){
						delete assocUnitsInWork[unit];
					});
					unlock();
					if (ws && error !== 'authentifier verification failed' && !error.match(/bad merkle proof at path/) && !bPosted)
						writeEvent('invalid', ws.host);
					if (objJoint.unsigned)
						eventBus.emit("validated-"+unit, false);
				},
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
