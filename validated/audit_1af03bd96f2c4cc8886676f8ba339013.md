### Title
Attacker-triggerable `throw Error` in private-asset double-spend validation crashes every full node that processes a crafted unit, causing repeated network-wide crash loops - ([File: validation.js])

### Summary
The Directus report is a CWE-770 "resource not released on error" bug: a malformed request causes an internal handler to throw before the AWS SDK response stream is consumed, and because that failure path is repeatable at scale, it exhausts the finite socket pool, making all future requests (including from privileged users) fail. The reachable analog in `ocore` is an unhandled, synchronous `throw Error` inside `checkForDoublespends`'s `onDone` callback in `validation.js`, invoked while a unit (which can be a base or private-asset payment posted by any unprivileged peer/wallet) is being validated. Because ocore installs a top-level `uncaughtException` handler in `network.js` that deliberately re-throws to crash the process, this reachable throw becomes a remotely triggerable, repeatable crash of every full node (and the exchange/hub operator's own node) that processes the crafted unit — a network-wide "unable to confirm new units" denial of service, analogous in effect to the exhaustion of the finite resource pool in the original report.

### Finding Description
`checkForDoublespends` in `validation.js` is called from `validatePaymentInputsAndOutputs` when validating a private-asset payment's `transfer`/`issue` inputs: [1](#0-0) 

Its `onDone` callback contains:
```
function onDone(err){
    if (err && objAsset && objAsset.is_private && !conf.bLight)
        throw Error("spend proof didn't help: "+err);
    cb2(err);
}
``` [2](#0-1) 

This same pattern also fires from `checkForDoublespends` itself for other kinds of conflicting records, via the invariant-assumption `throw Error` statements inside its `async.eachSeries` iteration (e.g. "conflicting spend proof spent from another address?", "unreachable code, conflicting ... in unit", "double spending ... without double spending address?"): [3](#0-2) 

These `throw` statements execute inside asynchronous DB-query callbacks that are several frames deep in `async.series`/`async.eachSeries` chains started from `validation.validate()`, which itself runs under a global `mutex.lock(arrAuthorAddresses, ...)` and a live DB transaction (`BEGIN`) taken from the connection pool: [4](#0-3) 

Because the throw happens inside an I/O callback, no calling `try/catch` in the validation pipeline can intercept it — it propagates to Node's event loop as an uncaught exception. `network.js` explicitly turns this into a full process crash:
```
process.on('uncaughtException', (err) => {
    console.log('Uncaught exception:', err);
    ...
    throw err; // crash the process to avoid ending up in an inconsistent state
});
``` [5](#0-4) 

This is reachable by any unprivileged unit poster: a normal peer can post (or broadcast) a private-asset payment whose input's recomputed spend proof does not match the one recorded for the same slot (e.g. a payment on a locally forked/competing chain, or a maliciously crafted conflicting private-asset spend), causing `checkForDoublespends`'s conflict-resolution logic to fail its "un-uniquify" retry and fall into `if (err && objAsset.is_private && !conf.bLight) throw ...`. The joint enters via `network.js`'s `handleJoint`/`handleOnlineJoint`/`handlePostedJoint` flow, i.e., from any connected peer or from the node's own wallet accepting a peer-forwarded private payment: [6](#0-5) 

Since the same unit will be re-broadcast/forwarded to peers and will be re-validated on every full node that receives it (and again on restart via `rerequestLostJoints`/`readDependentJointsThatAreReady`), a single crafted unit can crash many independent nodes repeatedly (crash → restart → re-encounter the same unhandled/unsaved unit → crash again), which is functionally equivalent to the "assets become unavailable to everyone" outcome in the Directus report, but achieved via forced restart loops rather than socket-pool exhaustion.

### Impact Explanation
This is a network-wide availability failure: any full node that receives the crafted private-asset unit is forced to crash via the intentional `throw err` in the `uncaughtException` handler, and because unresolved/unhandled joints are retried automatically after restart (`rerequestLostJoints`, `readDependentJointsThatAreReady`), an attacker can create a persistent crash loop that prevents the affected node(s) from confirming any further units while they are down/restarting. Because it's triggerable by ordinary peer traffic (posting or relaying a joint), it can be used to selectively attack witnesses, hubs, or exchange nodes, degrading network liveness — matching the "network unable to confirm new units" bar for Medium/High severity DoS in the validation rules.

### Likelihood Explanation
Reaching the vulnerable branch requires the unit to already pass many prior checks (well-formed private-asset payment, valid inputs referencing a real previous output/spend proof, valid signatures) and requires a specific mismatch condition on the double-spend resolution path (`checkForDoublespends`'s "accept doublespend" retry still returns an error after the private_write "ununique" step). This is a non-trivial but realistic scenario for private/divisible or indivisible assets under fork/reorg conditions or intentionally malformed spend-proof chains constructed by the attacker (since private payment payloads and spend proofs are attacker-supplied JSON structures that are only partially cross-checked against the DB). Because the throw is inside a general-purpose validation function reachable for every unit that carries a private-asset payment message, and ocore's design explicitly crashes on any uncaught exception, the likelihood of an attacker being able to construct at least one triggering unit is considered realistic, though crafting the exact double-spend/spend-proof condition requires some care and is not as trivially reproducible as the one-line malformed HTTP query in the original report.

### Recommendation
- Replace the `throw Error("spend proof didn't help: "+err)` in `validation.js`'s `checkForDoublespends`/`onDone` handling (and the other invariant `throw` statements inside `checkForDoublespends`) with proper `cb(err)`/`callback(err)` propagation so that malformed or conflicting but attacker-controlled unit content results in `ifUnitError`/`ifJointError` rejection instead of a process crash.
- Audit all `throw Error(...)` statements reached from `validation.validate()`'s call graph (used for "should never happen" invariants) and distinguish genuinely impossible internal-consistency violations from conditions that are reachable with attacker-supplied unit/private-payment data; convert the latter into normal validation-error returns.
- Ensure the DB connection and mutex lock acquired in `validate()` are released before any error terminates validation, so that even genuine internal-invariant crashes do not leave shared resources (mutex on `arrAuthorAddresses`, pooled DB connections) stuck if the `uncaughtException` handler's crash-and-restart semantics are ever changed.
- Consider adding regression tests that post private-asset payments with intentionally mismatched/conflicting spend proofs to confirm they are rejected via `ifUnitError`, not via process crash.

### Proof of Concept
Not independently reproducible from the indexed code alone; a full PoC would need to construct a private-asset payment (using the `is_private` asset flow in `divisible_asset.js`/`indivisible_asset.js`) whose input's spend proof conflicts with a previously accepted spend proof for the same output/serial number in a way that survives `checkForDoublespends`'s "ununique the conflicts" retry (`mutex.lock(["private_write"], ...)`) but still returns an error, and then submit that joint via `handlePostedJoint`/`handleOnlineJoint`. This would need to be built and tested against a running `ocore`-based full node (relay) to confirm the `throw Error("spend proof didn't help: ...")` path fires and crashes the process via the `uncaughtException` handler in `network.js`. Given the scope of this analysis (static code review only), this PoC step could not be executed; a Devin session with the actual repository and a runnable test harness (as used in `test/aa.test.js`, `test/formula.test.js`) would be needed to confirm the exact private-asset construction that reaches this branch.

### Citations

**File:** validation.js (L357-380)
```javascript
	mutex.lock(arrAuthorAddresses, function(unlock){
		
		var conn = null;
		var commit_fn = null;
		var start_time = null;

		async.series(
			[
				function(cb){
					if (external_conn) {
						conn = external_conn;
						start_time = Date.now();
						commit_fn = function (cb2) { cb2(); };
						return cb();
					}
					db.takeConnectionFromPool(function(new_conn){
						conn = new_conn;
						start_time = Date.now();
						commit_fn = function (cb2) {
							conn.query(objValidationState.bAdvancedLastStableMci ? "COMMIT" : "ROLLBACK", function () { cb2(); });
						};
						conn.query("BEGIN", function(){cb();});
					});
				},
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

**File:** validation.js (L2270-2304)
```javascript
				checkForDoublespends(
					conn, "divisible input", 
					doubleSpendQuery, doubleSpendVars, 
					objUnit, objValidationState, 
					function acceptDoublespends(cb3){
						console.log("--- accepting doublespend on unit "+objUnit.unit);
						var sql = "UPDATE inputs SET is_unique=NULL WHERE "+doubleSpendWhere+
							" AND (SELECT is_stable FROM units WHERE units.unit=inputs.unit)=0";
						if (!(objAsset && objAsset.is_private)){
							objValidationState.arrAdditionalQueries.push({sql: sql, params: doubleSpendVars});
							objValidationState.arrDoubleSpendInputs.push({message_index: message_index, input_index: input_index});
							return cb3();
						}
						mutex.lock(["private_write"], function(unlock){
							console.log("--- will ununique the conflicts of unit "+objUnit.unit);
							conn.query(
								sql, 
								doubleSpendVars, 
								function(){
									console.log("--- ununique done unit "+objUnit.unit);
									objValidationState.arrDoubleSpendInputs.push({message_index: message_index, input_index: input_index});
									unlock();
									cb3();
								}
							);
						});
					}, 
					function onDone(err){
						if (err && objAsset && objAsset.is_private && !conf.bLight)
							throw Error("spend proof didn't help: "+err);
					//	if (objAsset)
					//		profiler2.stop('checkInputDoubleSpend');
						cb2(err);
					}
				);
```

**File:** network.js (L1149-1218)
```javascript
function handleJoint(ws, objJoint, bSaved, bPosted, callbacks){
	if ('aa' in objJoint)
		return callbacks.ifJointError("AA unit cannot be broadcast");
	var unit = objJoint.unit.unit;
	if (typeof unit !== 'string')
		return callbacks.ifJointError("invalid unit");
	const version = objJoint.unit.version;
	if (typeof version !== 'string')
		return callbacks.ifJointError("invalid version");
	const fVersion = parseFloat(version);
	if (!(fVersion >= constants.fVersion4 || objJoint.ball)) // covers NaN too
		return callbacks.ifTransientError("version is too old");
	if (assocUnitsInWork[unit])
		return callbacks.ifUnitInWork();
	assocUnitsInWork[unit] = true;
	
	var validate = function(){
		mutex.lock(['handleJoint'], function(unlock){
			if (ws && !conf.bLight)
				currentJointHost = ws.host;
			// clear host only if validation completed with any result, otherwise it crashed and we keep it for a while to avoid DoS from the same peer
			const clearHost = () => {
				if (ws && !conf.bLight)
					currentJointHost = null;
			};
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
				ifJointError: function(error){
					clearHost();
					callbacks.ifJointError(error);
				//	throw Error(error);
					joint_storage.saveKnownBadJoint(objJoint, error, function(){
						delete assocUnitsInWork[unit];
					});
					unlock();
					if (ws)
						writeEvent('invalid', ws.host);
					if (objJoint.unsigned)
						eventBus.emit("validated-"+unit, false);
				},
				ifTransientError: function(error){
				//	throw Error(error);
					console.log("############################## transient error "+error);
					clearHost();
					callbacks.ifTransientError ? callbacks.ifTransientError(error) : callbacks.ifUnitError(error);
					process.nextTick(unlock);
					joint_storage.removeUnhandledJointAndDependencies(unit, function(){
					//	if (objJoint.ball)
					//		db.query("DELETE FROM hash_tree_balls WHERE ball=? AND unit=?", [objJoint.ball, objJoint.unit.unit]);
						delete assocUnitsInWork[unit];
					});
					if (error.includes("last ball just advanced"))
						setTimeout(rerequestLostJoints, 10 * 1000, true);
					if (error === "possible AA" && bCatchingUp)
						tryToAdvanceStabilityPointForCatchupAATrigger(objJoint);
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
