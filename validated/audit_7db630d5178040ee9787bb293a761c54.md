Based on my investigation, I found a valid analog to this Squid CVE bug class (unhandled assertion/exception on malformed input causing daemon exit/DoS).

### Title
Unhandled `throw Error()` in `checkForDoublespends` during unit validation crashes the entire node - ([File: validation.js])

### Summary
CVE-2016-2572 is a bug class where a peer-controlled malformed input causes an internal invariant check ("assertion") to fail in a code path that isn't designed to gracefully reject bad input, resulting in an uncaught failure and daemon exit. `ocore` has a structurally identical pattern: `validation.js`'s `checkForDoublespends` throws bare JS exceptions (not callback errors) when it hits states it assumes are "impossible," and any uncaught exception is deliberately turned into a full process crash by the global handler in `network.js`.

### Finding Description
`checkForDoublespends` in `validation.js` is called during message validation of both payment inputs and definition-related doublespend checks for every incoming unit (posted by any unprivileged unit poster, or arriving from an AA trigger/private payment flow) [1](#0-0) . Inside its row-processing loop it makes hard assumptions about the returned conflicting record and throws bare `Error` objects instead of returning a validation error through the callback chain when those assumptions don't hold: [2](#0-1) [3](#0-2) 

Unlike the normal validation errors in this file, which are returned via `callback(err)` and safely propagate to `ifUnitError`/`ifJointError` (see the standard `validate()` error handling path) [4](#0-3) , these three `throw Error(...)` statements happen synchronously inside an `async.eachSeries` iterator/callback and are not wrapped in any try/catch in the call chain from `validate()` down through `validateMessage`/`validateInputs`. A thrown error here escapes the `async` control flow and becomes an uncaught exception at the event-loop level.

`network.js` explicitly converts any uncaught exception into a fatal process crash: [5](#0-4) 
This is functionally the same failure mode as the Squid bug: a response/unit-parsing edge case that the code treats as "should never happen" turns into an unhandled fault that kills the whole daemon, rather than being rejected as an ordinary invalid unit.

### Impact Explanation
Because `handleJoint` in `network.js` invokes `validation.validate` for every joint received from peers or posted directly by a light client/wallet [6](#0-5) , and the global `uncaughtException` handler re-throws to crash the process [5](#0-4) , a single crafted unit that reaches one of these invariant-violation branches in `checkForDoublespends` can take down a full node (hub or normal peer), matching the "network unable to confirm new units" / DoS impact class defined in scope.

### Likelihood Explanation
Reaching the exact race/ordering condition required (a conflicting spend record whose `address` doesn't match the crafted unit's own author addresses, or an "included" conflicting record whose sequence/mci state falls outside the two handled branches) requires careful setup of a prior conflicting unit plus a new unit referencing it in a specific parent/inclusion configuration. This is plausible for a sophisticated unprivileged unit poster to engineer (author addresses and parent selection are fully attacker-controlled), but it is not a trivial single-field malformation — it requires orchestrating a genuine double-spend scenario that lands on an "impossible" branch, so likelihood is moderate rather than trivial.

### Recommendation
Replace the three `throw Error(...)` calls in `checkForDoublespends` (validation.js lines 1673, 1688-1692) with `return cb2(err)`/`return cb(err)` style validation errors (as used everywhere else in this function), so any unexpected state is rejected as an ordinary unit/joint validation error instead of crashing the process. Additionally, consider hardening the global `uncaughtException` handler in `network.js` to avoid an unconditional daemon-wide crash triggered by a single malformed/unexpected unit from an untrusted peer.

### Proof of Concept
Conceptual (I cannot fully verify the exact DB state needed to hit the unreachable branches without running the code): craft two conflicting units spending the same input from address A, arranged so that the second unit's `parent_units` include the first unit indirectly, but the DB-returned conflicting record's `address` differs from any of the new unit's `objUnit.authors[*].address` (e.g., via a shared/multi-sig address scenario), or so that the conflicting record's `main_chain_index`/`sequence` falls outside the "too young" and "good sequence" cases. This drives `checkForDoublespends` into the `throw Error("conflicting "+type+" spent from another address?")` or `throw Error("unreachable code, conflicting "+type+" in unit "+objConflictingRecord.unit)` branches at [7](#0-6) , producing an uncaught exception that the handler at [5](#0-4)  turns into a process crash.

### Citations

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

**File:** network.js (L1149-1189)
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
