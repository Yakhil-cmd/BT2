### Title
Reachable "unreachable code" assertion in `checkForDoublespends` crashes the entire node process - (File: validation.js)

### Summary
The Apache report describes an assertion failure in `mod_proxy_http2` that an untrusted client can trigger via a specific proxy configuration, causing a full worker crash (DoS). The ocore analog is the double-spend detection helper `checkForDoublespends()` in `validation.js`, which contains multiple `throw Error(...)` "invariant" assertions inside asynchronous callbacks that run during ordinary unit validation of untrusted, network-supplied units. Because these throws occur inside `async.eachSeries` callbacks (not inside any `try/catch`), an unexpected code path reachable by a crafted unit is not converted into a normal validation error — it becomes an uncaught exception. `network.js` installs a global `process.on('uncaughtException', ...)` handler that logs, and then explicitly re-throws (`throw err; // crash the process to avoid ending up in an inconsistent state`), terminating the entire node.

### Finding Description
`validation.validate()` is the single entry point used to validate every unit received from any peer or self-posted unit (`network.js: handleJoint` → `validation.validate`). Deep inside message validation, `checkForDoublespends()` is invoked to detect conflicting spend proofs / input spends: [1](#0-0) 

Inside `checkForDoublespends`, several branches assume invariants about the conflicting DB records that were supposed to always hold, and `throw Error(...)` unconditionally if they don't, instead of returning a normal (non-fatal) validation error to the callback chain: [2](#0-1) 

Specifically:
- `throw Error("conflicting "+type+" spent from another address?")` fires whenever a conflicting spend-proof/input record's `address` is not among the current unit's author addresses.
- `throw Error("unreachable code, conflicting "+type+" in unit "+objConflictingRecord.unit)` fires on a state the author assumed could never occur.
- `throw Error("double spending "+type+" without double spending address?")` fires when `objValidationState.arrAddressesWithForkedPath` doesn't contain the conflicting address.

All of these are executed synchronously inside `async.eachSeries` callbacks that are invoked from deep within the validation pipeline of a joint that came directly from the network (`validation.js` → `validateMessage` → `validateInlinePayload`/`validateSpendProofs`/payment input validation → `checkForDoublespends`), which itself is called from `network.js`'s `handleJoint`/`handleOnlineJoint` for every posted or gossiped unit: [3](#0-2) 

Because the throw happens outside of the `try { ... } catch(e) { return callbacks.ifJointError/ifUnitError }` scaffolding that wraps most of `validate()`, it propagates up through async callbacks (`async.eachSeries`, `conn.query` callback) uncaught, and is caught only by the process-wide fatal handler: [4](#0-3) 

This mirrors the Apache bug class: a specific but reachable combination of state (equivalent to Apache's "reverse proxy for HTTP/2 backend + ProxyPreserveHost on") turns attacker-supplied input processing into an assertion/invariant violation that crashes the whole server instead of returning a controlled error.

### Impact Explanation
If an attacker can construct a unit whose spend-proof/input conflict pattern violates the author's assumed invariant (e.g., by causing the DB to return a conflicting record whose `address` differs from any author of the new unit — feasible in multi-author units, or through races/edge cases in double-spend bookkeeping across forked/non-serial branches), submitting that single unit to any full node (via P2P `joint` message or HTTP light-vendor posting) throws an uncaught exception that is deliberately re-thrown by the global handler, crashing the Node.js process. Since `validation.validate` runs for every incoming joint from every peer, a single crafted unit broadcast to the network can crash every full node that processes it — a network-wide denial of service preventing confirmation of new units, which matches the required impact bar ("a network unable to confirm new units").

### Likelihood Explanation
The likelihood depends on how easily the specific invariant-violating state (mismatched author/address on a conflicting spend record, or an unexpected non-serial/forked-path combination) can be engineered by an external, unprivileged unit poster. This requires precise crafting of a double-spend scenario across specific unit graph topologies (parallel branches, multiple authors, spend-proof addressing) so that the DB query in `checkForDoublespends` returns a row that fails the invariant check. This is plausible given that spend-proof `address` is attacker-controlled per author and multiple authors can be combined in one unit, but constructing the exact DB state (existing conflicting record with mismatched address) requires prior units to be accepted into the DAG. It is a High rather than Critical likelihood because it requires multi-step unit crafting rather than a single trivially malformed field.

### Recommendation
Convert all `throw Error(...)` invariant checks inside `checkForDoublespends` (and other async-callback assertions reachable from untrusted unit validation) into calls to the `cb`/`callback` error paths so they surface as normal `ifUnitError`/`ifJointError` results instead of uncaught exceptions. Additionally, reconsider the network-wide `process.on('uncaughtException')` policy of unconditionally re-throwing after any exception during peer-supplied joint processing — at minimum, distinguish between conditions that indicate genuine internal-state corruption (which may warrant a crash-and-restart) and conditions directly derivable from attacker-supplied unit content (which should be validation failures, not fatal errors).

### Proof of Concept
A concrete end-to-end PoC requires constructing a specific DAG state where two spend-proofs (or inputs) referencing the same output/spend_proof value exist, with the new unit's authors set such that the previously recorded conflicting spend's `address` is not among the new unit's author addresses, or where `arrAddressesWithForkedPath` does not include the conflicting address in a non-included-unit scenario. Exact reproduction requires stepping through `validateSpendProofs`/payment-input validation with a controlled multi-author/multi-branch unit set and is not fully verified against the live DB query semantics in this analysis (index/query results for `spend_proofs`/`outputs` joins were not fully traced) — this is flagged as an area needing further verification via full DAG simulation before treating it as a confirmed exploit rather than a code-review-level assertion-reachability finding.

### Citations

**File:** validation.js (L1643-1656)
```javascript
	function validateSpendProofs(cb){
		if (!("spend_proofs" in objMessage))
			return cb();
		var arrEqs = objMessage.spend_proofs.map(function(objSpendProof){
			return "spend_proof="+conn.escape(objSpendProof.spend_proof)+
				" AND address="+conn.escape(objSpendProof.address ? objSpendProof.address : objUnit.authors[0].address);
		});
		var doubleSpendIndexMySQL = conf.storage == "mysql" ? "USE INDEX(bySpendProof)" : "";
		checkForDoublespends(conn, "spend proof", 
			"SELECT address, unit, main_chain_index, sequence FROM spend_proofs "+ doubleSpendIndexMySQL+" JOIN units USING(unit) WHERE unit != ? AND sequence!='final-bad' AND ("+arrEqs.join(" OR ")+")",
			[objUnit.unit], 
			objUnit, objValidationState, function(cb2){ cb2(); }, cb);
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

**File:** network.js (L1174-1218)
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
