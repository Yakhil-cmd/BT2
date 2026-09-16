### Title
Attacker-triggerable uncaught `throw Error` in double-spend validation crashes the full node — ([File: validation.js])

### Summary
The Ghostscript CVE describes a dangling-pointer dereference reachable from normal, remote input that crashes the process instead of returning a controlled error. The analogous bug class in ocore is an **unhandled invariant-violation `throw`** inside `checkForDoublespends()` in `validation.js`, which is on the hot path for validating any unit received from a peer or posted by an unprivileged client. A crafted `spend_proofs` entry (or a payment/asset input) that produces a "conflicting record" whose address is not among the unit's authors makes the function `throw Error(...)` instead of calling back with a normal validation error. Because this throw happens inside an asynchronous `conn.query` callback, it cannot be caught by any surrounding `try/catch` in the call chain and becomes a Node.js `uncaughtException`. `network.js` installs a handler for `uncaughtException` that explicitly does `throw err;` again "to crash the process to avoid ending up in an inconsistent state" [1](#0-0) , so the entire node process terminates.

### Finding Description
`checkForDoublespends` is called from `validateInlinePayload`'s `validateSpendProofs` step for every unit that includes a `spend_proofs` message, using attacker-controlled `spend_proof` and `address` values built directly from the message payload: [2](#0-1) 

Inside `checkForDoublespends`, once the SQL finds any row (a record considered "conflicting"), the code assumes the conflicting record's address must always be one of `objUnit.authors`. If that assumption is violated, it throws instead of returning a normal validation error to the caller: [3](#0-2) 

There are two more unguarded `throw` statements in the same function reachable from unusual-but-attacker-influenceable graph relationships (`determineIfIncludedOrEqual` result combined with `arrAddressesWithForkedPath` state): [4](#0-3) 

This function is invoked from inside a `conn.query(...)` callback, i.e., on the Node.js event loop with no active `try/catch` frame connecting back to `validation.validate`'s caller. Any `throw` here becomes an `uncaughtException`. `network.js`'s handler for this event deliberately logs diagnostics and then re-throws, killing the node process: [1](#0-0) 

`checkForDoublespends` is also reused for payment/asset input double-spend checks elsewhere in `validation.js` (`validatePaymentInputsAndOutputs`), so the same unguarded-throw pattern is reachable via ordinary payment inputs as well as `spend_proofs`, both of which are fields any unprivileged unit author fully controls.

### Impact Explanation
Any peer or light client that can get a unit accepted into the validation pipeline (unauthenticated network input, or a unit posted through a hub/light-vendor) can potentially drive `checkForDoublespends` into one of these "should never happen" branches by crafting spend proofs/inputs whose owning address diverges from the unit's authors under specific double-spend/fork conditions. Triggering the throw path crashes the entire full node process (not just the connection/peer), which is a stronger DoS than a per-connection error: it takes the node offline until manually restarted, matching "a network unable to confirm new units" if triggered against multiple/witness nodes simultaneously, in the same way the Ghostscript CVE turns a reachable edge case into an application-wide crash rather than a contained error.

### Likelihood Explanation
The precondition (a double-spend conflicting record whose address is not among the current unit's authors, or a conflicting record that is included yet neither too-young nor "good" sequence, or a non-included conflicting record for an address not marked as forked) requires constructing a specific fork/double-spend scenario. This is more complex than a single crafted field, so it is not trivially one-shot, but it is fully reachable using only unprivileged unit posting/spend_proof or input crafting — no special privileges, hub cooperation, or node-operator access are required. This keeps it in Medium-to-High likelihood territory: it requires deliberate crafting of a double-spend graph, but no cryptographic breaks or races beyond ordinary transaction construction.

### Recommendation
- Replace the three `throw Error(...)` calls inside `checkForDoublespends` (validation.js lines 1673, 1688, 1692) with calls to `cb2(...)`/`cb(...)` returning a normal validation error (e.g., `ifUnitError`) instead of throwing.
- Audit other `conn.query(...)` callback bodies in `validation.js`, `main_chain.js`, and `storage.js` for the same pattern — an internal-invariant `throw` reachable from data supplied by an unprivileged unit author, unit poster, or private-payment sender — and convert them to callback-based error propagation so a single malformed/edge-case unit cannot bring down the whole process.
- Add regression tests that construct a double-spend/fork scenario matching each of the three throw conditions and assert the node returns a controlled validation error rather than crashing.

### Proof of Concept
1. An attacker crafts and broadcasts (or posts through a light vendor) a unit `U` that includes a `spend_proofs` message whose `spend_proof`/`address` pair matches an already-recorded `spend_proofs` row belonging to a *different* address than any of `U`'s authors (e.g. by reusing another user's previously broadcast spend proof value alongside their own unit, since `spend_proof` values are effectively attacker-supplied hash-like strings that only need to match on lookup, not be cryptographically bound at this validation stage).
2. `validateSpendProofs` builds the SQL from the attacker-supplied `spend_proof`/`address` fields and calls `checkForDoublespends(conn, "spend proof", sql, ...)` (validation.js:1651–1654).
3. The query returns the pre-existing conflicting row whose `address` is not in `arrAuthorAddresses` of `U`.
4. `checkForDoublespends` executes `throw Error("conflicting spend proof spent from another address?")` inside the `conn.query` callback (validation.js:1673), producing an uncaught exception.
5. `network.js`'s `process.on('uncaughtException', ...)` handler logs the state and re-`throw`s, terminating the entire full node process (network.js:4530–4543), taking the node offline for all peers until it is manually restarted.

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

**File:** validation.js (L1643-1655)
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
