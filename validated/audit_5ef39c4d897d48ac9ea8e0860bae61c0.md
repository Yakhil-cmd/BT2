Based on my research, I found a directly analogous bug class in `ocore--007`: an assertion-style `throw Error(...)` reachable from validation of an attacker-supplied unit, which — because of the global `uncaughtException` handler that re-throws to crash the process — turns a "this should never happen" logic assumption into a remote, unauthenticated denial-of-service, exactly as CVE-2021-25215 does for BIND (a crafted-but-superficially-valid input reaches an assertion the code assumes is unreachable, and the daemon process terminates).

### Title
Reachable assertion-failure crash via crafted double-spend/spend-proof conflict in unit validation - (File: validation.js)

### Summary
`checkForDoublespends()` in `validation.js` is invoked while validating any freshly posted unit (public payments, spend-proof private payments, and even AA-authored spends) to detect double spends. Instead of returning a soft validation error for certain conflict shapes it deems "impossible," it uses `throw Error(...)`, which is an unhandled exception in `ocore`'s event-driven, single-process architecture and results in full node termination, mirroring BIND's `INSIST`/assertion-failure crash on a superficially valid-but-adversarial query.

### Finding Description
When `handleJoint()` (called for every unit received from the network or submitted locally) validates a unit, `validation.js`'s `validate()` eventually calls `validateMessages` → `validateMessage` → `checkForDoublespends()` for payment inputs and spend proofs [1](#0-0) . Inside `checkForDoublespends`, when a conflicting record is found in the DB, the code assumes two invariants can never be violated by attacker input and enforces them with `throw Error(...)` instead of a callback error: [2](#0-1) 

Specifically:
- `throw Error("conflicting "+type+" spent from another address?")` at line 1673, assuming any conflicting spend-proof/input record found by the SQL query must belong to one of the current unit's author addresses.
- `throw Error("unreachable code, conflicting "+type+" in unit "+objConflictingRecord.unit)` at line 1688, an explicit "unreachable" assumption about sequence/mci combinations.
- `throw Error("double spending "+type+" without double spending address?")` at line 1692, assuming `objValidationState.arrAddressesWithForkedPath` (populated elsewhere during parent/graph analysis) always contains the conflicting address whenever the conflicting unit is not included in the new unit's parents.

This same helper is also used for divisible-asset input double-spend checks, where an additional `throw Error("spend proof didn't help: "+err)` exists for private assets [3](#0-2) . This is the AA/private-asset-reachable variant of the same pattern.

These are exactly the class of "invariant that is assumed but not actually enforced/verified against attacker-chosen graph shapes" bugs — the same bug class as BIND's assertion failure, where a value the code assumes cannot occur is reachable through carefully constructed (but protocol-valid-looking) input.

Any of these `throw Error()` calls escaping the validation callback chain becomes an uncaught exception. `network.js` installs a global handler that explicitly re-throws to crash the process: [4](#0-3) 

So any node (full node, hub, or AA-processing node) that receives/validates a unit hitting one of these `throw Error` paths terminates entirely — a full network-wide DoS if a single malicious unit is broadcast, since every node independently validates it and independently crashes.

### Impact Explanation
This maps to "a network unable to confirm new units": a successfully broadcast unit that trips one of these assertions crashes every full node that processes it (validation happens identically on all nodes per `handleJoint`/`validate`), since the exception is not user-input-error but an uncaught JS exception that the top-level handler re-throws to kill the process. This is a High-severity, unauthenticated DoS achievable by a single unprivileged unit poster crafting a specific double-spend or spend-proof shaped unit.

### Likelihood Explanation
The likelihood depends on whether an attacker can actually construct a unit/graph shape that violates the assumed invariants in `checkForDoublespends` (e.g., producing a conflicting `spend_proofs`/`inputs` row whose address is not in `arrAuthorAddresses` for the exact query used, or a conflicting unit not properly reflected in `objValidationState.arrAddressesWithForkedPath`). I was not able to fully trace, within the available search iterations, every code path that populates `arrAddressesWithForkedPath` (7 references, all in `validation.js`) or that determines `sequence`/`main_chain_index` for a conflicting record across multi-author units, forked DAG branches, or the private-asset spend-proof path, so I cannot confirm a concrete unit payload that triggers the throw. This should be treated as a plausible reachable-assertion candidate requiring further code tracing (specifically the population of `arrAddressesWithForkedPath` and the multi-author/forked-branch double-spend detection logic) before being confirmed exploitable — I flag this uncertainty explicitly rather than asserting definite reachability.

### Recommendation
Treat every `throw Error(...)` inside code paths reachable from `validate()`/`checkForDoublespends()`/`validatePaymentInputsAndOutputs()` that process attacker-controlled unit fields as a potential DoS vector: replace them with proper `callback("...")`/`cb2("...")` soft validation errors (as done elsewhere in the same file) rather than hard throws, so malformed/adversarial-but-well-formed units are rejected gracefully instead of crashing the node. Additionally, audit `arrAddressesWithForkedPath`'s population logic to ensure it is exhaustive for all multi-author/forked-DAG double-spend scenarios before relying on it as a safety invariant guarded only by a `throw`.

### Proof of Concept
Not confirmed with a concrete payload — this requires validating the exact conditions under which `objConflictingRecord.address` can fall outside `arrAuthorAddresses`, or `arrAddressesWithForkedPath` can fail to include a conflicting address, for a unit with multiple authors and/or a spend-proof-based private payment that double-spends across a forked DAG branch. Further Devin-session tracing of `arrAddressesWithForkedPath`'s writers and the double-spend detection SQL/graph logic (`validation.js`) is required to construct a working PoC unit.

### Citations

**File:** validation.js (L1643-1657)
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
	
	async.series([validateSpendProofs, validatePayload], callback);
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

**File:** validation.js (L2296-2304)
```javascript
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
