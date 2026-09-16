### Title
Unhandled `throw Error` on spend-proof/input double-spend checks crashes the node on a single crafted unit - (File: validation.js)

### Summary
The MySQL DML CVE describes a crash/hang of the server triggered by a privileged-but-remote client sending data that the server's DML-handling logic does not expect, causing a repeatable full-process denial of service. The closest reachable analog in `ocore--012` is `checkForDoublespends()` in [1](#0-0) , which contains several unconditional `throw Error(...)` "invariant" checks executed deep inside `conn.query`/`graph.determineIfIncludedOrEqual` async callbacks while validating a unit posted by an ordinary (unprivileged) unit poster.

### Finding Description
`checkForDoublespends` is invoked both from `validateSpendProofs` (for `spend_proofs` on any message) and from `checkInputDoubleSpend` (for payment inputs) inside `validatePaymentInputsAndOutputs`, i.e. it runs on every unit a peer/wallet posts to the network, with attacker-fully-controlled `objUnit`/`objMessage` content: [2](#0-1) 

Inside the function, when the double-spend lookup query returns rows, the code assumes as an invariant that the returned `address` will always be one of the current unit's author addresses, and any deviation from the expected "in included ancestry" / "good sequence" / "already forked" states is treated as "impossible" and is enforced with `throw Error(...)` instead of a normal validation-error callback: [3](#0-2) [4](#0-3) 

These `throw` statements execute inside asynchronous DB-callback contexts (`conn.query`, `graph.determineIfIncludedOrEqual`), not inside the synchronous `validate()` try/catch. An exception thrown there propagates as an uncaught exception on the event loop. `network.js` installs a global handler that deliberately re-throws to kill the process rather than continue in a possibly-inconsistent state: [5](#0-4) 

So any single posted/broadcast unit that reaches one of these "unreachable" branches will crash the entire node process — this is a direct full-DoS analog to the MySQL Server DML crash described in CVE-2020-14620, and it is reachable from a single unprivileged unit poster (no malicious peer/hub collusion, no p2p/catch-up trickery needed) via the normal `handleJoint` → `validation.validate` → `validateMessage`/`validatePaymentInputsAndOutputs` → `checkForDoublespends` path shown in [6](#0-5)  and [7](#0-6) .

The specific branch at line 1672 (`"conflicting "+type+" spent from another address?"`) is guarded only by the assumption that the SQL query's `WHERE` clause (built from `arrEqs`, derived from `objSpendProof.address` supplied by the attacker or defaulting to `author[0].address`) can never return a row whose `address` differs from the current unit's authors — but `spend_proof.address` is attacker-supplied per-message and is not required to equal an author address at the point this code executes, so a unit whose `spend_proofs` payload references a `spend_proof` value/`address` combination matching an existing DB row for an address that is not among the new unit's authors will hit the `throw`.

### Impact Explanation
Triggering any of these `throw Error` invariants is a full, unhandled process crash of the node (light or full), matching CVSS Availability impact "complete DOS" from the reference CVE. Because the crash is deterministic given specific but constructible input (a unit whose spend-proof/double-spend lookup unexpectedly returns a foreign address or an unexpected sequence/inclusion combination), an attacker can repeatably crash any node that processes/validates the crafted unit, i.e. every full node and any light node that receives it — a network-wide, repeatable DoS, not merely a resource-exhaustion issue.

### Likelihood Explanation
Reaching the exact combination of conditions requires the attacker to control which existing `spend_proofs`/`inputs` rows are present (e.g., by first posting a spend-proof/input themselves, then crafting a follow-up unit that queries for it with mismatched address/sequence state) and to understand the internal double-spend bookkeeping precisely. This makes the bug non-trivial to trigger blindly, but the conditions are fully expressible from the wallet/unit-composition APIs available to any ordinary unit author, without needing malicious-peer or malicious-hub cooperation, node internals access, or privileged/leaked keys.

### Recommendation
Replace the `throw Error(...)` invariant-violation branches inside `checkForDoublespends` (lines ~1672, ~1688, ~1692) with calls to `cb2(...)`/`cb(...)` that surface a normal unit-validation error, so malformed/unexpected but attacker-reachable states result in unit rejection instead of an uncaught exception that kills the process. Additionally, wrap or audit all other `throw Error(...)` "should never happen" assertions reachable from `validateMessage`/`validatePaymentInputsAndOutputs` (e.g. lines 2299, 2417-2424, 2451, 2458, 2476, 2591, 2688) for the same class of issue, and ensure they cannot be reached by externally-supplied unit/message content, or convert them to graceful validation failures.

### Proof of Concept
Not independently executable from static analysis alone — reaching the throw requires orchestrating prior on-chain state (an existing `spend_proofs`/`inputs` row) plus a follow-up unit whose message references matching `spend_proof`/output coordinates but with an address/sequence combination outside the assumed invariant. Conceptually:
1. Post/confirm a unit A from address X containing a `spend_proofs` entry `{spend_proof: S, address: X}` (or an input spending output O).
2. Craft unit B (single-authored by address Y ≠ X) whose `spend_proofs` entry uses the same `spend_proof` value `S` but explicit `address: X` (allowed since `objSpendProof.address` is attacker-supplied per spend-proof entry) so that the SQL `WHERE` in `validateSpendProofs`/`checkForDoublespends` matches the row for address X while `objUnit.authors` = [Y].
3. Broadcast/POST unit B to any node; `checkForDoublespends` finds `objConflictingRecord.address === X`, which is not in `arrAuthorAddresses = [Y]`, triggering `throw Error("conflicting spend proof spent from another address?")`, which propagates uncaught and crashes the receiving node via the `process.on('uncaughtException', …)` handler in `network.js`. [8](#0-7) [5](#0-4)

### Citations

**File:** validation.js (L418-443)
```javascript
				function(cb){
				//	profiler.stop('validation-parents');
					profiler.start();
					!objJoint.skiplist_units
						? cb()
						: validateSkiplist(conn, objJoint.skiplist_units, cb);
				},
				function(cb){
					profiler.stop('validation-skiplist');
					validateWitnesses(conn, objUnit, objValidationState, cb);
				},
				function (cb) {
					validateAATrigger(conn, objUnit, objValidationState, cb);
				},
				function (cb) {
					validateTpsFee(conn, objJoint, objValidationState, cb);
				},
				function(cb){
					profiler.start();
					validateAuthors(conn, objUnit.authors, objUnit, objValidationState, cb);
				},
				function(cb){
					profiler.stop('validation-authors');
					profiler.start();
					objUnit.content_hash ? cb() : validateMessages(conn, objUnit.messages, objUnit, objValidationState, cb);
				}
```

**File:** validation.js (L1643-1705)
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
}


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

**File:** network.js (L1149-1174)
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
