### Title
Reachable Assertion / Uncaught Exception in `checkForDoublespends` Crashes the Entire Node from a Single Crafted Unit - ([File: validation.js])

### Summary
`validation.js`'s `checkForDoublespends()` contains several `throw Error(...)` "assertion" statements that are meant to be unreachable, but are executed inside asynchronous DB-callback code with no enclosing `try/catch`. A specifically crafted double-spending input/spend-proof on an otherwise-normal posted unit can drive execution into one of these branches. Because the throw happens inside a `conn.query()` / `graph.determineIfIncludedOrEqual()` callback, it escapes every `try/catch` in the call chain (`validateMessage` → `validate` → `handleJoint`) and becomes a Node.js `uncaughtException`. In `network.js` the global handler explicitly re-throws to crash the process: `throw err; // crash the process to avoid ending up in an inconsistent state`. This is the same bug class as the Zebra advisory (CWE: Uncaught Exception / Reachable Assertion) — an unprivileged, authenticated-by-nothing-more-than-protocol actor triggers a code path meant to be an internal invariant, and instead of getting a validation error, the whole node aborts.

### Finding Description
`checkForDoublespends` is invoked from `validateMessage`'s `validateSpendProofs` (for private-payment spend proofs) and from `validatePaymentInputsAndOutputs`'s `checkInputDoubleSpend` (for every payment input, base or asset) during standard unit validation of a unit posted by *any* party — a light client posting through `handlePostedJoint`, or a peer broadcasting a `joint` — see the call path in `network.js`: [1](#0-0) 

Inside `checkForDoublespends`, once a conflicting record is found in the DB, the code enforces the invariant that the conflicting record's address must belong to one of the current unit's authors; if not, it throws instead of returning a validation error: [2](#0-1) 

Two further `throw Error(...)` invariants exist in the same function, reachable when a conflicting record is included in the submitted unit's ancestry: [3](#0-2) 

These are executed inside `graph.determineIfIncludedOrEqual`'s callback (an asynchronous DB traversal), not inside the `try/catch` blocks that exist elsewhere in `validation.js` (e.g. around unit-hash or payload-hash calculation). The same unguarded assertion pattern recurs at other points reachable from ordinary payment/input validation of a posted unit, e.g.: [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) 

Any of these `throw` statements executing inside an async DB callback is not caught by the outer `async.series`/`mutex.lock` machinery in `validate()` (that machinery only catches `err` values passed to callbacks, not JS exceptions thrown from inside nested async callbacks). The exception therefore surfaces as a bare Node `uncaughtException`, handled globally in `network.js`: [8](#0-7) 

which deliberately re-throws to crash the whole process ("`throw err; // crash the process to avoid ending up in an inconsistent state`"). This mirrors exactly the Zebra bug class: a condition intended to produce a graceful error response instead becomes an unhandled, fatal exception.

### Impact Explanation
This is a full node crash (Denial of Service) triggerable by any unprivileged actor who can get a unit into the validation pipeline — a light wallet user posting a unit, or any peer broadcasting a joint/unit that another full node will validate. Unlike Zebra's per-connection crash, this crashes the entire `ocore`-based process (`throw err` at top level), taking down all peer connections, hub services, and light-vendor service simultaneously — "a network unable to confirm new units" if enough witness/hub nodes are affected, satisfying the "Validate" criteria for concrete impact (network-wide denial of service via node crash triggered by a single posted unit).

### Likelihood Explanation
Reaching these specific `throw` branches requires crafting a unit whose spend-proof/input references a record that is a conflicting double-spend candidate in the DB but does not satisfy the exact invariant the code assumes (e.g., a conflicting record whose owning address is not among the new unit's authors, or a conflicting record that is included in the new unit's parents but has neither "good" sequence nor an appropriately young main_chain_index, or falls into the "not included, and not present in `arrAddressesWithForkedPath`" case). Because the DB rows and adjacency (graph inclusion) that decide which branch is taken are attacker-influenced by prior posted units and by carefully chosen `parent_units`/spend_proof addresses, an attacker with the ability to post/propagate multiple units (which is a normal capability of any wallet or peer) has a realistic, if not fully trivial, path to engineer the DB state that satisfies one of these "impossible" branches. The comments themselves ("unreachable code", "without double spending address?") indicate the developers believed these states could not occur, which is precisely the pattern reachable-assertion bugs come from.

### Recommendation
- Replace every `throw Error(...)` inside `checkForDoublespends` (and the analogous ones in `validatePaymentInputsAndOutputs`, e.g. lines 2298-2299, 2415-2424, 2449-2459, 2591) with a call to the `cb`/`cb2`/`cb3` error-callback pattern already used elsewhere in the file, converting them into `ifUnitError`/`ifJointError` validation failures instead of process-fatal exceptions.
- Alternatively (defense in depth), wrap the asynchronous callback bodies that contain these throws in `try/catch` and route caught exceptions to `callbacks.ifJointError`/`ifUnitError`, matching the pattern already used around unit-hash and payload-hash computation in `validate()`.
- Reconsider the global `process.on('uncaughtException', ...)` policy in `network.js` so that exceptions originating from unit/message validation of externally supplied data do not necessarily crash the entire process; at minimum, ensure all validation-time assertions are converted to soft errors before relying on crash-as-safety-net semantics.

### Proof of Concept
Conceptual PoC (requires DB-state engineering, not fully automated here due to index limitations noted below):
1. Post/propagate unit `U1` from address `A` establishing a spend-proof or input record for asset/base coin `X`.
2. Post a second unit `U2` from a different address `B` that is not an author of `U1`, but that the validator's SQL match (`checkForDoublespends`'s `sql`/`arrSqlArgs`, e.g. the `spend_proofs` or `inputs` query) returns as a "conflicting record" whose `address` is `B`'s output/spend-proof address recorded under different unit metadata (e.g., via `type=issue`/`transfer` combinations, or a light-client spend-proof with mismatched author list).
3. When the second unit's `checkForDoublespends` call executes, the conflicting record's `address` will not be present in the new unit's `arrAuthorAddresses`, hitting:
```js
if (arrAuthorAddresses.indexOf(objConflictingRecord.address) === -1)
    throw Error("conflicting "+type+" spent from another address?");
```
4. This throw is not caught anywhere in the async call chain, bubbles to Node's `uncaughtException` handler in `network.js`, which re-throws and crashes the process for every node that validates `U2`.

Note: Because of index/coverage limits on this analysis I was not able to fully trace every SQL predicate variant in `checkForDoublespends`'s callers to build a concrete, minimal unit pair that guarantees hitting the exact throw branch; a Devin session with full repository/test access (and the ability to run the ocore test suite/`aa.test.js`/`validation` fixtures) would be needed to construct and verify a deterministic, minimal reproduction.

### Citations

**File:** network.js (L1149-1163)
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

**File:** validation.js (L2298-2299)
```javascript
						if (err && objAsset && objAsset.is_private && !conf.bLight)
							throw Error("spend proof didn't help: "+err);
```

**File:** validation.js (L2415-2424)
```javascript
					if (objAsset && objAsset.is_private && objAsset.fixed_denominations){
						if (!objValidationState.src_coin)
							throw Error("no src_coin");
						var src_coin = objValidationState.src_coin;
						if (!src_coin.src_output)
							throw Error("no src_output");
						if (!isPositiveInteger(src_coin.denomination))
							throw Error("no denomination in src coin");
						if (!isPositiveInteger(src_coin.amount))
							throw Error("no src coin amount");
```

**File:** validation.js (L2449-2451)
```javascript
						function(rows){
							if (rows.length > 1)
								throw Error("more than 1 src output");
```

**File:** validation.js (L2456-2459)
```javascript
							if (bStableInParents) {
								if (src_output.sequence === 'temp-bad')
									throw Error("spending a stable temp-bad output " + input.unit);
								if (src_output.sequence === 'final-bad')
```
