### Title
Attacker-Controlled `aa` Flag in a Posted Joint Causes Uncaught Exception and Node Crash - ([File: validation.js])

### Summary
`validation.validate()` trusts the `objJoint.aa` field taken directly from the joint object supplied by the caller, without confirming that the joint actually came from the trusted internal AA composer rather than from the network/an unprivileged unit poster. Once `bAA` is set, multiple downstream code paths perform hard, synchronous `throw Error(...)` instead of returning an error through the callback chain. Any synchronous throw inside these `async.series`/`async.eachSeries` step functions propagates as an uncaught exception, which is caught only by the top-level `process.on('uncaughtException', ...)` handler in `network.js`, which deliberately **re-throws to crash the process** ("crash the process to avoid ending up in an inconsistent state").

### Finding Description
In `validate()`: [1](#0-0) 
`bAA` is derived straight from `objJoint.aa`/`objJoint.aa_mci`, which are then deleted from the object *before* the "unknown fields in unit-joint" checks run: [2](#0-1) 
Because the deletion happens first, an externally supplied `"aa": true` field is silently accepted and stripped, and the internal-only `objValidationState.bAA` flag becomes true for a joint that was never produced by the trusted `aa_composer`. Note this is analogous to the CVE's core defect class: a crafted/attacker-influenced field silently subverts an internal trust boundary and reaches an unguarded code path that terminates abnormally.

Multiple `bAA`-guarded branches use `throw Error(...)` (synchronous throw, not `callback(err)`), assuming they can never be reached from network input because only the internal AA composer sets `bAA`:
- `validateParents`: `if (objValidationState.bAA && objUnit.parent_units.length > 2) throw Error("AA unit with more than 2 parents");` [3](#0-2) 
- `validateAuthors`: `if (objValidationState.bAA && arrAuthors.length !== 1) throw Error("AA unit with multiple authors");` [4](#0-3) 
- `validateAuthor`: `if (objValidationState.bAA && hasFieldsExcept(objAuthor, ["address"])) throw Error("unknown fields in AA author");` [5](#0-4) 
- `validateAuthor` (AA definition lookup path): `if (!arrDefinition) throw Error("AA definition not found " + objAuthor.address);` [6](#0-5) 

Any of these is trivially satisfied by a crafted joint: e.g. a normally-formed unit with 3+ `parent_units` (a legal condition for a regular unit) plus the extra top-level `"aa": true` field. This throw occurs synchronously inside the `async.series` iterator used by `validate()`: [7](#0-6) 
`async`/`async.series` do not wrap synchronous exceptions thrown by iterator functions in a try/catch that routes them back into the `function(err){...}` completion handler; the exception instead propagates up the call stack as an uncaught exception.

The top-level handler explicitly crashes the process on any uncaught exception: [8](#0-7) 

This is reachable through `handlePostedJoint`, which forwards attacker/light-client-controlled `objJoint` objects straight into `handleJoint`/`validate()`: [9](#0-8) 

### Impact Explanation
Any unprivileged unit poster (including a light client posting a joint to a full node/hub, or a peer sending a "joint" message) can craft a syntactically valid-looking unit with an added `"aa": true` field and violate one of the AA-only invariants (e.g., more than 2 parent units, more than 1 author, or unknown author fields). This makes `validate()` throw synchronously, escapes async error handling, and is caught only by the process-wide `uncaughtException` handler, which re-throws by design to terminate the process. Every full node or hub that receives and validates this joint over the network will crash identically, since the same code path executes on every node performing validation — this is a reliable, remotely triggerable denial-of-service against the network's ability to process/confirm units, not merely a single victim's local error.

### Likelihood Explanation
Likelihood is high: no signature or witnessing is required for the crash to occur — the fatal `throw` happens in early structural validation steps (`validateParents`, `validateAuthors`, `validateAuthor`) before signature verification completes. The attacker needs only to construct one crafted JSON joint and post/broadcast it; no privileged AA state, no private keys beyond a self-consistent unit hash, and no complex OScript/AA setup are required.

### Recommendation
- In `validate()`, never trust `objJoint.aa`/`objJoint.aa_mci` from the joint object argument for network-facing entry points. Require a separate, non-serializable/internal parameter (or an explicit trusted flag passed by `aa_composer` only) to indicate that a joint represents an AA response, instead of reading it off the attacker-controlled `objJoint`.
- Explicitly reject (via `ifJointError`) any incoming joint from `handlePostedJoint`/`handleOnlineJoint` that already contains an `aa` or `aa_mci` field, before it reaches `validate()`.
- Replace the internal `throw Error(...)` invariant checks in `validateParents`, `validateAuthors`, and `validateAuthor` that are reachable from `bAA` with `callback(err)`/`ifUnitError` style error propagation, so that even if `bAA` is erroneously set, the failure surfaces as a normal validation error instead of crashing the process.

### Proof of Concept
1. Construct a normal, self-consistent unit `U` with 3 valid, existing `parent_units` and correct `unit_hash`/`payload_commission` etc. (a perfectly legal shape for a non-AA unit — AA units are simply never expected to have >2 parents).
2. Wrap it as a joint and add the extra top-level field: `{"unit": U, "aa": true}`.
3. Post this joint to a full node/hub (e.g., via `handlePostedJoint`) or send it as a "joint" `justsaying`/network message.
4. `validate()` reads `objJoint.aa` → sets `bAA = true`, deletes `objJoint.aa` before the "unknown fields" check, then proceeds; when `validateParents` executes with `objUnit.parent_units.length > 2`, it synchronously throws `"AA unit with more than 2 parents"`.
5. The exception is not caught in the async chain and bubbles to `process.on('uncaughtException')` in `network.js`, which re-throws, terminating the node process.

### Citations

**File:** validation.js (L142-152)
```javascript
	var bAA = false;
	if (objJoint.aa) {
		bAA = true;
		var aa_mci = objJoint.aa_mci;
		delete objJoint.aa;
		delete objJoint.aa_mci;
	}
	else {
		if (isArrayOfLength(objUnit.authors, 1) && !isNonemptyObject(objUnit.authors[0].authentifiers) && !objUnit.content_hash && !conf.bLight)
			return callbacks.ifTransientError("possible AA");
	}
```

**File:** validation.js (L160-179)
```javascript
	if (objJoint.unsigned){
		if (hasFieldsExcept(objJoint, ["unit", "unsigned"]))
			return callbacks.ifJointError("unknown fields in unsigned unit-joint");
	}
	else if ("ball" in objJoint){
		if (!isStringOfLength(objJoint.ball, constants.HASH_LENGTH))
			return callbacks.ifJointError("wrong ball length");
		if (hasFieldsExcept(objJoint, ["unit", "ball", "skiplist_units"]))
			return callbacks.ifJointError("unknown fields in ball-joint");
		if ("skiplist_units" in objJoint){
			if (!isNonemptyArray(objJoint.skiplist_units))
				return callbacks.ifJointError("missing or empty skiplist array");
			//if (objUnit.unit.charAt(0) !== "0")
			//    return callbacks.ifJointError("found skiplist while unit doesn't start with 0");
		}
	}
	else{
		if (hasFieldsExcept(objJoint, ["unit"]))
			return callbacks.ifJointError("unknown fields in unit-joint");
	}
```

**File:** validation.js (L404-417)
```javascript
				function(cb){
					profiler.stop('validation-parents-exist');
					profiler.start();
					!objUnit.parent_units
						? cb()
						: validateHashTreeParentsAndSkiplist(conn, objJoint, cb);
				},
				function(cb){
					profiler.stop('validation-hash-tree-parents');
				//	profiler.start(); // conflicting with profiling in determineIfStableInLaterUnitsAndUpdateStableMcFlag
					!objUnit.parent_units
						? cb()
						: validateParents(conn, objJoint, objValidationState, cb);
				},
```

**File:** validation.js (L677-678)
```javascript
	if (objValidationState.bAA && objUnit.parent_units.length > 2)
		throw Error("AA unit with more than 2 parents");
```

**File:** validation.js (L1128-1130)
```javascript
function validateAuthors(conn, arrAuthors, objUnit, objValidationState, callback) {
	if (objValidationState.bAA && arrAuthors.length !== 1)
		throw Error("AA unit with multiple authors");
```

**File:** validation.js (L1149-1151)
```javascript
function validateAuthor(conn, objAuthor, objUnit, objValidationState, callback){
	if (objValidationState.bAA && hasFieldsExcept(objAuthor, ["address"]))
		throw Error("unknown fields in AA author");
```

**File:** validation.js (L1168-1174)
```javascript
	if (objValidationState.bAA) {
		storage.readAADefinition(conn, objAuthor.address, objValidationState.aa_mci, function (arrDefinition) {
			if (!arrDefinition)
				throw Error("AA definition not found " + objAuthor.address);
			checkSerialAddressUse();
		});
		return;
```

**File:** network.js (L1353-1365)
```javascript
function handlePostedJoint(ws, objJoint, onDone){
	
	if (!objJoint || !objJoint.unit || !objJoint.unit.unit || typeof objJoint.unit.unit !== 'string')
		return onDone('no unit');
	if ("unsigned" in objJoint)
		return onDone('unsigned unit');
	
	var unit = objJoint.unit.unit;
	delete objJoint.unit.main_chain_index;
	delete objJoint.unit.actual_tps_fee;
	objJoint = sortObject(objJoint);
	
	handleJoint(ws, objJoint, false, true, {
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
