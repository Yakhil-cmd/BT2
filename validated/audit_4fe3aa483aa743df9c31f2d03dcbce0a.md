### Title
Remote Denial of Service via Unhandled Exception in AA Author Validation - (File: validation.js)

### Summary
A remote, unauthenticated peer can post a joint containing forged `aa` / `aa_mci` fields. `validate()` silently accepts these fields, switches the unit into the internal "AA-response" validation path, and later synchronously `throw`s an uncaught `Error` from inside an asynchronous database callback when the referenced address has no AA definition. Because the throw happens outside any surrounding try/catch (it fires from a fresh callback frame invoked by `storage.readAADefinition`), it becomes a true Node.js "uncaught exception," which the global handler in `network.js` deliberately re-throws to crash the whole process.

### Finding Description
`validate()` trusts the joint-supplied `aa` flag without any authentication or origin check: [1](#0-0) 

These fields are deleted from `objJoint` *before* the `hasFieldsExcept` unknown-field check runs, so an attacker-supplied `aa`/`aa_mci` never triggers a "unknown fields" rejection: [2](#0-1) 

The attacker-controlled `aa_mci` value is then copied verbatim into `objValidationState.aa_mci`, with no type or range validation: [3](#0-2) 

`validateAuthors`/`validateAuthor` is reached later in the same synchronous `async.series` pipeline. When `objValidationState.bAA` is true, `validateAuthor` completely skips authentifier/signature checks and only requires the author object to contain an `address` field: [4](#0-3) 

It then looks up the AA definition using the forged `aa_mci`, and if no definition is found for that address/mci pair, it synchronously `throw`s inside the async callback rather than calling `callback(err)`: [5](#0-4) 

Because `storage.readAADefinition`'s callback fires from a database I/O completion (a new JS call stack), this `throw` cannot be caught by any `try/catch` in the caller chain — it becomes an uncaught exception. `network.js` installs a process-wide handler that intentionally terminates the entire node on any uncaught exception: [6](#0-5) 

This is directly analogous to the MsQuic bug class described in the report: an unauthenticated remote party sends a single malformed/unexpected message (there, a version-negotiation packet on an established connection; here, a joint with forged `aa`/`aa_mci` fields referencing a non-existent AA definition), the receiver dereferences/assumes a value that doesn't exist, and the resulting unhandled fault crashes the whole server process (CWE-476 missing-null-check leading to CWE-400 denial of service).

### Impact Explanation
Any single crafted joint — reachable by posting a unit directly (light wallet `post_joint`) or by having it relayed/broadcast through the P2P layer — can crash any full node (including hubs and witnesses) that validates it. Since the crash handler explicitly re-throws to terminate the process (`throw err; // crash the process to avoid ending up in an inconsistent state`), this is not a caught, contained error: the node process dies. If propagated across the network (as ordinary joints are), this can be used to repeatedly crash relays/hubs/witnesses, degrading the network's ability to confirm new units — a High severity availability impact, matching the CVSS profile of the referenced advisory (`AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`).

### Likelihood Explanation
Likelihood is high: the attack requires no special privileges, no valid signature, and no wallet funds — only the ability to submit or relay a single joint. The `aa`/`aa_mci` fields are trivially forgeable JSON fields, and the "AA definition not found" condition is easy to satisfy by referencing any address without a deployed AA definition at the chosen `aa_mci`.

### Recommendation
- Do not accept `aa`/`aa_mci` fields from any externally supplied joint; these should only ever be set internally by the AA composer for locally generated response units, never parsed off the wire/from posted joints.
- In `validateAuthor`'s AA branch, replace `throw Error(...)` with a proper `callback(err)`/`ifUnitError` path so failures are routed through the normal validation error-handling instead of throwing from an async callback.
- Ensure `hasFieldsExcept` checks run before `aa`/`aa_mci` are stripped, so any joint carrying these fields from an external source is rejected outright.

### Proof of Concept
1. Craft a joint whose top level includes `"aa": true` and an `"aa_mci"` value (e.g. `0` or the current stable mci).
2. Set the unit's single author `address` to any valid-checksum address that is *not* a deployed Autonomous Agent (so `storage.readAADefinition` resolves to `null`/`undefined` for that mci).
3. Submit the joint to a full node via `post_joint` (light vendor endpoint) or broadcast it as a regular unit over the P2P `network.js` joint-handling path.
4. `validate()` sets `bAA = true` (validation.js:143-148), skips signature checks (validation.js:1149-1156), and calls `storage.readAADefinition`; when the callback fires with no definition, it throws (validation.js:1170-1172), producing an uncaught exception that the handler in `network.js:4530-4543` turns into a full process crash.

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

**File:** validation.js (L176-179)
```javascript
	else{
		if (hasFieldsExcept(objJoint, ["unit"]))
			return callbacks.ifJointError("unknown fields in unit-joint");
	}
```

**File:** validation.js (L334-336)
```javascript
	objValidationState.bAA = bAA;
	if (bAA)
		objValidationState.aa_mci = aa_mci;
```

**File:** validation.js (L1149-1156)
```javascript
function validateAuthor(conn, objAuthor, objUnit, objValidationState, callback){
	if (objValidationState.bAA && hasFieldsExcept(objAuthor, ["address"]))
		throw Error("unknown fields in AA author");
	if (!objValidationState.bAA) {
		if (hasFieldsExcept(objAuthor, ["address", "authentifiers", "definition"]))
			return callback("unknown fields in author");
		if (!isNonemptyObject(objAuthor.authentifiers) && !objUnit.content_hash)
			return callback("no authentifiers");
```

**File:** validation.js (L1168-1175)
```javascript
	if (objValidationState.bAA) {
		storage.readAADefinition(conn, objAuthor.address, objValidationState.aa_mci, function (arrDefinition) {
			if (!arrDefinition)
				throw Error("AA definition not found " + objAuthor.address);
			checkSerialAddressUse();
		});
		return;
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
