## Analog Found: Unhandled `throw Error` Reachable From a Malicious Unit Crashes the Node — (`File: definition.js`)

### Summary
CVE-2020-5420 is a DoS where a party with limited privileges ("cf push" access) submits a specially crafted payload that the routing component cannot gracefully reject, crashing the whole cluster. The analogous class in ocore is a `throw Error(...)` executed inside an **asynchronous** database callback in the definition-evaluation logic. Because it fires inside a `conn.query` callback rather than the synchronous call stack that `validation.js` wraps in `try/catch`, it cannot be caught by any of the normal `ifUnitError`/`ifJointError` paths. It becomes an uncaught exception, and `network.js` deliberately re-throws on `uncaughtException` to kill the process, exactly the "crafted payload posted by an unprivileged actor crashes the node" pattern from the CVE.

### Finding Description
When evaluating an address definition (during authentifier/signature verification), the `'address'` op resolves a referenced *other address* that has no on-chain definition yet by looking for a co-author in the same unit whose `definition` hashes to the expected `definition_chash`: [1](#0-0) 

If more than one author entry in `objUnit.authors` matches (same `address` and a `definition` whose chash equals `definition_chash`), the code does not return a normal validation error — it directly does:

```js
if (arrDefiningAuthors.length > 1)
    throw Error("more than 1 address definition");
```

This same anti-pattern also exists in the definition-only validator at: [2](#0-1) 

Both `throw Error` calls execute inside a `storage.readDefinitionByAddress` → `ifDefinitionNotFound` callback, invoked from within `evaluate()`'s recursive, asynchronous walk of the address definition — not inside a `try { } catch` block that `validation.js` sets up around synchronous validation code.

Crucially, `validation.js`'s top-level author validation does not appear to reject units whose `authors` array contains two entries with the same `address`: [3](#0-2) [4](#0-3) 

Only `isValidAddress` is checked per author address — there is no uniqueness constraint enforced before authors are handed to per-author validation/definition evaluation. Any unprivileged unit poster can therefore submit a serial unit with two co-authors sharing the same `address` field, each carrying a `definition` field that hashes to the same `definition_chash` referenced by an `'address'` op inside another author's (or the same unit's) address-definition condition, or reference a `'definition template'` unit lookup that behaves inconsistently between the two evaluation passes (`definition.js:812` also uses a bare `throw Error("not 1 template")` inside a DB callback rather than routing the failure back through `cb2`/`callback`).

Once this array has length > 1 during evaluation, the `throw Error("more than 1 address definition")` fires from inside the async DB callback. There is no enclosing `try/catch` around this async callback in `validateAuthentifiers`/`validateDefinition`'s `evaluate()` recursion, so the exception is not converted into `callbacks.ifUnitError`/`ifJointError` the way validation errors normally are (contrast with `validation.js`'s wrapping `try{...}catch(e){return callbacks.ifJointError(...)}` patterns used elsewhere, e.g. [5](#0-4) ). Instead it surfaces as a Node.js uncaught exception.

`network.js` installs a global handler that intentionally re-throws to crash the process on any uncaught exception, "to avoid ending up in an inconsistent state": [6](#0-5) 

### Impact Explanation
Any full node (and hub) that receives and validates such a maliciously crafted unit crashes via the deliberate re-throw in the global `uncaughtException` handler. Since units propagate through the P2P network, a single posted unit can potentially crash every node that attempts to validate it — a network-wide denial-of-service that prevents the network from confirming new units, mirroring the "malicious developer crashes the whole Gorouter cluster" scenario in CVE-2020-5420. This is reachable purely by posting a unit — no elevated privileges, hub/operator access, or key compromise required.

### Likelihood Explanation
The precondition is a unit whose `authors` array contains duplicate `address` entries with colliding `definition_chash` matches (or a definition using `definition template` whose backing unit resolves inconsistently). No explicit code path in `validation.js` was found rejecting duplicate author addresses before this evaluation logic runs, making this readily constructible by any user able to compose a raw unit JSON (not merely use standard wallet tooling). The exact conditions for reaching `arrDefiningAuthors.length > 1` (vs. `=== 0`, which is handled gracefully) depend on the address/definition-hash bookkeeping and would need confirmation by testing against a live validator, but the structural bug — an unguarded `throw Error` inside an async DB callback within attacker-triggerable definition-evaluation logic — is clearly present and inconsistent with the rest of the codebase's careful error-callback conventions.

### Recommendation
- Replace the bare `throw Error("more than 1 address definition")` (definition.js:299, definition.js:795) and `throw Error("not 1 template")` (definition.js:812) with calls to the appropriate callback (`cb`/`cb2`) carrying a unit-validation error, matching the pattern used everywhere else in `evaluate()`.
- Add an explicit unit-level check in `validation.js` rejecting units whose `authors` array contains duplicate `address` values, closing off the precondition entirely.
- Wrap `evaluate()`'s recursive async callbacks in `try/catch` that route unexpected exceptions to `callbacks.ifUnitError`, so unforeseen edge cases fail per-unit instead of crashing the whole process.

### Proof of Concept
Conceptual construction (exact byte-for-byte unit crafting would need to be validated against a live node, since it also must satisfy hashing/well-formedness checks earlier in `validate()`):
1. Craft a unit with two entries in `authors`, both having `address = A`, and both carrying a `definition` field whose `chash160` equals the same `definition_chash` value expected by some address-definition `'address'` op reference (e.g. address `A`'s definition is not yet found on-chain, and another party's definition-in-force references `['address', A]`).
2. Post/broadcast the unit to a node via the standard `handleJoint` path used for any posted unit: [7](#0-6) .
3. During `validateAuthor`/`validateAuthentifiers` evaluation of the `'address'` op, `arrDefiningAuthors.length` becomes `2`, triggering the unguarded `throw Error("more than 1 address definition")` inside the `storage.readDefinitionByAddress` callback (definition.js:794-795), which is not caught, propagates as an uncaught exception, and is intentionally re-thrown by `network.js`'s `process.on('uncaughtException', ...)` handler, terminating the node process.

### Citations

**File:** definition.js (L296-300)
```javascript
						if (arrDefiningAuthors.length === 0) // no address definition in the current unit
							return bAllowUnresolvedInnerDefinitions ? cb(null, true) : cb("definition of inner address "+other_address+" not found");
						if (arrDefiningAuthors.length > 1)
							throw Error("more than 1 address definition");
						var arrInnerAddressDefinition = arrDefiningAuthors[0].definition;
```

**File:** definition.js (L774-799)
```javascript
			case 'address':
				// ['address', 'BASE32']
				if (!pathIncludesOneOfAuthentifiers(path, arrAuthentifierPaths, bAssetCondition))
					return cb2(false);
				var other_address = args;
				storage.readDefinitionByAddress(conn, other_address, objValidationState.last_ball_mci, {
					ifFound: function(arrInnerAddressDefinition){
						evaluate(arrInnerAddressDefinition, path, cb2);
					},
					ifDefinitionNotFound: function(definition_chash){
						try {
							var arrDefiningAuthors = objUnit.authors.filter(function(author){
								return (author.address === other_address && author.definition && objectHash.getChash160(author.definition) === definition_chash);
							});
						}
						catch (e) {
							return cb2(false);
						}
						if (arrDefiningAuthors.length === 0) // no definition in the current unit
							return cb2(false);
						if (arrDefiningAuthors.length > 1)
							throw Error("more than 1 address definition");
						var arrInnerAddressDefinition = arrDefiningAuthors[0].definition;
						evaluate(arrInnerAddressDefinition, path, cb2);
					}
				});
```

**File:** validation.js (L131-138)
```javascript
	try{
		// UnitError is linked to objUnit.unit, so we need to ensure objUnit.unit is true before we throw any UnitErrors
		if (objectHash.getUnitHash(objUnit) !== objUnit.unit)
			return callbacks.ifJointError("wrong unit hash: "+objectHash.getUnitHash(objUnit)+" != "+objUnit.unit);
	}
	catch(e){
		return callbacks.ifJointError("failed to calc unit hash: "+e);
	}
```

**File:** validation.js (L321-327)
```javascript
	var arrAuthorAddresses = objUnit.authors ? objUnit.authors.map(function(author) { return author.address; } ) : [];
	
	var objValidationState = {
		arrAdditionalQueries: [],
		arrDoubleSpendInputs: [],
		arrInputKeys: []
	};
```

**File:** validation.js (L354-356)
```javascript
	if (!arrAuthorAddresses.every(isValidAddress))
		return callbacks.ifUnitError("invalid author address");

```

**File:** network.js (L1149-1178)
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
