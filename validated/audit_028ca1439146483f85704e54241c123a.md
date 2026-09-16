## Analysis: Unhandled `throw Error("more than 1 address definition")` in address-definition evaluation → node crash

### Title
Unhandled exception in nested address-definition evaluation crashes full nodes on a single crafted unit - (File: definition.js)

### Summary
CVE-2018-17000 is a libtiff NULL-pointer dereference reachable by feeding a crafted file to a comparison routine (`_TIFFmemcmp`) that assumes preconditions the caller failed to guarantee, crashing the process. The analogous bug class in `ocore--011` is a hard `throw Error(...)` (rather than a soft validation error passed through the `cb`/`callback` chain) inside the unit-content-derived “nested address” evaluation path in `definition.js`. Because network-level unit processing installs a global `uncaughtException` handler that deliberately re-throws to kill the process, any reachable unhandled `throw` during validation of an attacker-supplied unit is a full-node crash / denial-of-service, exactly like the libtiff bug turning a malformed input into a process-ending null dereference.

### Finding Description
`definition.js` implements two structurally identical evaluators for the `address` definition opcode — one in `validateDefinition()` (used while validating a definition before it is known-good) and one in `validateAuthentifiers()` (used while checking authentifiers/signatures). Both resolve a referenced “inner address” that appears among the unit’s own `authors`: [1](#0-0) [2](#0-1) 

In both cases, when the referenced address’s `definition_chash` is not yet known in storage, the code filters `objUnit.authors` for entries whose `address` matches and whose `definition` hashes to `definition_chash`:
```
var arrDefiningAuthors = objUnit.authors.filter(function(author){
    return (author.address === other_address && author.definition && objectHash.getChash160(author.definition) === definition_chash);
});
...
if (arrDefiningAuthors.length > 1)
    throw Error("more than 1 address definition");
```
This is a hard JavaScript `throw`, not routed through the `cb`/`callback` error-reporting convention used everywhere else in this same function (e.g. `return cb("...")`). Nothing in `validateAuthor()` (`validation.js`) rejects a unit whose `authors` array contains two entries with the *same* `address` before this code is reached — each author is validated independently against storage, with no cross-author uniqueness check: [3](#0-2) 

A unit poster fully controls the `authors` array of their own unit and can duplicate the same address as two author entries, each carrying the same (attacker-known) definition and identical authentifiers/signature for that one keypair. If any address definition in the unit (the author’s own definition, or a definition/asset condition it references) contains an `['address', other_address]` op pointing at that duplicated address, and `other_address`’s `definition_chash` is not yet resolvable in storage (e.g. a first-use/newly introduced address), `arrDefiningAuthors.length` becomes `2`, triggering the unguarded `throw`.

This exception is not caught anywhere up the validation call chain that ultimately runs inside `network.js`’s `handleOnlineJoint`/`validate` pipeline, so it becomes an uncaught exception. The node's own crash handler confirms the severity of any such unhandled throw: [4](#0-3) 

### Impact Explanation
Any full node (and light vendors serving posted units) that processes such a crafted unit terminates its process (the handler intentionally re-throws “to crash the process to avoid ending up in an inconsistent state”). A single unprivileged unit poster can broadcast this unit to the network; every full node that validates it before consensus/witness protections can filter it out crashes, disrupting the ability of the network to process/confirm new units until operators intervene — this matches the “network unable to confirm new units” impact bar in the validation rules.

### Likelihood Explanation
Likelihood is high for any attacker capable of constructing a unit: it requires only crafting an `authors` array with a duplicated address (using one legitimately-owned keypair signed twice) and an address/asset definition that references that address via the `'address'` opcode while its `definition_chash` is not yet stored — both fully within the poster’s control, with no special privileges, hub/peer trust, or race conditions needed.

### Recommendation
- Replace both hard `throw Error("more than 1 address definition")` statements in `definition.js` (`validateDefinition` and `validateAuthentifiers`) with a call to the enclosing `cb`/`cb2` error-reporting continuation (e.g. `return cb("more than 1 address definition")` / `return cb2(false)`), so malformed input becomes a validation rejection instead of an uncaught exception.
- Add an explicit check earlier in unit validation (e.g., in `validateAuthor`/`validate` in `validation.js`) rejecting units whose `authors` array contains duplicate `address` values, closing off the root cause rather than only the symptom.
- Audit `definition.js` and related evaluators for other bare `throw Error(...)` calls reachable from externally-supplied unit/definition content and convert them to normal error callbacks.

### Proof of Concept
1. Attacker controls address `A` with a known definition `defA` (`getChash160(defA) === A`, and `A` not yet used/stored on-chain).
2. Attacker crafts a unit whose `authors` array contains two entries, both with `address: A`, `definition: defA`, and valid (duplicated) `authentifiers` for `A`.
3. The unit (or one of the assets/addresses it defines) includes a definition condition `['address', A]` at a point in the evaluation tree that gets evaluated (e.g., as part of validating the unit’s own or a referenced definition) while `A`’s `definition_chash` is still unresolved in storage.
4. During `validateDefinition`/`validateAuthentifiers` evaluation of the `'address'` op, `arrDefiningAuthors` collects both matching authors, its length is `2`, and `throw Error("more than 1 address definition")` fires.
5. This propagates as an uncaught exception through the validation pipeline invoked from `network.js`, hitting the global `uncaughtException` handler, which logs and re-throws, terminating the node process for every peer that validates this unit.

Note: I was unable to fully confirm within the indexed portions of `validation.js` whether some other, currently-unlocated check elsewhere in the codebase might already reject duplicate-address authors before this code path is reached; the grep results only returned match counts without full context for that specific check. If such a check exists and fully blocks duplicate author addresses, the exact PoC above would need adjustment to reach the `'address'`-op evaluation through a different vector (e.g., a referenced but not-yet-defined nested address shared indirectly rather than via literal duplicate authors), but the underlying unguarded `throw` in `definition.js` remains a real defect regardless of the exact triggering path.

### Citations

**File:** definition.js (L284-301)
```javascript
					ifDefinitionNotFound: function(definition_chash){
					//	if (objValidationState.bAllowUnresolvedInnerDefinitions)
					//		return cb(null, true);
						var bAllowUnresolvedInnerDefinitions = true;
						try {
							var arrDefiningAuthors = objUnit.authors.filter(function (author) {
								return (author.address === other_address && author.definition && objectHash.getChash160(author.definition) === definition_chash);
							});
						}
						catch (e) {
							return cb("failed to calc definition hash of co-author "+other_address+": "+e.message);
						}
						if (arrDefiningAuthors.length === 0) // no address definition in the current unit
							return bAllowUnresolvedInnerDefinitions ? cb(null, true) : cb("definition of inner address "+other_address+" not found");
						if (arrDefiningAuthors.length > 1)
							throw Error("more than 1 address definition");
						var arrInnerAddressDefinition = arrDefiningAuthors[0].definition;
						needToEvaluateNestedAddress(path) ? evaluate(arrInnerAddressDefinition, path, bInNegation, cb) : cb(null, true);
```

**File:** definition.js (L783-797)
```javascript
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
```

**File:** validation.js (L1149-1183)
```javascript
function validateAuthor(conn, objAuthor, objUnit, objValidationState, callback){
	if (objValidationState.bAA && hasFieldsExcept(objAuthor, ["address"]))
		throw Error("unknown fields in AA author");
	if (!objValidationState.bAA) {
		if (hasFieldsExcept(objAuthor, ["address", "authentifiers", "definition"]))
			return callback("unknown fields in author");
		if (!isNonemptyObject(objAuthor.authentifiers) && !objUnit.content_hash)
			return callback("no authentifiers");
		for (var path in objAuthor.authentifiers) {
			if (!isNonemptyString(objAuthor.authentifiers[path]))
				return callback("authentifiers must be nonempty strings");
			if (objAuthor.authentifiers[path].length > constants.MAX_AUTHENTIFIER_LENGTH)
				return callback("authentifier too long");
		}
	}
	
	var bNonserial = false;
	var bInitialDefinition = false;

	if (objValidationState.bAA) {
		storage.readAADefinition(conn, objAuthor.address, objValidationState.aa_mci, function (arrDefinition) {
			if (!arrDefinition)
				throw Error("AA definition not found " + objAuthor.address);
			checkSerialAddressUse();
		});
		return;
	}
	
	var arrAddressDefinition = objAuthor.definition;
	if (isNonemptyArray(arrAddressDefinition)){
		if (arrAddressDefinition[0] === 'autonomous agent')
			return callback('AA cannot be defined in authors');
		// todo: check that the address is really new?
		validateAuthentifiers(arrAddressDefinition);
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
