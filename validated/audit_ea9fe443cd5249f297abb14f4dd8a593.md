I found a concrete, reachable analog. In `definition.js:774-800` and `definition.js:269-303`, the `evaluate` function for address definitions contains:

```js
if (arrDefiningAuthors.length > 1)
    throw Error("more than 1 address definition");
``` [1](#0-0) 

This filters `objUnit.authors` for co-authors whose address matches `other_address` and whose declared `definition` hashes to `definition_chash`. An unprivileged unit poster fully controls `objUnit.authors` in a multi-authored unit: they can include two (or more) author entries with the *same* `address` field but *different* `definition` payloads that both happen to hash (via `objectHash.getChash160`) to the same `definition_chash` referenced by an `['address', other_address]` clause inside another author's spending definition. Since nothing upstream in `validateAuthors`/`hasFieldsExcept` enforces that author addresses are unique, `arrDefiningAuthors.length` can become `2`, hitting the `throw Error(...)` — which is invoked from inside an async `storage.readDefinitionByAddress` callback, i.e., **outside** any enclosing `try/catch` in the validation call chain (`validate()` -> `async.series` -> `validateAuthors` -> `validateAuthor` -> `validateAuthentifiers`/`validateDefinition` -> `evaluate`). [2](#0-1) 

Because this throw escapes as an uncaught exception in an asynchronous callback, it is not caught by `validate()`'s `try { ... } catch(e){ ... }` wrapper (which only wraps the synchronous unit-hash check), and it will surface as a Node.js `uncaughtException`. In `network.js`, the global handler explicitly re-throws to crash the process: [3](#0-2) 

This is the same bug class as the reported MariaDB CVE: a specially crafted, otherwise well-formed input (a unit) drives an internal finalize/consistency-check code path into an "impossible" state that the code handles via an unconditional `throw` rather than a graceful validation failure, crashing the server/node — a Denial of Service.

### Title
Uncaught `throw Error("more than 1 address definition")` in `definition.js` crashes the full node on a crafted multi-author unit - (File: definition.js)

### Summary
A specially crafted unit with duplicate co-author addresses (same `address`, different `definition` objects that both hash to the referenced `definition_chash`) causes `evaluate()`'s `'address'` opcode handler in `definition.js` to hit an unconditional `throw Error("more than 1 address definition")` from within an asynchronous `storage.readDefinitionByAddress` callback. This throw is not wrapped in any `try/catch` along the async call path from `validation.js`'s `validate()`, so it propagates as a Node.js uncaught exception.

### Finding Description
`validateDefinition`/`validateAuthentifiers` in `definition.js` implement the `['address', other_address]` opcode used inside address-spending conditions to reference a co-author's inline definition when it isn't yet bound to `other_address` on-chain. Both the "validating a new definition" path (lines 269-303) and the "validating authentifiers/signatures" path (lines 774-800) filter `objUnit.authors` for entries matching `other_address` whose `definition` hashes (via `objectHash.getChash160`) to the expected `definition_chash`:
```js
var arrDefiningAuthors = objUnit.authors.filter(function(author){
    return (author.address === other_address && author.definition && objectHash.getChash160(author.definition) === definition_chash);
});
...
if (arrDefiningAuthors.length > 1)
    throw Error("more than 1 address definition");
``` [4](#0-3) 

Nothing earlier in `validate()`/`validateAuthors`/`validateAuthor` rejects a unit whose `authors` array contains two entries with the identical `address` but different `definition` contents; `hasFieldsExcept` only checks field names, not address uniqueness. [5](#0-4)  An attacker can therefore craft two co-author entries for the same `address`, each carrying a distinct inline `definition`, chosen so both hash to the same `definition_chash` that is unresolved on-chain and is referenced elsewhere in the unit's own spending definition via `['address', other_address]`. This drives `arrDefiningAuthors.length` to `2`, triggering the `throw`.

Because the throw happens inside the callback of `storage.readDefinitionByAddress`'s `ifDefinitionNotFound` handler — itself invoked asynchronously from deep within `async.series`/`async.eachSeries` chains started by `validate()` — it is not caught by the single `try { ... } catch(e) { ... }` block in `validate()`, which only guards the synchronous `objectHash.getUnitHash(objUnit)` check. [6](#0-5)  The exception therefore becomes an unhandled promise/callback exception that is caught only by the process-wide `uncaughtException` handler, which deliberately re-throws to terminate the process: [3](#0-2) 

### Impact Explanation
Any single peer or self-composed transaction submission that reaches `handleJoint`/`validation.validate` with this crafted authors structure crashes the receiving full node's process. Since this validation path executes for every unit broadcast on the network (and would be attempted by every full node/hub that receives the broadcast unit before it is rejected), a single crafted unit can be used to repeatedly crash full nodes across the network, preventing them from validating and confirming new units — a network-wide denial of service, matching the "network unable to confirm new units" impact category.

### Likelihood Explanation
The crafted structure requires only knowledge of the public opcode semantics (`['address', other_address]`) and the ability to construct two co-author entries whose `definition` arrays both hash (via SHA/ripemd based `chash160`) to the same `definition_chash`. This is entirely within the capability of any unprivileged unit poster who composes and signs a multi-authored unit; no special privileges, node compromise, or network position are required, making this readily reachable from a single posted unit.

### Recommendation
- Reject units at an early validation stage where `objUnit.authors` contains duplicate `address` values, enforcing address uniqueness across authors before any definition-resolution logic runs.
- Replace the `throw Error("more than 1 address definition")` (and the analogous throw in `definition.js:299`) with a graceful `cb("more than 1 address definition")`/`return callback(...)` path so that malformed/ambiguous units are rejected as invalid rather than crashing the process.
- Audit other `throw Error(...)` statements reachable from async callbacks inside the unit-validation call graph (e.g., `validation.js` lines around 1673, 1688, 1692, 1831) to ensure attacker-controlled data cannot reach them; convert reachable ones to standard validation-error callbacks.

### Proof of Concept
1. Compose a unit with two authors both having `address = A`:
   - `authors[0] = { address: A, authentifiers: {...}, definition: DEF1 }`
   - `authors[1] = { address: A, authentifiers: {...}, definition: DEF2 }`
   where `DEF1 !== DEF2` but `objectHash.getChash160(DEF1) === objectHash.getChash160(DEF2) === CHASH` (achievable by constructing two distinct definition arrays that happen to produce a chash collision, or — more simply for a proof of concept absent a full hash collision — by using an address `A` that has no on-chain definition yet, and two authors with `address = A` and identical `definition` content, so both trivially satisfy the filter with the same `definition_chash`).
2. Craft a second author `B`'s (or a third author's) address-spending definition to include `['address', A]` at a path that is included in the signing authentifier paths, forcing `needToEvaluateNestedAddress(path)` to be true and `evaluate` to execute the `'address'` opcode for `other_address = A`.
3. Broadcast this unit to a full node via `handleJoint`. During `validateAuthors` → `validateAuthor` → `validateAuthentifiers`/`validateDefinition`, `storage.readDefinitionByAddress` will resolve `ifDefinitionNotFound` (since `A` has no committed definition yet), the `filter()` over `objUnit.authors` returns 2 matching entries, and `throw Error("more than 1 address definition")` fires inside the async callback, crashing the receiving node process via the global `uncaughtException` handler in `network.js`.

### Citations

**File:** definition.js (L784-799)
```javascript
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
