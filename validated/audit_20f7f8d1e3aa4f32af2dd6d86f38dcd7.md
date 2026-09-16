### Title
Unhandled exception in nested address definition evaluation crashes the node process - ([File: definition.js])

### Summary
`validateDefinition()`'s `'address'` opcode handler contains an unguarded `throw Error("more than 1 address definition")` at [1](#0-0)  that fires when a unit's `authors` array contains more than one author whose address matches the referenced address and whose `definition` hashes to the same `definition_chash`. Because this throw happens inside an asynchronous `storage.readDefinitionByAddress` callback, it is not caught by any synchronous `try/catch` in the call chain, and it ultimately reaches the global `process.on('uncaughtException', ...)` handler in `network.js`, which explicitly re-throws to crash the node: [2](#0-1) .

### Finding Description
`validateDefinition()` is invoked from `validateAuthor()` while checking an author's address definition, and recursively evaluates nested `['address', 'BASE32...']` operators that reference *other* addresses defined by co-authors of the same unit [3](#0-2) . When such a nested reference is not yet known to storage, the code filters `objUnit.authors` for authors whose `.address` and hashed `.definition` match, and if the filter unexpectedly returns more than one match, the code throws a raw JS `Error` instead of returning an error via the `cb` callback used everywhere else in this function: [4](#0-3) .

Nothing in the surrounding validation pipeline prevents an attacker from crafting a multi-authored unit where two authors share the same address value but each supplies a `definition` array that both happen to hash (via `objectHash.getChash160`) to the same `definition_chash` referenced by a third author's nested `['address', ...]` condition. `validate()` only checks `arrAuthorAddresses.every(isValidAddress)` [5](#0-4)  — it never rejects duplicate addresses across `objUnit.authors`. This is exactly the kind of "crafted structure causes a parser to hit an unreachable/invalid internal state and dereference/crash" bug class that CVE-2019-5010 represents (a malformed X.509 structure triggering a NULL pointer dereference in the certificate parser): here a malformed but hash/format-valid unit structure drives an address-definition evaluator into a state its author assumed to be impossible, and the code reacts with a hard `throw` instead of a graceful validation-error path.

Because the throw occurs inside an `ifDefinitionNotFound` callback fired asynchronously from `storage.readDefinitionByAddress` (itself invoked from inside `evaluate()`'s `case 'address'`), there is no enclosing `try/catch` frame active at the point the exception is thrown — the `try/catch` a few lines above at line 288-295 only wraps the `objUnit.authors.filter(...)` computation, not the subsequent `throw` at line 299. The exception therefore propagates out of the async callback chain uncaught and is picked up by the global handler that intentionally re-throws to crash the process: [2](#0-1) .

### Impact Explanation
Any unprivileged peer that can get a unit posted/relayed to a node (a standard, protocol-valid-looking unit posted over the network) can crash the receiving Obyte full node/hub process. Since the crash is triggered during normal unit validation (`validate()` → `validateAuthor()` → `validateDefinition()`), it affects any full node that processes the malicious unit, including hubs and relays — this matches the "network unable to confirm new units" impact bar: an attacker can repeatedly crash/restart nodes across the network, disrupting confirmation and stability processing while the node restarts and re-syncs.

### Likelihood Explanation
Reaching this code path requires: (1) crafting a unit with ≥2 authors sharing the same wallet address but distinct `definition` arrays whose chash160 both equal the `definition_chash` referenced by a nested `['address', X]` opcode in a third author's (or the same author's) address definition, and (2) that referenced address's definition being previously unknown to `storage` (`ifDefinitionNotFound` branch). Constructing two structurally different definition arrays that hash to the same chash requires either a hash collision (impractical) or, more plausibly, exploiting the same author address appearing twice with an *identical* definition supplied twice (both entries in `objUnit.authors` are literally duplicates) — which trivially produces `arrDefiningAuthors.length > 1` without needing a hash collision at all, since the filter only checks address + chash match, not uniqueness of author entries. Nothing else in `validate()` rejects a unit whose `authors` array simply repeats the same address/definition pair twice. This makes the trigger straightforward to construct for a single poster.

### Recommendation
- Replace the `throw Error("more than 1 address definition")` at `definition.js:299` (and the parallel `throw Error("more than 1 address definition")` in `validateAuthentifiers`'s equivalent `'address'` case) with a call to the `cb`/`cb2` error-callback pattern used throughout this function, so malformed units are rejected as validation errors rather than crashing the process.
- Add an explicit check in `validate()`/`validateAuthors()` in `validation.js` rejecting units whose `authors` array contains duplicate `address` values, closing off the root cause of ambiguous "more than 1 matching author" states.
- Audit other `throw Error(...)` call sites inside async callbacks reachable from `validate()`/`validateDefinition()`/`validateAuthentifiers()` (e.g., `definition.js:795` "more than 1 address definition" in `validateAuthentifiers`, and similar unguarded throws) for the same unguarded-async-throw pattern.

### Proof of Concept
1. Construct a unit `U` with two entries in `authors`, both having identical `address: "A"` and an identical `definition` array `D` (so both entries are exact duplicates in the array). This produces a well-formed, hash-valid `objUnit` (author addresses are not deduplicated by validation).
2. Have a third author (or a nested condition in `D` itself if self-referential is permitted) include a spending-condition definition containing `['address', 'A']` that is evaluated while `A`'s definition is not yet found in storage (`ifDefinitionNotFound` branch of `storage.readDefinitionByAddress`).
3. When `validateDefinition()` evaluates this nested `'address'` opcode, `objUnit.authors.filter(...)` matches both duplicate entries for address `A`, so `arrDefiningAuthors.length === 2`, hitting `throw Error("more than 1 address definition")` at `definition.js:299`.
4. This exception is not caught by any `try/catch` in the async callback chain and surfaces as an uncaught exception, triggering `network.js`'s `process.on('uncaughtException', ...)` handler, which re-throws and terminates the node process.

### Citations

**File:** definition.js (L43-43)
```javascript
function validateDefinition(conn, arrDefinition, objUnit, objValidationState, arrAuthentifierPaths, bAssetCondition, handleResult){
```

**File:** definition.js (L284-303)
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
					}
				});
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

**File:** validation.js (L354-355)
```javascript
	if (!arrAuthorAddresses.every(isValidAddress))
		return callbacks.ifUnitError("invalid author address");
```
