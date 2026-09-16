### Title
Denial of Service via Uncaught Exception in Address-Definition Evaluation (`definition.js`) Crashing the Full Node - ([File: definition.js])

### Summary
`@hapi/ammo`'s bug class is: a header-parsing function that is expected to always return normally instead `throw`s on malformed input, and because the caller (`hapi`) has no expectation of an exception, it propagates all the way to the top and kills the process. ocore has the same class of defect in its unit/definition validation pipeline: several code paths inside `definition.js`'s `evaluate()` (used by `validateAuthentifiers`, which is invoked for every unit that defines or references an address/asset spending condition) use `throw Error(...)` instead of returning an error through the callback, and these throws occur **inside asynchronous database-query callbacks**, so no enclosing `try/catch` in the synchronous call chain can catch them.

### Finding Description
`Definition.validateAuthentifiers()` is called from `validation.js` (`validateAuthor`, `validateAssetDefinition`, `evaluateAssetCondition`, `validateAuthorSignaturesWithoutReferences`, `signed_message.js`) whenever a unit's author supplies/uses an address definition, or an asset's spending condition is checked — i.e., this code runs on every unit posted by an ordinary, unprivileged wallet, as well as on AA trigger/asset messages.

Inside `evaluate()`'s `'address'` op handler [1](#0-0) , when the referenced address has no known definition yet, the code filters the unit's own `authors` array looking for a co-author that supplies the matching definition:
```
if (arrDefiningAuthors.length > 1)
    throw Error("more than 1 address definition");
```
This `throw` fires from inside the callback passed to `storage.readDefinitionByAddress(...).ifDefinitionNotFound`, i.e. from an **async** context [2](#0-1) . The parallel, structurally-similar code in `validateDefinition()` has the exact same unguarded `throw Error("more than 1 address definition")` right after a `try/catch` that only covers the chash computation, not the length check itself [3](#0-2) .

The same file contains numerous other `throw Error(...)` statements placed directly inside `conn.query(...)` callbacks (e.g. `"not 1 template"` in the `'definition template'` op of `validateAuthentifiers`) [4](#0-3) , and `validation.js` has similar patterns, e.g. `storage.readAADefinition(...)` callback throwing `"AA definition not found "` [5](#0-4) .

None of these are wrapped by a `try/catch` at the point where the async callback fires — normal JS `try/catch` cannot catch exceptions thrown inside a callback invoked later by the event loop/db driver. The exception therefore bypasses `validation.validate()`'s entire `ifUnitError`/`ifJointError`/`ifTransientError` error-reporting mechanism (`validation.js:117-496`) and becomes a genuinely **uncaught exception**.

ocore's own `network.js` explicitly turns any uncaught exception into a full process crash by design:
```
process.on('uncaughtException', (err) => {
    console.log('Uncaught exception:', err);
    ...
    throw err; // crash the process to avoid ending up in an inconsistent state
});
``` [6](#0-5) 

This is the exact analog of the `@hapi/ammo` advisory: a function that is expected/designed to signal errors via its callback instead throws synchronously/asynchronously, the framework (here, ocore's node process) has no way to recover, and the whole service goes down.

### Impact Explanation
Any unprivileged party who can get a unit accepted into validation (a normal wallet posting a payment/asset/AA-trigger unit with a crafted address/asset definition) can potentially trigger one of these unguarded `throw`s deep in async validation code. Because the throw happens outside any `try/catch` reachable by the synchronous call stack, it propagates to `process.on('uncaughtException')`, which is coded to always re-throw and crash the process. On a full/hub node this halts consensus processing and network relaying for all peers connected to that node until it is manually restarted — a network-wide denial of service if repeated against multiple relay/hub nodes.

### Likelihood Explanation
The likelihood depends on whether an attacker can actually construct a unit where the guarded condition (e.g., two "defining authors" for the same referenced address, or an author co-signing with a definition matching a not-yet-registered chash) is reachable without being rejected earlier by author/definition sanity checks. Based on the code reviewed, `validate()`/`validateAuthors()` do not appear (in the sections retrieved) to explicitly reject duplicate author addresses before this evaluation runs, but I was not able to fully trace every earlier validation branch given index/time limits, so this specific reachability should be confirmed by directly crafting and testing such a unit against `validation.js`/`definition.js`.

### Recommendation
Audit every `throw Error(...)` inside `definition.js` (`validateDefinition`, `validateAuthentifiers`/`evaluate`) and `validation.js` that appears inside a `conn.query`/`storage.read*` callback, and convert them to graceful `cb("...")`/`callback("...")` error returns instead of throwing, mirroring the safe pattern already used elsewhere in the same file (e.g. `validateDefinition`'s `'definition template'` branch, which correctly returns `cb("template not found or too many")` instead of throwing). At minimum, wrap these async callbacks so unexpected internal-consistency violations are reported as validation errors (`ifUnitError`) rather than crashing the whole process.

### Proof of Concept
Conceptual PoC (requires confirmation of full reachability against duplicate-author checks):
1. Craft a unit whose `authors` array contains an entry defining address `A` for the first time in this unit, and construct a nested address-spending condition (`['address', 'A']`) inside another address/asset definition being validated in the same unit, such that `storage.readDefinitionByAddress` returns `ifDefinitionNotFound` for `A`.
2. Arrange the unit so that `objUnit.authors.filter(...)` in `definition.js:774-799` (or the equivalent block in `validateDefinition`, `definition.js:279-303`) matches more than one author entry for address `A` with a definition whose chash equals the expected `definition_chash`.
3. Post the unit to a full node. The `throw Error("more than 1 address definition")` fires inside the async `ifDefinitionNotFound` callback, escapes `validation.validate()`'s error handling, and is caught only by `process.on('uncaughtException')` in `network.js:4530-4543`, which re-throws and crashes the node process, denying service to all connected peers until restart.

### Citations

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

**File:** definition.js (L802-819)
```javascript
			case 'definition template':
				// ['definition template', ['unit', {param1: 'value1'}]]
				var unit = args[0];
				var params = args[1];
				conn.query(
					"SELECT payload FROM messages JOIN units USING(unit) \n\
					WHERE unit=? AND app='definition_template' AND main_chain_index<=? AND +sequence='good' AND is_stable=1",
					[unit, objValidationState.last_ball_mci],
					function(rows){
						if (rows.length !== 1)
							throw Error("not 1 template");
						var template = rows[0].payload;
						var arrTemplate = JSON.parse(template);
						var arrFilledTemplate = replaceInTemplate(arrTemplate, params);
						evaluate(arrFilledTemplate, path, cb2);
					}
				);
				break;
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
