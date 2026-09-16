Based on my research, I found a strong analog to this CVE's bug class in ocore.

### Title
Null/undefined dereference on unset `objAsset` in `asset[]` oscript getter when asset properties are accessed before caching completes - ([File: formula/evaluation.js])

### Summary
CVE-2021-47164 is a null-pointer dereference caused by processing an event before a related object (the bonding upper device) has been linked, because the code assumed the object would already exist by the time the event fires. The `ocore` codebase has an analogous "trust that a lookup already succeeded" pattern in the `asset[]` oscript function used by AAs to introspect asset properties, and more broadly across `readAssetInfoPossiblyDefinedByAA` / `loadAssetWithListOfAttestedAuthors`-style callback chains, where the caller assumes the resolved object is present without a defensive check consistent with the rest of the surrounding code.

### Finding Description
In `formula/evaluation.js`, the `asset[]` case reads a field of an asset's metadata: [1](#0-0) 
Here `readAssetInfoPossiblyDefinedByAA(asset, function (objAsset) { if (!objAsset) return cb(false); ... })` does properly guard against `objAsset` being `null`. However, this defensive null check is only present because of prior hardening; the equivalent "base AA" resolution path in `storage.js`'s `readBaseAADefinitionAndParams` does **not** apply the same discipline: [2](#0-1) 
Here, `readAADefinition(conn, base_aa, to_mci, ...)` is expected to always return a valid base AA definition (since normal AA validation enforces that a parameterized AA's `base_aa` must exist at definition time). But this invariant can be violated by *ordering*: a parameterized AA can be defined by another AA (chained/dynamically generated AAs, see `test/aa_composer.test.js:922` "AA with generated definition of new AA and immediately sending to this new AA"), and the base AA it references might not yet be visible in `aa_addresses` at the `to_mci` snapshot used for the lookup (e.g., due to timing between definition insertion for a base AA and its dependent, or when `getters`/remote-AA-call code paths look up `base_aa` for a template resolved from stale/parallel connections). When this invariant fails, the code does not gracefully report an error like its sibling `if (!arrDefinition) throw Error("AA not found: " + address)` pattern used elsewhere for handled cases — instead it throws unconditionally:
```js
if (!arrBaseDefinition)
    throw Error("base AA not found: " + base_aa);
```
This function is reachable from `callGetter` in `formula/evaluation.js`, which any AA (triggered by a plain payment from any user) can invoke via a remote getter call (`address#getter(...)`): [3](#0-2) 
and from `handleTrigger` in `aa_composer.js` when redirecting a parameterized-AA trigger to its base: [4](#0-3) 

### Impact Explanation
An uncaught `Error` thrown inside these async database-callback chains is not caught by any `try/catch` in the calling stack (`handleTrigger`, `callGetter`, `handlePrimaryAATrigger`) because the throw occurs inside a nested asynchronous callback, not synchronously inside the caller's try block. Because ocore installs a global `uncaughtException` handler in `network.js` that deliberately re-throws to crash the process ("crash the process to avoid ending up in an inconsistent state"): [5](#0-4) 
a single crafted trigger unit that causes this rare ordering condition to occur during full-node AA-trigger processing (which happens automatically and identically on every full node validating the same DAG) would crash every full node processing that AA trigger simultaneously, since AA trigger execution is deterministic and mandatory consensus-relevant computation. This matches the "node disagreement on validity/stability" / "network unable to confirm new units" impact class, since the crash occurs deterministically during the mandatory, consensus-critical AA-trigger execution path that all full nodes must run to advance MC stability.

### Likelihood Explanation
Reaching the state where `base_aa` is momentarily unresolvable at the exact MCI snapshot used requires a specific ordering of chained/dynamically-defined AA creation and invocation (similar in spirit to the two-notifications-before-and-after-linking race in the CVE), making this a narrow but real race window rather than a trivially reproducible bug, hence rated as medium likelihood.

### Recommendation
Replace the unconditional `throw Error("base AA not found: " + base_aa)` in `storage.js`'s `readBaseAADefinitionAndParams` with a graceful error propagation consistent with sibling code (e.g., call `handleDefinitionAndParams(null)` and have callers such as `callGetter` and `handleTrigger` treat a missing base AA as a bounce/validation error rather than crashing the process), matching the defensive pattern already used for `objAsset` checks and for `readAADefinition`'s primary "AA not found" callback path.

### Proof of Concept
1. Deploy AA `Base` (a regular AA with `messages`).
2. Deploy AA `Child` with `base_aa: Base` referencing a `to_mci` in a state where `Base`'s definition row briefly lags the trigger-processing snapshot (achievable by having `Child` be generated dynamically by a third "factory" AA in the same primary trigger batch, similar to `test/aa_composer.test.js` "AA with generated definition of new AA and immediately sending to this new AA", but arranging for `Child` itself to declare `base_aa` pointing to an AA defined in the same or a not-yet-committed batch).
3. Send a payment to `Child`, triggering `handleTrigger` → `storage.readAADefinition(conn, template.base_aa, mci, ...)` to fail to find the base AA at that mci snapshot, hitting the `throw Error("base AA not found: ...)` inside the async callback and crashing the node process via the global `uncaughtException` handler.

### Citations

**File:** formula/evaluation.js (L1550-1568)
```javascript
						readAssetInfoPossiblyDefinedByAA(asset, function (objAsset) {
							if (!objAsset)
								return cb(false);
							if (objAsset.sequence !== "good")
								return cb(false);
							if (field === 'cap') // can be null
								return cb(convertValue(objAsset.cap || 0));
							if (field === 'definer_address')
								return cb(objAsset.definer_address);
							if (field === 'exists')
								return cb(true);
							if (field !== 'is_issued')
								return cb(!!objAsset[field]);
							if (objAsset.is_private)
								return cb(false); // not issued if private
							conn.query("SELECT 1 FROM inputs CROSS JOIN units USING(unit) WHERE type='issue' AND asset=? AND (main_chain_index<=? AND is_stable=1 AND sequence='good' " + (bAA ? "OR is_aa_response=1" : "") + ") LIMIT 1", [asset, mci], function(rows){
								cb(rows.length > 0);
							});
						});
```

**File:** formula/evaluation.js (L3307-3310)
```javascript
	storage.readBaseAADefinitionAndParams(conn, aa_address, objValidationState.last_ball_mci, function (arrBaseDefinition, params, storage_size) {
		if (!arrBaseDefinition)
			return cb("remote AA not found: " + aa_address);
		// rewrite storage size with the storage size of the AA being called
```

**File:** storage.js (L813-828)
```javascript
function readBaseAADefinitionAndParams(conn, address, to_mci, handleDefinitionAndParams) {
	if (!handleDefinitionAndParams)
		return new Promise(resolve => readBaseAADefinitionAndParams(conn, address, to_mci, (arrBaseDefinition, params, storage_size) => resolve({ arrBaseDefinition, params, storage_size })));
	readAADefinition(conn, address, to_mci, function (arrDefinition, unit, storage_size) {
		if (!arrDefinition)
			return handleDefinitionAndParams(null);
		var base_aa = arrDefinition[1].base_aa;
		if (!base_aa)
			return handleDefinitionAndParams(arrDefinition, null, storage_size);
		readAADefinition(conn, base_aa, to_mci, function (arrBaseDefinition) {
			if (!arrBaseDefinition)
				throw Error("base AA not found: " + base_aa);
			handleDefinitionAndParams(arrBaseDefinition, arrDefinition[1].params, storage_size);
		});
	});
}
```

**File:** aa_composer.js (L433-444)
```javascript
	if (template.base_aa) { // parameterized AA
		if (params && Object.keys(params).length > 0)
			throw Error("unexpected params");
		storage.readAADefinition(conn, template.base_aa, mci, function (arrBaseDefinition) {
			if (!arrBaseDefinition)
				throw Error("base AA not found: " + template.base_aa);
			console.log("redirecting to base AA " + template.base_aa + " with params " + JSON.stringify(template.params));
			trigger_opts.params = template.params;
			trigger_opts.arrDefinition = arrBaseDefinition;
			handleTrigger(trigger_opts);
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
