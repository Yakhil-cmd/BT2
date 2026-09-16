## Title
Node crash via unchecked `payload` in `getAllAuthorsAndOutputAddresses()` when notifying watchers of a new unit - (File: network.js)

### Summary
`network.js`'s `notifyWatchers()` is invoked by every full node for every newly received/validated joint, including units posted by any unprivileged peer. It calls `getAllAuthorsAndOutputAddresses(objUnit)`, which iterates `objUnit.messages` and, for `app === 'definition'` messages, dereferences `payload.definition[1]` without first checking that `payload` is truthy, unlike the sibling `payment` branch which explicitly checks `payload` before touching it.

### Finding Description
```javascript
function getAllAuthorsAndOutputAddresses(objUnit){
	var arrAuthorAddresses = objUnit.authors.map(function(author){ return author.address; });
	if (!objUnit.messages) // voided unit
		return null;
	var arrOutputAddresses = [];
	var arrBaseAAAddresses = [];
	for (var i=0; i<objUnit.messages.length; i++){
		var message = objUnit.messages[i];
		var payload = message.payload;
		if (message.app === "payment" && payload) {
			for (var j = 0; j < payload.outputs.length; j++) {
				...
			}
		}
		else if (message.app === 'definition' && payload.definition[1].base_aa)
			arrBaseAAAddresses.push(payload.definition[1].base_aa);
	}
	...
}
``` [1](#0-0) 

The `payment` branch guards `payload` truthiness before accessing `.outputs`, mirroring the strict validation everywhere else in the codebase (e.g. `validateMessage`/`validateInlinePayload` in `validation.js` [2](#0-1) ). The `definition` branch, however, has no such guard — it directly evaluates `payload.definition[1].base_aa`. If `message.payload` is `undefined`/`null` (as it legitimately can be for messages whose payload has been stripped, e.g. a voided message that keeps `objUnit.messages` populated but nulls out individual `payload` fields, or a message reconstructed with `payload` absent), this throws an uncaught `TypeError: Cannot read properties of undefined (reading 'definition')`.

This mirrors the CVE-2020-15304 bug class: a value derived from untrusted/attacker-influenced input (the message `payload`) is dereferenced without a null/existence check before use, leading to an invalid access on a null/undefined reference — in this JS codebase this manifests as an uncaught `TypeError` rather than a native NULL-pointer dereference, but the effect is process-crashing because the codebase intentionally treats uncaught exceptions as fatal.

`notifyWatchers()` is called for **every joint the node processes**, on the hot save/validate path, meaning this reachable from any single posted unit that reaches this function with a `definition` message whose `payload` ends up falsy. The project's own top-level exception handler is designed to intentionally crash the whole process on any uncaught exception:
```javascript
process.on('uncaughtException', (err) => {
	console.log('Uncaught exception:', err);
	...
	throw err; // crash the process to avoid ending up in an inconsistent state
});
``` [3](#0-2) 

### Impact Explanation
A crash triggered inside `notifyWatchers()` (invoked synchronously during handling of newly-arrived/validated joints on every full node) intentionally propagates to the global `uncaughtException` handler, which re-throws to kill the process. Since this runs on the standard unit-processing path for *every* node in the network that reaches this code path with the crafted message, a single malicious unit could be leveraged to disrupt processing/confirmation of that unit (and potentially any subsequent DAG progress relying on that node), matching the "network unable to confirm new units" impact class described in the validation rules.

### Likelihood Explanation
Reaching this exact bug requires a `definition`-app message where `message.payload` is falsy while `objUnit.messages` itself is non-null. Normal validation (`validateInlinePayload`) forces `definition` messages to always be inline and payload to be a non-empty object [4](#0-3) , so a *freshly validated, well-formed* unit cannot trigger it through the normal `handleJoint`→`validate`→`saveJoint`→`notifyWatchers` flow. The exploitability therefore hinges on whether `notifyWatchers` can be reached with a joint whose message payloads have been altered/stripped (e.g., voided message reconstruction, or a joint object mutated between validation and notification) — this path could not be fully confirmed from the available code slices, since the exact call sites feeding `notifyWatchers` with potentially payload-less messages, and whether `objUnit.messages` can be non-null while individual payloads are stripped, were not conclusively traced in this session.

### Recommendation
Add a payload existence check to the `definition` branch, mirroring the `payment` branch:
```javascript
else if (message.app === 'definition' && payload && isArrayOfLength(payload.definition, 2) && isNonemptyObject(payload.definition[1]) && payload.definition[1].base_aa)
	arrBaseAAAddresses.push(payload.definition[1].base_aa);
```
This defensive check costs nothing and eliminates the crash risk regardless of whether the "stripped payload" pathway is currently reachable.

### Proof of Concept
Could not be fully constructed/confirmed in this session: a concrete PoC requires demonstrating a concrete code path that calls `notifyWatchers(objJoint, ...)` with an `objJoint.unit.messages` array containing a `definition`-app message whose `payload` is `undefined`/`null`, bypassing the inline-payload-required validation in `validateInlinePayload`. This would need further tracing of all call sites that construct `objJoint` for `notifyWatchers` (e.g. archived/voided-joint reconstruction paths in `storage.js`/`archiving.js`) to confirm reachability by an unprivileged unit poster; that verification was not completed given the tool budget of this analysis.

### Citations

**File:** network.js (L1685-1711)
```javascript
function getAllAuthorsAndOutputAddresses(objUnit){
	var arrAuthorAddresses = objUnit.authors.map(function(author){ return author.address; });
	if (!objUnit.messages) // voided unit
		return null;
	var arrOutputAddresses = [];
	var arrBaseAAAddresses = [];
	for (var i=0; i<objUnit.messages.length; i++){
		var message = objUnit.messages[i];
		var payload = message.payload;
		if (message.app === "payment" && payload) {
			for (var j = 0; j < payload.outputs.length; j++) {
				var address = payload.outputs[j].address;
				if (arrOutputAddresses.indexOf(address) === -1)
					arrOutputAddresses.push(address);
			}
		}
		else if (message.app === 'definition' && payload.definition[1].base_aa)
			arrBaseAAAddresses.push(payload.definition[1].base_aa);
	}
	var arrAddresses = _.union(arrAuthorAddresses, arrOutputAddresses, arrBaseAAAddresses);
	return {
		author_addresses: arrAuthorAddresses,
		output_addresses: arrOutputAddresses,
		base_aa_addresses: arrBaseAAAddresses,
		addresses: arrAddresses,
	};
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

**File:** validation.js (L1747-1758)
```javascript
		case "definition": // for AAs only
			if (!isNonemptyObject(payload))
				return callback("payload must be a non empty object");
			if (hasFieldsExcept(payload, ["address", "definition"])) // AA definition cannot be changed and its address is also its definition_chash
				return callback("unknown fields in app definition");
			try{
				if (payload.address !== objectHash.getChash160(payload.definition))
					return callback("definition doesn't match the chash");
			}
			catch(e){
				return callback("bad definition");
			}
```
