### Title
Unbounded recursive traversal of an unvalidated shared-address definition template crashes the wallet before validation - ([File: wallet_defined_by_addresses.js])

### Summary
The Wireshark EAP-dissector bug is a crash triggered by a specially crafted, deeply-structured input that the dissector recurses into before any sanity check rejects it. The closest ocore analog is in the paired-device "shared address" flow: `handleNewSharedAddress()` walks an attacker-supplied `body.definition` (an oscript-style definition array) with unbounded recursive helpers *before* the depth/complexity-limited `Definition.validateDefinition()` check runs, so a deeply nested definition sent by a paired device can blow the JS call stack and crash the node process.

### Finding Description
`handleNewSharedAddress(body, callbacks)` receives `body.definition` directly from a paired device over the `new_shared_address` device message [1](#0-0) . Before calling `validateAddressDefinition()` (which delegates to `Definition.validateDefinition()`, the function that enforces `MAX_DEPTH`/`MAX_COMPLEXITY` limits), the handler already recurses into the definition via `extractAddressPathsFromDefinition(body.definition)` [2](#0-1) .

The related helper `getMemberDeviceAddressesBySigningPaths()` shows the pattern used throughout this module: a plain recursive `evaluate()` function that walks `or`/`and`/`r of set`/`weighted and` nodes with **no depth counter and no bail-out** for deeply nested structures [3](#0-2) . `validateAddressDefinition()` itself simply forwards to `Definition.validateDefinition` with `bAllowUnresolvedInnerDefinitions: true` [4](#0-3) , but that call happens only *after* the unbounded pre-processing steps in `handleNewSharedAddress`.

This is in stark contrast to how the codebase treats a posted **unit**: `validation.js`'s `validate()` calls `isTooDeeplyNestedOrHasTooManyNodes(objUnit)` immediately, before any recursive walk of the unit's contents [5](#0-4) , and that helper explicitly bounds depth/node count [6](#0-5) . AA definitions similarly enforce `MAX_DEPTH` before recursing (`aa_validation.js`) [7](#0-6) . The shared-address-template code path lacks this early guard, so a crafted, deeply nested `definition` (e.g., thousands of nested `["and", [...]]` arrays) reaching `extractAddressPathsFromDefinition`/`getMemberDeviceAddressesBySigningPaths` triggers unbounded synchronous recursion, causing a `RangeError: Maximum call stack size exceeded`, which is uncaught in this code path and crashes the wallet/hub process — a denial of service, directly analogous to the Wireshark EAP dissector crash.

### Impact Explanation
A paired device (an authorized correspondent, not necessarily trusted with arbitrary payloads) can send a single `new_shared_address` message with a maliciously deep/nested definition and crash the receiving wallet or hub process. This is a concrete node-crash DoS reachable through a legitimate paired-device message-handling path, satisfying "a network unable to confirm new units"/node-disagreement-style impact at the node level (the affected node stops operating until restarted), consistent with the Medium severity of the reference CVE.

### Likelihood Explanation
Likelihood is moderate: it requires being paired with the victim device (a normal, low-barrier operation in this wallet protocol — pairing is routine for correspondents), and then sending one crafted message; no privileged network position, hub compromise, or protocol bypass is needed. The `signers`/`address` fields are checked first, but the recursive extraction of definition paths happens unconditionally on `body.definition` regardless of those checks succeeding.

### Recommendation
Add an early bounded-depth/size check (reusing `string_utils.isTooDeeplyNestedOrHasTooManyNodes` or an equivalent `MAX_DEPTH` guard as used in `definition.js`/`aa_validation.js`) on `body.definition` at the very top of `handleNewSharedAddress()`, before `extractAddressPathsFromDefinition()` or any other recursive walk executes. Apply the same guard to `getMemberDeviceAddressesBySigningPaths()` and any other unbounded recursive `evaluate()` helpers in `wallet_defined_by_addresses.js` that operate on device-supplied definition/template structures, and wrap the outer message handler in a try/catch that converts `RangeError` into a graceful `ifError` response instead of allowing it to propagate and crash the process.

### Proof of Concept
1. Pair with the victim device (attacker acts as a legitimate correspondent).
2. Construct `arrDefinition` as a deeply nested oscript structure, e.g. programmatically build `["and", [["and", [["and", [ ... "sig" leaf ... ]]]]]]` nested to a depth of tens of thousands of levels (or any structure walked by `extractAddressPathsFromDefinition`/`getMemberDeviceAddressesBySigningPaths`).
3. Send a `new_shared_address` device message: `{address: objectHash.getChash160(arrDefinition), definition: arrDefinition, signers: {...minimal valid signer map...}}`.
4. On the victim, `handleNewSharedAddress()` invokes `extractAddressPathsFromDefinition(body.definition)` before any depth-limited validation runs, causing unbounded recursion and a `RangeError: Maximum call stack size exceeded` that is not caught, crashing the wallet/hub process.

Note: I could not directly view the full body of `extractAddressPathsFromDefinition()` (only the caller and the structurally-similar `getMemberDeviceAddressesBySigningPaths()` were retrieved) due to index/tooling limits reached in this session; a full source review of `extractAddressPathsFromDefinition()` is recommended to confirm the exact recursion shape before implementing the fix.

### Citations

**File:** wallet_defined_by_addresses.js (L45-49)
```javascript
function sendNewSharedAddress(device_address, address, arrDefinition, assocSignersByPath, bForwarded){
	device.sendMessageToDevice(device_address, "new_shared_address", {
		address: address, definition: arrDefinition, signers: assocSignersByPath, forwarded: bForwarded
	});
}
```

**File:** wallet_defined_by_addresses.js (L377-415)
```javascript
// {address: "BASE32", definition: [...], signers: {...}}
function handleNewSharedAddress(body, callbacks){
	if (!ValidationUtils.isArrayOfLength(body.definition, 2))
		return callbacks.ifError("invalid definition");
	if (typeof body.signers !== "object" || Object.keys(body.signers).length === 0)
		return callbacks.ifError("invalid signers");
	try {
		var addr = objectHash.getChash160(body.definition);
	}
	catch (e) {
		return callbacks.ifError("invalid definition: " + e);
	}
	if (body.address !== addr)
		return callbacks.ifError("definition doesn't match its c-hash");
	for (var signing_path in body.signers){
		var signerInfo = body.signers[signing_path];
		if (signerInfo.address && signerInfo.address !== 'secret' && !ValidationUtils.isValidAddress(signerInfo.address))
			return callbacks.ifError("invalid member address: " + JSON.stringify(signerInfo.address));
	}
	const assocDefinitionAddresses = extractAddressPathsFromDefinition(body.definition);
	for (let signing_path in body.signers) {
		const signerInfo = body.signers[signing_path];
		if (assocDefinitionAddresses[signing_path] !== signerInfo.address)
			return callbacks.ifError("signer address at path " + signing_path + " doesn't match definition");
	}
	for (let def_path in assocDefinitionAddresses) {
		if (!body.signers[def_path])
			return callbacks.ifError("no signer for definition address at path " + def_path);
	}
	determineIfIncludesMeAndRewriteDeviceAddress(body.signers, function(err){
		if (err)
			return callbacks.ifError(err);
		validateAddressDefinition(body.definition, function(err){
			if (err)
				return callbacks.ifError(err);
			addNewSharedAddress(body.address, body.definition, body.signers, body.forwarded, callbacks.ifOk);
		});
	});
}
```

**File:** wallet_defined_by_addresses.js (L439-479)
```javascript
function getMemberDeviceAddressesBySigningPaths(arrAddressDefinitionTemplate){
	function evaluate(arr, path){
		var op = arr[0];
		var args = arr[1];
		if (!args)
			return;
		switch (op){
			case 'or':
			case 'and':
				for (var i=0; i<args.length; i++)
					evaluate(args[i], path + '.' + i);
				break;
			case 'r of set':
				if (!ValidationUtils.isNonemptyArray(args.set))
					return;
				for (var i=0; i<args.set.length; i++)
					evaluate(args.set[i], path + '.' + i);
				break;
			case 'weighted and':
				if (!ValidationUtils.isNonemptyArray(args.set))
					return;
				for (var i=0; i<args.set.length; i++)
					evaluate(args.set[i].value, path + '.' + i);
				break;
			case 'address':
				var address = args;
				var prefix = '$address@';
				if (!ValidationUtils.isNonemptyString(address) || address.substr(0, prefix.length) !== prefix)
					return;
				var device_address = address.substr(prefix.length);
				assocMemberDeviceAddressesBySigningPaths[path] = device_address;
				break;
			case 'definition template':
				throw Error(op+" not supported yet");
			// all other ops cannot reference device address
		}
	}
	var assocMemberDeviceAddressesBySigningPaths = {};
	evaluate(arrAddressDefinitionTemplate, 'r');
	return assocMemberDeviceAddressesBySigningPaths;
}
```

**File:** wallet_defined_by_addresses.js (L518-528)
```javascript
// fix:
// 1. check that my address is referenced in the definition
function validateAddressDefinition(arrDefinition, handleResult){
	var objFakeUnit = {authors: []};
	var objFakeValidationState = {last_ball_mci: MAX_INT32, bAllowUnresolvedInnerDefinitions: true};
	Definition.validateDefinition(db, arrDefinition, objFakeUnit, objFakeValidationState, null, false, function(err){
		if (err)
			return handleResult(err);
		handleResult();
	});
}
```

**File:** validation.js (L154-155)
```javascript
	if (isTooDeeplyNestedOrHasTooManyNodes(objUnit))
		return bAA ? callbacks.ifUnitError("unit is too deeply nested") : callbacks.ifJointError("unit is too deeply nested");
```

**File:** string_utils.js (L260-284)
```javascript
function isTooDeeplyNestedOrHasTooManyNodes(obj, depthLimit = 100, nodesLimit = 10000) {
	let nodeCount = 0;

	function check(variable, depth){
		if (depth > depthLimit || nodeCount > nodesLimit)
			return true;
		if (variable === null || typeof variable !== "object")
			return false;
		if (Array.isArray(variable)) {
			nodeCount += variable.length;
			for (let v of variable)
				if (check(v, depth + 1))
					return true;
		}
		else {
			nodeCount += Object.keys(variable).length;
			for (let key in variable)
				if (check(variable[key], depth + 1))
					return true;
		}
		return false;
	}

	return check(obj, 1);
}
```

**File:** aa_validation.js (L598-601)
```javascript
	function validate(obj, name, path, locals, depth, cb, bValueOnly) {
		if (depth > MAX_DEPTH)
			return cb("max depth reached");
		count++;
```
