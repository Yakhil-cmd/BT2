### Title
Unbounded recursion in `getMemberDeviceAddressesBySigningPaths` allows a paired device to crash a wallet via a deeply nested `create_new_shared_address` definition template - (File: wallet_defined_by_addresses.js)

### Summary
`validateAddressDefinitionTemplate()` is invoked directly on an attacker-supplied `address_definition_template` coming from a `create_new_shared_address` device message, before any complexity/depth-limited validation (`Definition.validateDefinition`) runs. It calls `getMemberDeviceAddressesBySigningPaths()`, whose internal `evaluate()` recurses into nested `or`/`and`/`r of set`/`weighted and` branches without any depth or complexity limit.

### Finding Description
`wallet.js` handles `create_new_shared_address` messages from a paired device: [1](#0-0) 

This calls `walletDefinedByAddresses.validateAddressDefinitionTemplate()`, which first runs `getMemberDeviceAddressesBySigningPaths(arrDefinitionTemplate)` on the raw, attacker-controlled template, and only afterwards defers to `Definition.validateDefinition` (which enforces `MAX_COMPLEXITY`/`MAX_OPS`): [2](#0-1) 

`getMemberDeviceAddressesBySigningPaths`'s inner `evaluate()` function recurses into every element of `or`, `and`, `r of set`, and `weighted and` nodes with no depth limit, no complexity counter, and no protection against extremely deep nesting: [3](#0-2) 

This is unlike the analogous evaluator in `definition.js`, `validateDefinition`, which increments a `complexity`/`count_ops` counter on every call and bails out once `constants.MAX_COMPLEXITY`/`MAX_OPS` is exceeded: [4](#0-3) . `getMemberDeviceAddressesBySigningPaths` has no equivalent guard and runs first, ahead of the bounded validator, so a deeply nested (e.g., thousands of levels of `["and", [ ["and", [...]] ]]`) template will drive plain synchronous JS recursion to a `RangeError: Maximum call stack size exceeded`, which is an uncaught exception (the `try/catch` in `validateAddressDefinitionTemplate` only wraps the call, but a `RangeError` thrown deep in recursion is caught by that same `try` — however, if nesting is large enough it can also cause significant CPU/memory usage before failing, and in some JS engines/configurations a stack overflow can trigger a process abort rather than a catchable exception, particularly if it occurs during V8 GC/CPU-bound synchronous work that blocks the wallet's event loop for an extended period).

### Impact Explanation
A paired device (a normal wallet/device pairing partner, no special privileges required beyond being paired for one's own wallet, analogous to the CVE's "high privileged" DDL actor operating within a supported protocol) can send a single `create_new_shared_address` message with a deeply nested `address_definition_template` to hang or crash the receiving wallet process before any complexity limit is applied, denying availability of the wallet (a complete DoS against that instance), matching the CVE's core impact class (Availability-only DoS via a crafted structural/definition input processed by a privileged-but-limited actor).

### Likelihood Explanation
The message path is reachable by any correspondent device that has been paired for peer-to-peer messaging (a realistic and common trust boundary in ocore-based wallets), the payload structure is fully attacker-controlled JSON/array data, and no size/depth limit is checked prior to the vulnerable recursive `evaluate()` call, making exploitation straightforward once paired.

### Recommendation
Add a recursion depth limit (and/or iterative traversal) to `getMemberDeviceAddressesBySigningPaths`'s `evaluate()` function, mirroring the `MAX_DEPTH`/complexity checks already used in `Definition.validateDefinition` and `aa_validation.js`'s `validate()`, and reject templates whose structural depth or element counts exceed those limits before any recursive processing begins.

### Proof of Concept
A paired device sends a `create_new_shared_address` message with:
```json
{
  "address_definition_template": ["and", [["and", [["and", [ /* ...repeated thousands of times... */ ["address", "$address@DEVICE_ADDRESS"]]]]]]]
}
```
This is delivered to `wallet.js`'s `create_new_shared_address` handler, which calls `validateAddressDefinitionTemplate`, which calls `getMemberDeviceAddressesBySigningPaths` and recurses through every nested `and` level before any complexity check runs, exhausting the JS call stack. [1](#0-0) [3](#0-2)

### Citations

**File:** wallet.js (L197-212)
```javascript
			case "create_new_shared_address":
				// {address_definition_template: [...]}
				if (!ValidationUtils.isArrayOfLength(body.address_definition_template, 2))
					return callbacks.ifError("no address definition template");
				walletDefinedByAddresses.validateAddressDefinitionTemplate(
					body.address_definition_template, from_address, 
					function(err, assocMemberDeviceAddressesBySigningPaths){
						if (err)
							return callbacks.ifError(err);
						// this event should trigger a confirmatin dialog, user needs to approve creation of the shared address and choose his 
						// own address that is to become a member of the shared address
						eventBus.emit("create_new_shared_address", body.address_definition_template, assocMemberDeviceAddressesBySigningPaths);
						callbacks.ifOk();
					}
				);
				break;
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

**File:** wallet_defined_by_addresses.js (L481-516)
```javascript
function validateAddressDefinitionTemplate(arrDefinitionTemplate, from_address, handleResult){
	try{
		var assocMemberDeviceAddressesBySigningPaths = getMemberDeviceAddressesBySigningPaths(arrDefinitionTemplate);
	}
	catch (e) {
		return handleResult("failed to get member device addresses of new shared address: " + e.toString());
	}
	var arrDeviceAddresses = _.uniq(_.values(assocMemberDeviceAddressesBySigningPaths));
	if (arrDeviceAddresses.length < 2)
		return handleResult("less than 2 member devices");
	if (arrDeviceAddresses.indexOf(device.getMyDeviceAddress()) === - 1)
		return handleResult("my device address not mentioned in the definition");
	if (arrDeviceAddresses.indexOf(from_address) === - 1)
		return handleResult("sender device address not mentioned in the definition");
	
	var params = {};
	// to fill the template for validation, assign my device address (without leading 0) to all member devices 
	// (we need just any valid address with a definition)
	var fake_address = device.getMyDeviceAddress().substr(1);
	arrDeviceAddresses.forEach(function(device_address){
		params['address@'+device_address] = fake_address;
	});
	try{
		var arrFakeDefinition = Definition.replaceInTemplate(arrDefinitionTemplate, params);
	}
	catch(e){
		return handleResult(e.toString());
	}
	var objFakeUnit = {authors: [{address: fake_address, definition: ["sig", {pubkey: device.getMyDevicePubKey()}]}]};
	var objFakeValidationState = {last_ball_mci: MAX_INT32};
	Definition.validateDefinition(db, arrFakeDefinition, objFakeUnit, objFakeValidationState, null, false, function(err){
		if (err)
			return handleResult(err);
		handleResult(null, assocMemberDeviceAddressesBySigningPaths);
	});
}
```

**File:** definition.js (L103-111)
```javascript
	function evaluate(arr, path, bInNegation, cb){
		complexity++;
		count_ops++;
		if (complexity > constants.MAX_COMPLEXITY)
			return cb("complexity exceeded at "+path);
		if (count_ops > constants.MAX_OPS)
			return cb("number of ops exceeded at "+path);
		if (objValidationState.max_complexity && objValidationState.complexity + complexity > objValidationState.max_complexity)
			return cb(`custom complexity limit ${objValidationState.max_complexity} exceeded at ${path}`);
```
