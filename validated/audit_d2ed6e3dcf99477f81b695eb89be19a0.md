### Title
Stack overflow via unbounded recursive definition traversal before depth-limited validation - (File: wallet_defined_by_addresses.js)

### Summary
The CVE describes a stack overflow in GPAC's `gf_opus_read_length`, where a length-prefixed structure is recursively parsed without a recursion-depth guard, letting a crafted file drive the call stack to exhaust and crash the process. The analogous bug class in ocore is a recursive parser/traversal function over an attacker-supplied, self-referential array structure (address definition) that has no recursion-depth limit, and that runs on a device-message input *before* the depth/complexity-limited validator is invoked.

### Finding Description
Address definitions in ocore are nested arrays such as `["or", [...]]`, `["and", [...]]`, `["r of set", {set:[...]}]`, `["weighted and", {set:[...]}]`. The canonical validator, `validateDefinition`'s inner `evaluate()` in `definition.js`, enforces `MAX_COMPLEXITY`/`MAX_OPS` limits on every recursive step: [1](#0-0) 

However, `wallet_defined_by_addresses.js` exposes a helper, `extractAddressPathsFromDefinition`, that performs the *same* recursive descent over `or`/`and`/`r of set`/`weighted and` nodes with **no depth counter, no complexity limit, and no iteration cap**: [2](#0-1) 

This function is invoked directly inside `handleNewSharedAddress`, the handler for an incoming `new_shared_address` device message body (`{address, definition, signers}`), and critically it is called *before* `validateAddressDefinition` (the safe, depth/complexity-limited path) is ever reached: [3](#0-2) 

Because `body.definition` is attacker-controlled JSON coming straight from a paired device's message, an attacker can construct a definition consisting of thousands of nested `["and", [["and", [...]], ...]]` (or `or`/`r of set`/`weighted and`) levels. `traverse()` will recurse once per nesting level with no bound, exhausting the JS call stack (`RangeError: Maximum call stack size exceeded`) before the length/complexity checks in `Definition.validateDefinition` (which are async, `MAX_DEPTH`/`MAX_COMPLEXITY`-bounded, and interrupt the call stack via `setImmediate`) ever run.

The same unguarded-recursion pattern also exists in `getMemberDeviceAddressesBySigningPaths` (`wallet_defined_by_addresses.js`) and `getDeviceAddressesBySigningPaths` (`wallet_defined_by_keys.js`), and in `hasReferences` in `definition.js`, all of which walk untrusted definition trees without depth limiting: [4](#0-3) [5](#0-4) 

By contrast, code paths that are hardened against this exact issue (`definition.js` `evaluate`, `aa_validation.js` `validate`, `formula/validation.js` `evaluate`) all track `depth`/`complexity`/`count` and periodically yield via `setImmediate` specifically "to avoid extra long call stacks to prevent Maximum call stack size exceeded": [6](#0-5) [7](#0-6) 

This shows the project is aware of and defends against this bug class elsewhere, but the wallet-shared-address message-handling code path was missed.

### Impact Explanation
A stack overflow crashes the Node.js process handling the device message (denial of service against the receiving wallet/hub-connected node). This matches the CVE's DoS impact class. It does not by itself cause double-spend/inflation, but it satisfies the "node unable to process/confirm" impact bucket for a single targeted node reachable by any paired device (a normal, low-privilege actor in the ocore threat model, since device pairing/correspondent relationships are routinely established between wallet users). Repeated attacks can be used to reliably crash a victim's wallet process whenever it tries to accept a `new_shared_address` proposal from a paired device.

### Likelihood Explanation
Likelihood is high for any wallet that automatically processes `new_shared_address` messages from a paired correspondent device (a standard, expected wallet feature for multi-sig/shared-address setups). Building a several-thousand-level-deep nested array in JSON is trivial and requires no special privileges — only an existing device pairing, which is a normal deployment scenario for wallets (e.g., multi-device or multi-sig setups), satisfying the "paired device" reachability required by the scoping rules.

### Recommendation
Add an explicit recursion-depth limit (mirroring `MAX_DEPTH`/`MAX_COMPLEXITY` used in `Definition.validateDefinition`) to `extractAddressPathsFromDefinition`, `getMemberDeviceAddressesBySigningPaths`, `getDeviceAddressesBySigningPaths`, and `hasReferences`, bailing out early once a depth threshold is exceeded. Alternatively/additionally, call `Definition.validateDefinition` (or an equivalent depth/complexity pre-check) on `body.definition` in `handleNewSharedAddress` *before* calling `extractAddressPathsFromDefinition`, so that malformed, over-nested definitions are rejected by the bounded validator prior to any unbounded recursive traversal.

### Proof of Concept
1. Attacker pairs a device with the victim (or is already a correspondent).
2. Attacker sends a `new_shared_address` device message with a body like:
```json
{
  "address": "<40-char base32 chash of the crafted definition>",
  "definition": ["and", [ ... nested "and" wrapping 50,000 times ... , ["address", "VICTIMADDRESS...."]]],
  "signers": { "r.0.0.0. ... ": { "address": "VICTIMADDRESS....", "device_address": "..." } }
}
```
3. On receipt, `wallet.js`'s message dispatcher routes this to `handleNewSharedAddress`, which calls `extractAddressPathsFromDefinition(body.definition)` at [8](#0-7) , recursing once per nested `and` level via the unguarded `traverse()` function.
4. With sufficient nesting depth (tunable to exceed Node's default stack size), the process throws `RangeError: Maximum call stack size exceeded`, crashing/killing the victim's node process before `validateAddressDefinition`'s bounded checks are ever reached.

### Citations

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

**File:** definition.js (L1504-1522)
```javascript
function hasReferences(arrDefinition){
	
	function evaluate(arr){
		var op = arr[0];
		var args = arr[1];
	
		switch(op){
			case 'or':
			case 'and':
				for (var i=0; i<args.length; i++)
					if (evaluate(args[i]))
						return true;
				return false;
				
			case 'r of set':
				for (var i=0; i<args.set.length; i++)
					if (evaluate(args.set[i]))
						return true;
				return false;
```

**File:** wallet_defined_by_addresses.js (L339-375)
```javascript
function extractAddressPathsFromDefinition(arrDefinition) {
	var result = {};
	function traverse(arr, path) {
		if (!Array.isArray(arr) || arr.length < 2) return;
		var op = arr[0];
		var args = arr[1];
		switch (op) {
			case 'or':
			case 'and':
				if (Array.isArray(args))
					for (var i = 0; i < args.length; i++)
						traverse(args[i], path + '.' + i);
				break;
			case 'r of set':
				if (args && Array.isArray(args.set))
					for (var i = 0; i < args.set.length; i++)
						traverse(args.set[i], path + '.' + i);
				break;
			case 'weighted and':
				if (args && Array.isArray(args.set))
					for (var i = 0; i < args.set.length; i++)
						traverse(args.set[i].value, path + '.' + i);
				break;
			case 'address':
				result[path] = args;
				break;
			case 'hash':
				result[path] = 'secret';
				break;
			case 'in merkle':
				result[path] = ''; // empty address
				break;
		}
	}
	traverse(arrDefinition, 'r');
	return result;
}
```

**File:** wallet_defined_by_addresses.js (L378-415)
```javascript
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

**File:** aa_validation.js (L598-603)
```javascript
	function validate(obj, name, path, locals, depth, cb, bValueOnly) {
		if (depth > MAX_DEPTH)
			return cb("max depth reached");
		count++;
		if (count % 100 === 0) // interrupt the call stack
			return setImmediate(validate, obj, name, path, locals, depth, cb, bValueOnly);
```

**File:** formula/validation.js (L272-276)
```javascript
	function evaluate(arr, cb, bTopLevel) {
		count++;
		if (count % 100 === 0) // avoid extra long call stacks to prevent Maximum call stack size exceeded
			return (typeof setImmediate === 'function') ? setImmediate(evaluate, arr, cb) : setTimeout(evaluate, 0, arr, cb);
		depth++;
```
