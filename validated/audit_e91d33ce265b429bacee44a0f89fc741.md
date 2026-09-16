### Title
Uncontrolled recursion in `extractAddressPathsFromDefinition`/`traverse` causes stack exhaustion on attacker-supplied shared-address definitions - (File: wallet_defined_by_addresses.js)

### Summary
`wallet_defined_by_addresses.js`'s `handleNewSharedAddress` processes a `new_shared_address` device message body containing an attacker-controlled `body.definition` (an address-definition AST). Before any complexity/depth-bounded validation is performed, it calls `extractAddressPathsFromDefinition(body.definition)`, whose internal `traverse` function recurses into nested `'or'`/`'and'`/`'r of set'`/`'weighted and'` branches with no depth limit and no size limit, analogous to Go's unbounded `Glob` recursion on many path separators (CVE-2022-30630).

### Finding Description
`handleNewSharedAddress` performs only shallow structural checks (`isArrayOfLength`, hash match, signer object checks) before calling: [1](#0-0) 
which invokes the recursive `traverse` helper: [2](#0-1) 

Unlike the address-definition evaluators in `definition.js` (`evaluate` in `validateDefinition`/`validateAuthentifiers`), which increment a `complexity`/`count_ops` counter and bail out via `MAX_COMPLEXITY`/`MAX_OPS` checks on every recursive call: [3](#0-2) 
`traverse` in `extractAddressPathsFromDefinition` has **no depth counter, no complexity limit, and no node-count limit**. It simply recurses through every `or`/`and`/`r of set`/`weighted and` nesting level in the definition tree. Because `handleNewSharedAddress` calls `extractAddressPathsFromDefinition` *before* `validateAddressDefinition` (which eventually calls `Definition.validateDefinition` with its bounded `evaluate`): [4](#0-3) 
an attacker can craft a definition consisting of thousands of nested `["and", [...]]` (or `"or"`) arrays and trigger deep, unbounded JS recursion in `traverse` before the bounded validator ever runs.

`objectHash.getChash160(body.definition)` (also called earlier) may itself need to serialize/traverse the whole structure, but it is `traverse` in `extractAddressPathsFromDefinition` that has zero depth cap, making it the practical crash point matching the "uncontrolled recursion via many nested separators/elements" bug class from the Go report.

### Impact Explanation
`handleNewSharedAddress` is reachable from any correspondent/paired device that can send a `new_shared_address` message — this matches the allowed "paired device" reachable-surface category. A crafted deeply-nested definition causes a JS call-stack exhaustion (`RangeError: Maximum call stack size exceeded`), crashing or hanging the node process handling the message. Since shared-address creation flows are part of wallet/contract message handling used for multi-sig wallets, a paired device (which may be semi-trusted but still "unprivileged" from the node's security-boundary perspective) can crash a peer's wallet process, denying wallet/AA functionality that depends on that process (fund freezing/DoS of node availability for that wallet instance).

### Likelihood Explanation
Likelihood is high for any node that accepts `new_shared_address` messages from correspondent devices: the attacker only needs to construct a plain JSON array with deep `and`/`or` nesting (no valid signature or complexity budget is required to reach `extractAddressPathsFromDefinition`, since it runs prior to the bounded `Definition.validateDefinition`). No cryptographic material or special privilege is needed — just an existing device pairing, which is a normal condition for wallet use.

### Recommendation
Add a depth counter (and/or a total node-count budget) to `traverse` in `extractAddressPathsFromDefinition`, mirroring the `MAX_DEPTH`/`MAX_COMPLEXITY` checks already used in `definition.js`'s `evaluate`, and reject/return early once the limit is exceeded. Alternatively, move `extractAddressPathsFromDefinition` to run only after `Definition.validateDefinition` has confirmed the definition is within complexity/depth bounds, so no unbounded traversal of untrusted structures happens first.

### Proof of Concept
1. As a paired/correspondent device, send a `new_shared_address` chat message with a `body.definition` such as:
```js
let def = ['sig', {pubkey: 'AAAA...'}];
for (let i = 0; i < 100000; i++)
    def = ['and', [def]];
```
2. Set `body.address` to `objectHash.getChash160(def)`, and provide a `body.signers` object satisfying the earlier shallow checks.
3. Send this to a victim node's wallet listener that routes into `handleNewSharedAddress`.
4. `extractAddressPathsFromDefinition(body.definition)` recurses ~100000 levels deep in `traverse`, exceeding the JS call stack and crashing/throwing an uncaught `RangeError` in the message-handling process, before `validateAddressDefinition`'s bounded checks are ever reached. [5](#0-4)

### Citations

**File:** wallet_defined_by_addresses.js (L339-415)
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
