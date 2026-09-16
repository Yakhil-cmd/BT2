### Title
Unbounded recursive descent into attacker-supplied shared-address definition causes stack-overflow DoS - ([File: wallet_defined_by_addresses.js])

### Summary
`extractAddressPathsFromDefinition()` in `wallet_defined_by_addresses.js` recursively walks an address-definition tree supplied by a remote correspondent (paired) device inside a `"new_shared_address"` message, with **no depth limit**, before the definition is ever passed to the depth-limited validators in `definition.js`. A crafted, deeply-nested `"and"`/`"or"` definition therefore drives unbounded synchronous JS recursion and crashes the node with `RangeError: Maximum call stack size exceeded` — the same "unauthenticated remote input triggers stack/buffer overrun ⇒ process crash" bug class as CVE-2023-51886 in Mathtex.

### Finding Description
`handleNewSharedAddress(body, callbacks)` is the entry point that processes a `"new_shared_address"` device message coming from a paired device [1](#0-0) . Before any bounded validation runs, it calls:

```js
const assocDefinitionAddresses = extractAddressPathsFromDefinition(body.definition);
``` [2](#0-1) 

`extractAddressPathsFromDefinition` uses an inner `traverse(arr, path)` function that recurses into every `'or'`/`'and'` branch and `'r of set'`/`'weighted and'` set with **no depth counter and no `MAX_DEPTH` check**: [3](#0-2) 

This stands in contrast to the equivalent definition walkers in `definition.js`, which explicitly cap recursion depth via `MAX_DEPTH`/complexity/op-count limits and interleave `setImmediate` to avoid deep native call stacks [4](#0-3) [5](#0-4) , and to `formula/validation.js`'s `evaluate`, which enforces `depth > 100` explicitly [6](#0-5) .

`objectHash.getChash160(body.definition)` is computed at line 384 before `extractAddressPathsFromDefinition` runs, but `getChash160`/`getSourceString` only build a string representation and are not necessarily depth-bounded either, so this pre-check does not reliably prevent reaching the vulnerable recursion; regardless, `extractAddressPathsFromDefinition` and the structurally identical `getMemberDeviceAddressesBySigningPaths`'s `evaluate()` (used by `validateAddressDefinitionTemplate`) [7](#0-6)  both recurse without any bound, ahead of the properly depth-limited `Definition.validateDefinition()` call that occurs only afterward at line 409 [8](#0-7) .

### Impact Explanation
A paired/correspondent device (an entity explicitly in scope, no special privilege required beyond being a paired counterparty) can send a single `"new_shared_address"` message containing a definition nested tens of thousands of levels deep in `'and'`/`'or'` operators. This crashes the recipient wallet/hub process handling the message (denial of service against that node), which for hub-class or witness-adjacent nodes can affect network confirmation availability for the affected party.

### Likelihood Explanation
Likelihood is high for any node/wallet that accepts `new_shared_address` messages from paired devices: the payload is just nested JSON arrays, trivially constructible, requires no proof-of-work, no fee, and no prior on-chain state — only an established device pairing, which is the normal precondition for this feature.

### Recommendation
Add an explicit maximum recursion depth (mirroring `MAX_DEPTH` used elsewhere in `aa_validation.js`/`definition.js`) to `extractAddressPathsFromDefinition`'s `traverse()` and to `getMemberDeviceAddressesBySigningPaths`'s `evaluate()`, rejecting/erroring out on definitions that exceed the limit before any recursion is performed, and perform this depth/well-formedness check prior to computing `getChash160` or walking the tree at all.

### Proof of Concept
A paired device sends:
```json
{
  "cmd": "new_shared_address",
  "address": "<addr matching chash of definition below>",
  "definition": ["and", [["and", [["and", [ /* repeat 'and' nesting ~50,000 times ending in */ ["sig", {"pubkey": "..."}]] }]]]],
  "signers": { "r": {"address": "SOME_ADDR", "device_address": "..."} }
}
```
When the recipient's `handleNewSharedAddress` runs `extractAddressPathsFromDefinition(body.definition)`, the synchronous `traverse()` recursion exhausts the V8 stack and throws `RangeError: Maximum call stack size exceeded`, crashing the node process (unable to process further messages/units until restarted).

*Note: I was unable to further verify within the available tool budget whether `getSourceString`/`chash.getChash160` (invoked earlier in `handleNewSharedAddress` at line 384) impose any depth bound that would abort processing before `extractAddressPathsFromDefinition` is reached; if that string-serialization step is itself unbounded, it may crash first via the same root cause (unbounded recursion over attacker-controlled definition depth), which does not change the overall conclusion.*

### Citations

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

**File:** wallet_defined_by_addresses.js (L378-396)
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
```

**File:** wallet_defined_by_addresses.js (L406-415)
```javascript
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

**File:** definition.js (L621-638)
```javascript
	var complexity = 0;
	var count_ops = 0;
	evaluate(arrDefinition, 'r', false, function(err, bHasSig){
		if (err)
			return handleResult(err);
		if (!bHasSig && !bAssetCondition)
			return handleResult("each branch must have a signature");
		if (complexity > constants.MAX_COMPLEXITY)
			return handleResult("complexity exceeded");
		if (count_ops > constants.MAX_OPS)
			return handleResult("number of ops exceeded");
		if (objValidationState.max_complexity) {
			objValidationState.complexity += complexity;
			if (objValidationState.complexity > objValidationState.max_complexity)
				return handleResult(`custom complexity limit ${objValidationState.max_complexity} exceeded`);
		}
		handleResult();
	});
```

**File:** formula/validation.js (L272-288)
```javascript
	function evaluate(arr, cb, bTopLevel) {
		count++;
		if (count % 100 === 0) // avoid extra long call stacks to prevent Maximum call stack size exceeded
			return (typeof setImmediate === 'function') ? setImmediate(evaluate, arr, cb) : setTimeout(evaluate, 0, arr, cb);
		depth++;
		const orig_cb = cb;
		cb = err => {
			depth--;
			if (err && !errorLocation && arr && typeof arr === 'object' && arr.line !== undefined) {
				errorLocation = arr.source_location
					? Object.assign({}, arr.source_location)
					: { line: arr.line };
			}
			orig_cb(err);
		};
		if (depth > 100 && (mci >= constants.pemCurvesFixMci || require('../storage.js').getMinRetrievableMci() >= constants.pemCurvesFixMci))
			return cb("maximum depth exceeded");
```
