## Title
Uncaught exception via malformed merkle-proof authentifier crashes node during unit validation - (File: merkle.js)

### Summary
`merkle.deserializeMerkleProof()` blindly calls `.split("-")` on its input with no type check. It is reached from `definition.js`'s `evaluate()` for the `'in merkle'` opcode, where the string comes directly from `assocAuthentifiers[path]`, i.e., an attacker-controlled authentifier value supplied in a posted unit. If that value is not a string (or is otherwise malformed), the call throws an uncaught `TypeError`/`RangeError` outside of any `try/catch`, which is the JS-memory-safe analogue of the MavLink buffer-overflow DoS in CVE-2024-38951: a single crafted, unprivileged message causes the message-processing routine to crash instead of gracefully rejecting the bad input.

### Finding Description
The `'in merkle'` branch in `validateAuthentifiers`'s inner `evaluate()` function reads the caller-supplied authentifier for a given signing path and passes it straight to `merkle.deserializeMerkleProof`: [1](#0-0) 

`deserializeMerkleProof` performs no validation on its argument before calling `.split("-")`: [2](#0-1) 

`verifyMerkleProof` itself is defensively wrapped in a `try/catch` that returns `false` on any exception: [3](#0-2) 

However, `deserializeMerkleProof` is called *before* entering that `try` block, in `definition.js` line 1014, with no surrounding exception handling in `evaluate()`. `assocAuthentifiers` is built directly from `objUnit.authors[].authentifiers`, which are attacker-supplied values from the posted unit/AA trigger — there is no upstream type-check in `validation.js` forcing every authentifier value to be a string before definitions using `'in merkle'` conditions are evaluated (only `isNonemptyObject(author.authentifiers)` is asserted generally, not that every value is a string). If an author supplies a non-string (e.g., a number, `null`, an object, or an array) as the authentifier for a signing path bound to an `'in merkle'` condition, `serialized_proof.split` throws `TypeError: serialized_proof.split is not a function`, propagating up out of the async `evaluate` callback chain uncaught.

Because unit/AA-trigger validation runs inside the main node process (used by full nodes and light-vendor/hub nodes serving the network, as well as AA execution triggered from arbitrary AA triggers), an uncaught exception thrown synchronously from deep inside an `async.eachSeries`/callback chain during validation will not be caught by the calling code's own error handling and can crash the Node.js process (unhandled exception terminates the process by default), denying the network the ability to process/validate further units until restarted.

### Impact Explanation
A successful trigger causes an uncaught exception during unit/definition validation, terminating the Node.js process handling that unit. Because unit validation (and AA-trigger validation, which reuses the same `validateAuthentifiers`/`'in merkle'` path) is performed by every full node/hub that receives the crafted unit, a single posted unit exploiting an address with an `'in merkle'` condition (which the attacker themselves can define, since they control their own address definition and thus decide which signing paths carry `'in merkle'' conditions) can crash any node that attempts to validate it — this matches "a network unable to confirm new units" if propagated broadly, or at minimum denial of service against the validating node.

### Likelihood Explanation
The attacker fully controls: (1) their own address definition, so they can freely include an `['in merkle', ...]` condition on a chosen signing path, and (2) the `authentifiers` object supplied with their unit for that same address, so they can pass a non-string value for that path. No special privileges, coordination, or race conditions are needed — a single unprivileged unit poster can trigger this deterministically.

### Recommendation
- In `merkle.deserializeMerkleProof` (merkle.js), validate that `serialized_proof` is a non-empty string before calling `.split`, and return/throw a normal validation error otherwise.
- In `definition.js`'s `'in merkle'` evaluate branch, validate `typeof serialized_proof === 'string'` before calling `deserializeMerkleProof`, returning `cb2(false)`/a validation error rather than allowing an exception to propagate.
- Wrap the whole `'in merkle'` handling in a `try/catch` consistent with how `verifyMerkleProof` already defends itself, and audit other opcodes in the same `evaluate()` switch for similar "trust the type of authentifier value" assumptions.

### Proof of Concept
1. Attacker creates address `A` with definition `['sig', ...]`-analog but including at some signing path an `['in merkle', [[oracleAddr], 'feed', 'value']]` condition (this is the attacker's own address, so they fully control the definition).
2. Attacker crafts a unit where author `A`'s `authentifiers` object sets the value at that signing path to a non-string, e.g. `{ "r.1": 12345 }` or `{ "r.1": null }`, instead of the expected serialized merkle proof string.
3. Submits the unit to the network as an ordinary, unprivileged unit post (or as an AA trigger targeting an AA whose base address uses this definition pattern, if base_aa/asset conditions apply similarly).
4. On the receiving node, `validateAuthentifiers` → `evaluate()` reaches the `'in merkle'` case, executes `merkle.deserializeMerkleProof(12345)` (or `null`), which calls `(12345).split` / `null.split`, throwing a `TypeError` uncaught by any surrounding `try/catch` in the call chain — crashing the node process (or, depending on Node's unhandled-exception/domain handling, leaving the process in a broken state unable to continue validating units). [2](#0-1) [1](#0-0)

### Citations

**File:** definition.js (L1004-1019)
```javascript
			case 'in merkle':
				// ['in merkle', [['BASE32'], 'data feed name', 'expected value']]
				if (!assocAuthentifiers[path])
					return cb2(false);
				arrUsedPaths.push(path);
				var arrAddresses = args[0];
				var feed_name = args[1];
				var element = args[2];
				var min_mci = args[3] || 0;
				var serialized_proof = assocAuthentifiers[path];
				var proof = merkle.deserializeMerkleProof(serialized_proof);
			//	console.error('merkle root '+proof.root);
				if (!merkle.verifyMerkleProof(element, proof)){
					fatal_error = "bad merkle proof at path "+path;
					return cb2(false);
				}
```

**File:** merkle.js (L75-82)
```javascript
function deserializeMerkleProof(serialized_proof){
	var arr = serialized_proof.split("-");
	var proof = {};
	proof.root = arr.pop();
	proof.index = arr.shift();
	proof.siblings = arr;
	return proof;
}
```

**File:** merkle.js (L84-102)
```javascript
function verifyMerkleProof(element, proof){
	// Node-as-Leaf issue might matter in some cases
	try {
		var index = proof.index;
		var the_other_sibling = hash(element);
		for (var i = 0; i < proof.siblings.length; i++) {
			// this also works for duplicated trailing nodes
			if (index % 2 === 0)
				the_other_sibling = hash(the_other_sibling + proof.siblings[i]);
			else
				the_other_sibling = hash(proof.siblings[i] + the_other_sibling);
			index = Math.floor(index / 2);
		}
		return (the_other_sibling === proof.root);
	}
	catch (e){
		return false;
	}
}
```
