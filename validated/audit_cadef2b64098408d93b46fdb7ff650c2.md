### Title
Unhandled TypeError from unvalidated authentifier type in `in merkle` definition evaluation — ([File: definition.js])

### Summary
`validateAuthentifiers()`'s `'in merkle'` branch takes the raw authentifier value supplied by the unit's author and passes it directly to `merkle.deserializeMerkleProof()` without checking that it is a string, similar to how GStreamer's `subrip_unescape_formatting` dereferenced attacker-controlled subtitle data without a NULL check.

### Finding Description
In `definition.js`, the `'in merkle'` case of the authentifier-evaluation function only rejects a *falsy* authentifier value, not a non-string one: [1](#0-0) 

```
case 'in merkle':
    if (!assocAuthentifiers[path])
        return cb2(false);
    ...
    var serialized_proof = assocAuthentifiers[path];
    var proof = merkle.deserializeMerkleProof(serialized_proof);
    if (!merkle.verifyMerkleProof(element, proof)){ ... }
```

`assocAuthentifiers` is built from the `authentifiers` map that an unprivileged unit poster supplies inside `unit.authors[].authentifiers` for any address that uses an `in merkle` clause in its definition (a definition the poster can freely construct and register, or that any counterparty can require them to satisfy). Because the check is `if (!assocAuthentifiers[path])`, any *truthy but non-string* value — a number, an array, or an object — passes the guard and is forwarded to `merkle.deserializeMerkleProof()`: [2](#0-1) 

```
function deserializeMerkleProof(serialized_proof){
	var arr = serialized_proof.split("-");
	...
}
```

Calling `.split` on a non-string value (e.g. a plain object or number) throws `TypeError: serialized_proof.split is not a function`. This call is **not** wrapped in a `try/catch`, unlike the sibling `merkle.verifyMerkleProof()` call a few lines below, or the analogous `is_valid_merkle_proof` formula opcode in `formula/evaluation.js` which at least wraps the verify step in `try { ... } catch(e) { res = false; }` (though it too calls `deserializeMerkleProof` outside that guard): [3](#0-2) 

The uncaught exception propagates synchronously out of `evaluate()` during unit/authentifier validation — exactly the same bug class as the reported subparse NULL-pointer dereference: attacker-supplied, insufficiently type-checked data reaches a low-level parsing routine that assumes a valid shape and crashes when it isn't.

### Impact Explanation
Any full node validating a unit whose signer address definition contains an `'in merkle'` clause, where the attacker supplies a non-string but truthy authentifier value at that path, will hit an unhandled `TypeError` inside the synchronous validation call stack. Because all conformant nodes run the same validation code, a single maliciously crafted unit posted to the network can crash every node that attempts to validate it at the same point, producing an uncontrolled denial-of-service on unit/AA validation and preventing the network from confirming new units built on top of it, or causing divergent behavior between nodes whose call stacks catch the exception at different levels versus nodes that crash outright.

### Likelihood Explanation
The `'in merkle'` opcode is a documented, first-class part of the definition language, and any user can define an address using it and then post a unit purporting to satisfy it. Supplying a non-string (object/array/number) authentifier value instead of a proof string requires no special privilege — it's a standard unit-construction step available to any unprivileged unit poster.

### Recommendation
In `definition.js`'s `'in merkle'` branch, explicitly require `typeof assocAuthentifiers[path] === 'string'` before calling `merkle.deserializeMerkleProof()`, and/or wrap the `deserializeMerkleProof`/`verifyMerkleProof` pair in a `try/catch` that resolves to `cb2(false)` on any exception, mirroring the defensive pattern already used for `verifyMerkleProof` itself.

### Proof of Concept
1. Register/use an address whose definition includes `['in merkle', [[oracleAddress], 'feed_name', 'element']]`.
2. Construct a unit signed by that address where `authors[].authentifiers[path]` is set to a truthy non-string value, e.g. `{}` or `123`, instead of the expected serialized proof string.
3. Submit the unit for validation; `validateAuthentifiers()` reaches the `'in merkle'` case, passes the non-string value to `merkle.deserializeMerkleProof()`, which throws `TypeError` when calling `.split` on it, crashing the validating process (no surrounding `try/catch` in this branch).

### Citations

**File:** definition.js (L1004-1020)
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
				dataFeeds.dataFeedExists(arrAddresses, feed_name, '=', proof.root, min_mci, objValidationState.last_ball_mci, false, cb2);
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

**File:** formula/evaluation.js (L1785-1804)
```javascript
						else if (typeof proof === 'string') {
							if (proof.length > 1024)
								return setFatalError("proof is too large", { arr }, false, cb);
							objProof = merkle.deserializeMerkleProof(proof);
						}
						else // can't be valid proof
							return cb(false);
						if (bPostPemCurvesFix) {
							if (!Array.isArray(objProof.siblings) || !objProof.siblings.every(ValidationUtils.isNonemptyString))
								return cb(false);
							if (objProof.siblings.length > 50)
								return cb(false);
						}
						try {
							res = merkle.verifyMerkleProof(element, objProof);
						}
						catch (e) {
							res = false;
						}
						cb(res);
```
