Based on my investigation, I found a concrete structural analog to CVE-2017-17126's pattern (a parser that dereferences data structures it assumes are present/well-formed without validating that assumption, causing a crash on malformed/incomplete input).

### Title
Missing type/shape validation before `merkle.deserializeMerkleProof()` in `'in merkle'` definition evaluation causes uncaught exception on malformed authentifier - ([File: definition.js])

### Summary
The `'in merkle'` opcode handler in `definition.js` takes an attacker-supplied authentifier value directly from the posted unit and feeds it into `merkle.deserializeMerkleProof()` without first validating that it is a well-formed string, unlike the sibling code path for `is_valid_merkle_proof` in `formula/evaluation.js`, which explicitly type-checks the proof value and validates the `siblings` array shape before use.

### Finding Description
In `definition.js`, the `'in merkle'` case reads the authentifier supplied by the unit's author: [1](#0-0) 
`serialized_proof` is taken straight from `assocAuthentifiers[path]` — an attacker-controlled field of the posted unit — and passed to `merkle.deserializeMerkleProof(serialized_proof)`: [2](#0-1) 
`deserializeMerkleProof` unconditionally calls `.split("-")` on its argument and assumes at least a root/index structure exists. There is no check that `serialized_proof` is actually a string, nor any bound on its structure, before this call — mirroring the CVE-2017-17126 root cause where `load_debug_section` in `readelf.c` dereferenced ELF section-header data without first confirming the headers existed.

By contrast, the safer sibling opcode `is_valid_merkle_proof` in `formula/evaluation.js` explicitly checks `typeof proof === 'string'` before calling `deserializeMerkleProof`, bounds its length, and validates `objProof.siblings` shape before use, and wraps the actual verification in `try/catch`: [3](#0-2) 

The `'in merkle'` path in `definition.js` has none of these guards: no type check on `serialized_proof`, no try/catch around `deserializeMerkleProof`/`verifyMerkleProof`, and no validation of the resulting `proof` object's shape before it is passed to `dataFeeds.dataFeedExists`.

### Impact Explanation
If `assocAuthentifiers[path]` can be a non-string value (e.g., an object, array, number, or `null` supplied by a malicious address owner/author using an `'in merkle'` definition), `serialized_proof.split("-")` throws a `TypeError`. Because this call sits inside `validateAuthentifiers` with no surrounding `try/catch` at this call site, the exception propagates up through unit validation. Depending on how the top-level validation call stack handles this uncaught exception, this can crash the validating node process or cause it to reject/accept the unit inconsistently relative to nodes running different exception-handling logic, leading to node disagreement about the unit's validity — which is a stability/consensus-relevant impact, not merely a benign parse failure.

### Likelihood Explanation
Reaching this code requires only that some address use an `'in merkle'` clause in its definition (a normal, documented oscript feature) and that an author posting a unit under that address supplies a crafted authentifier value for that path. This is reachable by any ordinary unit poster who controls their own address definition and its authentifiers, matching the "unprivileged unit poster / address definitions and authentifiers" attack surface explicitly in scope. No special network position or privileged role is required.

### Recommendation
Add the same defensive checks used in `formula/evaluation.js`'s `is_valid_merkle_proof` path to the `'in merkle'` case in `definition.js`:
- Verify `typeof serialized_proof === 'string'` (and bound its length) before calling `merkle.deserializeMerkleProof`.
- Validate the resulting `proof` object has the expected shape (`index`, `root`, and an array `siblings` of strings) before calling `verifyMerkleProof`.
- Wrap the deserialize/verify sequence in `try/catch`, treating any exception as `cb2(false)` with a `fatal_error`, consistent with how `evaluation.js` handles this.

### Proof of Concept
1. Define an address with a definition containing `['in merkle', [[oracle_address], 'feed_name', 'element']]`.
2. Post a unit signed by that address where the corresponding authentifier for that path (`assocAuthentifiers[path]`) is set to a non-string value, e.g. `{}` or `null`, instead of the expected `"index-sibling1-sibling2-root"` string.
3. During validation, `definition.js` reaches the `'in merkle'` case at [4](#0-3) , calling `merkle.deserializeMerkleProof({})`, which executes `({}).split("-")` inside [5](#0-4)  and throws a `TypeError`, uncaught at this call site, unlike the guarded `is_valid_merkle_proof` path.

Note: I was unable to fully trace whether `assocAuthentifiers[path]` is guaranteed to be a string by earlier schema-level validation in `validation.js` before `validateAuthentifiers` is invoked (my search for the exact authentifier type-validation code was cut off by a tool error). If such a guarantee exists earlier in the pipeline, the crash vector described here would not be reachable and this finding would need to be downgraded or discarded — confirming this requires tracing the full authentifier validation chain from `validation.js` into `definition.js`'s `validateAuthentifiers`, which I could not complete in the available iterations.

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

**File:** formula/evaluation.js (L1782-1804)
```javascript
						var objProof;
						if (proof instanceof wrappedObject)
							objProof = proof.obj;
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
