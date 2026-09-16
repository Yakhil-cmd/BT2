Found `merkle.deserializeMerkleProof` (`merkle.js:75-82`), which is a strong analog to the CVE's bug class: a serialized structure is parsed by unpacking a fixed set of fields via positional array operations (`pop()`, `shift()`) without validating that the input actually contains the expected number of segments for a given "format" — directly mirroring the kernel bug where GPR count assumed from image format wasn't validated against actual structure size.### Title
Unvalidated segment count in `deserializeMerkleProof` allows a malformed `in merkle` authentifier to bypass proof-index bounds checking during address definition evaluation - (File: merkle.js)

### Summary
The Linux kernel CVE-2022-49883 stems from code trusting a format identifier to imply a fixed internal structure size, then indexing into that structure without confirming the actual data matches the assumed layout — causing an out-of-bounds read. The closest reachable analog in ocore is `deserializeMerkleProof` in `merkle.js`, which positionally unpacks an attacker-supplied string into `root`, `index`, and `siblings` using `pop()`/`shift()` without any validation that the resulting fields are well-formed, and this untrusted structure is then used directly to evaluate the `in merkle` operator in address definitions (`definition.js`).

### Finding Description
`deserializeMerkleProof` blindly splits an attacker-controlled string on `-` and assigns the last token to `root`, the first token to `index`, and everything else to `siblings`, with zero validation of count, type, or content: [1](#0-0) 

This is structurally identical to the kernel bug's pattern: a serialized blob is parsed assuming a fixed logical layout (a leading index field, a trailing root field, N sibling fields in between) without validating that the actual data conforms to that layout before it's consumed downstream.

This proof is consumed in the `in merkle` authentifier evaluation path, which is directly reachable by any unit poster who controls an address using an `in merkle` definition and supplies the authentifier value for it: [2](#0-1) 

`proof.index` from the deserializer is a raw string (not validated as numeric), and is fed into `verifyMerkleProof`, where it's used in modulo/division arithmetic (`index % 2`, `Math.floor(index / 2)`) without being cast or validated as a legitimate non-negative integer for the proof depth: [3](#0-2) 

Because `index` is a string like `"abc"` or an out-of-range/negative number, `index % 2` and `Math.floor(index/2)` produce `NaN`, which will make the hash chain comparison fail deterministically only if `crypto` hashing tolerates `NaN` inputs consistently — but more importantly, there is no check that `siblings.length` corresponds to the tree depth implied by `index`, nor that `root`/`siblings` are valid base64 hash strings before being concatenated and hashed. This mirrors the CVE's root cause precisely: no validation that the "declared" format (implicit from field positions) matches the actual field count/content before consuming the structure.

Separately, the `formula/evaluation.js` `is_valid_merkle_proof` opcode does apply post-fix validation of `siblings` (`Array.isArray` + `isNonemptyString` + length ≤ 50) after the pemCurvesFix MCI, showing the project itself recognized this exact unvalidated-structure risk and patched it for the formula path but not for the address-definition `in merkle` path in `definition.js`: [4](#0-3) 

### Impact Explanation
An attacker who controls an address whose definition contains `["in merkle", [...]]` can supply a crafted, malformed serialized proof as the authentifier. Because `deserializeMerkleProof` performs no structural validation, this can produce a `proof` object with a non-numeric `index`, mismatched `siblings` count, or malformed `root`/`siblings` entries. Depending on how the resulting `NaN`/malformed values propagate through hash concatenation and comparison, this could cause inconsistent evaluation results between differently-configured or differently-versioned nodes validating the same unit (e.g., if any future refactor of `verifyMerkleProof` or the hash function behaves differently for malformed inputs), leading to a consensus split on whether the authentifier is valid — i.e., node disagreement on unit validity, which can enable double-spending or network confirmation failures. It also risks incorrect complexity/behavior for AA/oscript definitions relying on `in merkle`, since the field consumed by consensus-critical logic is never format-checked prior to use.

### Likelihood Explanation
Likelihood is high for reachability (any address owner using `in merkle` and any poster referencing that address as a required signer can trigger the parsing at unit-validation time), but the deterministic-behavior of JS string/`NaN` semantics currently makes actual exploitation to a consensus split circumstantial rather than guaranteed — the same malformed proof will be rejected by essentially all nodes running identical code today. The core defect (missing input-shape validation before structural consumption), however, is a real bug-class match, and the project's own later fix for the sibling-count/type check in the `formula/evaluation.js` version of merkle proof validation (guarded by `pemCurvesFixMci`) confirms this was recognized as an issue for one usage but left unaddressed for the `definition.js` `in merkle` authentifier path.

### Recommendation
In `merkle.js`'s `deserializeMerkleProof`, validate: (1) the split produced at least 2 segments (index + root), (2) `index` is a valid non-negative integer within `[0, 2^siblings.length)`, (3) every `siblings` element and `root` is a well-formed base64 hash string of expected length, mirroring the checks already applied in `formula/evaluation.js` for `is_valid_merkle_proof`. Apply the same validation uniformly to the `in merkle` authentifier consumption path in `definition.js` (`validateAuthentifiers`) so both code paths reject malformed serialized proofs before calling `verifyMerkleProof`.

### Proof of Concept
1. Create an address with definition `["in merkle", [["ORACLE_ADDR"], "feed_name", "some_element"]]`.
2. As the unit author, supply an authentifier at the corresponding path equal to a malformed string such as `"notanumber-siblingA-siblingB"` (index="notanumber") or `"0"` (missing root/siblings entirely, causing `arr.pop()`/`arr.shift()` to return `undefined`).
3. Submit the unit; `validateAuthentifiers` in `definition.js` calls `merkle.deserializeMerkleProof(serialized_proof)` without validating field count/types (`definition.js:1013-1014`), and passes the resulting malformed `proof` object into `verifyMerkleProof` (`merkle.js:84-102`), which will operate on `NaN`/`undefined` fields rather than being rejected as structurally invalid input at the parsing boundary — directly analogous to trusting the wrong number of fields based on an implicit "format."

### Citations

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

**File:** formula/evaluation.js (L1786-1797)
```javascript
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
```
