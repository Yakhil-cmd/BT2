### Title
Unbounded Merkle-proof siblings in `in merkle` address-definition authentifier allow CPU-exhaustion DoS - ([File: definition.js])

### Summary
The external report describes an FFmpeg `decode_frame` (`libavcodec/tiff.c`) bug where a size/count field taken from untrusted input is used to drive parsing/looping without being bounds-checked, causing a denial of service. In `ocore`, the `in merkle` address-definition operator has the same bug-class: it deserializes and verifies a Merkle proof supplied directly by the unit's author as an authentifier, with no cap on the number of proof siblings, unlike the sibling `is_valid_merkle_proof` oscript function which was hardened with explicit size limits.

### Finding Description
`definition.js`'s `evaluate()` handles the `in merkle` definition op by taking the raw authentifier string supplied for that definition path and passing it straight into `merkle.deserializeMerkleProof()` and then `merkle.verifyMerkleProof()`: [1](#0-0) 

`merkle.deserializeMerkleProof()` simply splits the string on `"-"` and treats everything except the first and last token as `siblings`, with no limit on how many tokens/siblings can be present: [2](#0-1) 

`verifyMerkleProof()` then loops once per sibling, computing a SHA-256 hash per iteration: [3](#0-2) 

By contrast, the `is_valid_merkle_proof` oscript function — which consumes a structurally identical proof — was explicitly hardened after being identified as a resource-exhaustion vector: it caps the serialized proof string to 1024 characters and (post `bPostPemCurvesFix`) caps `siblings.length` to 50: [4](#0-3) 

The `in merkle` path in `definition.js` has no equivalent length/array-size validation before calling `verifyMerkleProof`, so the size of the "loop count" (number of siblings) is fully attacker-controlled and unbounded, exactly like the unchecked tile/strip-count field in the FFmpeg TIFF decoder that led to the referenced CVE-class DoS.

### Impact Explanation
An address whose definition includes an `in merkle` clause can be triggered by posting a unit whose authentifier for that path is an extremely long, dash-separated string (arbitrarily many "sibling" tokens, bounded only by overall message/unit size limits, which are much larger than 1024 bytes and not specifically restrictive here). Every full or light node that validates this unit must run `verifyMerkleProof`, which performs one SHA-256 hash per sibling token — an attacker can force each validating node to perform a very large number of hash operations for a single posted unit. This is a CPU-based denial-of-service reachable by any unpriviledged unit poster who can construct an address with an `in merkle` definition, causing nodes to spend disproportionate CPU during unit validation, potentially delaying or stalling processing of other units (network unable to confirm new units in a timely manner).

### Likelihood Explanation
Likelihood is Medium-High: crafting an address definition containing `in merkle` is straightforward (it is a documented definition operator), and supplying an oversized authentifier string requires no special privileges — only economic cost (unit fees for message/authentifier size), which is far cheaper than the CPU cost imposed on every validating node, especially since (unlike `is_valid_merkle_proof`) there is no explicit smaller cap on proof size in this validation path.

### Recommendation
Apply the same hardening used for `is_valid_merkle_proof` to the `in merkle` definition operator in `definition.js`: before calling `merkle.deserializeMerkleProof` / `merkle.verifyMerkleProof`, validate that the authentifier string length is bounded (e.g. ≤1024 chars) and, after deserialization, that `proof.siblings.length` does not exceed a small sane bound (e.g. 50), rejecting the definition/unit otherwise (as a `fatal_error`/definition validation failure) rather than allowing an unbounded hashing loop.

### Proof of Concept
1. Create an address whose definition contains `['in merkle', [[oracle_address], 'feed_name', 'expected_value']]`.
2. Post a unit authored by this address where the authentifier for that definition path is a string of the form `"0-<sib1>-<sib2>-...-<sibN>-<root>"` with N crafted to be very large (e.g. tens of thousands of dash-separated 44-character base64 tokens), while staying within overall unit-size limits.
3. Every node validating this unit calls `definition.js`'s `evaluate()` → `case 'in merkle'` → `merkle.deserializeMerkleProof()` → `merkle.verifyMerkleProof()`, which performs N SHA-256 hashing iterations, consuming disproportionate CPU per validating node compared to the cost paid by the attacker.

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

**File:** formula/evaluation.js (L1778-1797)
```javascript
					evaluate(proof_expr, function (proof) {
						if (fatal_error)
							return cb(false);
						let res;
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
```
