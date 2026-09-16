### Title
Denial-of-Service via unbounded merkle proof siblings in `in merkle` address-definition authentifier - ([File: definition.js])

### Summary
CVE-2017-0393 describes a libvpx bug where a maliciously crafted, unbounded/malformed input causes the parser to hang or crash a device — a classic "malformed structured input drives unbounded work in a validation/verification routine" bug class. The same bug class is reachable in `ocore` through the `in merkle` operator used in address spending-condition definitions: a unit author who signs a unit using a definition containing `['in merkle', [...]]` supplies an attacker-controlled serialized merkle proof as an authentifier, and the verification routine performs unbounded looped hashing over an unbounded number of "siblings" with no length cap, unlike the equivalent `is_valid_merkle_proof()` formula function which was hardened with an explicit siblings-length cap.

### Finding Description
In `definition.js`, the `'in merkle'` case inside `validateAuthentifiers`'s `evaluate()` takes the caller-supplied authentifier string directly and passes it into the merkle-proof verifier: [1](#0-0) 

`merkle.deserializeMerkleProof()` simply splits the string on `-` with no bound on the number of resulting elements, and assigns everything except the first/last token to `proof.siblings`: [2](#0-1) 

`verifyMerkleProof()` then loops once per sibling, computing a SHA-256 hash concatenation at every iteration — an O(n) cost directly proportional to attacker-controlled input size, with no upper bound in this call path: [3](#0-2) 

Contrast this with the sibling code path for the `is_valid_merkle_proof()` oscript/AA formula function, which explicitly caps `objProof.siblings.length` at 50 (a fix gated by `bPostPemCurvesFix`) before calling the same `merkle.verifyMerkleProof`: [4](#0-3) 

No equivalent siblings-length cap exists in the `definition.js` `'in merkle'` authentifier-verification path. The `assocAuthentifiers[path]` value is attacker-supplied (it comes from the message signer packaging the unit for validation, e.g. from `objUnit.authors[].authentifiers`), and its overall size is only indirectly bounded by generic unit-size limits (`MAX_UNIT_LENGTH`, `isTooDeeplyNestedOrHasTooManyNodes`) which apply to nested-object depth/node counts, not to a flat serialized string's length or to the number of dash-separated tokens it decodes into. A single long authentifier string (up to the unit-size ceiling) can therefore decode into a very large `siblings` array, forcing many repeated SHA-256 concatenation-hash operations on every node that validates this unit (and re-validates it, since `validateAuthentifiers`/`validateDefinition` are re-run "every time" per the comment at line 1449).

### Impact Explanation
This causes disproportionate CPU consumption on every full node that validates (or, per the comment in the code, re-validates on each redefinition check) the unit — a resource-exhaustion/DoS condition triggered purely by a single posted unit from an unprivileged address, matching "a network unable to confirm new units" in spirit if repeated across many units/addresses, or at minimum meaningfully degrading validation throughput for nodes processing the poisoned unit. It does not directly cause unauthorized spending or double-spend, but it is a concrete availability impact stemming from a missing bound that the codebase clearly considered necessary in the sibling code path (the `siblings.length > 50` check added for `is_valid_merkle_proof`).

### Likelihood Explanation
Reachable trivially by any address owner who defines (or is talked into co-signing under) a definition using `'in merkle'`, and by any unit poster using such a definition to sign a unit; no privileged position, hub/peer compromise, or light-client trust is required — it is a pure single-poster/unit-validation-path issue, matching the in-scope category "address definitions and authentifiers."

### Recommendation
Apply the same defensive cap used in `formula/evaluation.js`'s `is_valid_merkle_proof` handler to the `'in merkle'` authentifier-verification path in `definition.js`: after `merkle.deserializeMerkleProof(serialized_proof)`, validate that `proof.siblings` is an array of reasonable length (e.g. ≤ 50, matching the AA formula limit) and that each sibling is a well-formed hash string, rejecting the authentifier (fatal error) if not, before calling `merkle.verifyMerkleProof`.

### Proof of Concept
1. Craft an address definition containing `['in merkle', [['SOME_ORACLE_ADDRESS'], 'feed_name', 'expected_value']]` as part of an `and`/`or` branch that also includes a valid signature branch (to satisfy "each branch must have a signature").
2. When signing a unit that spends from this address, supply as the authentifier at the corresponding path a serialized merkle proof string of the form `index-h1-h2-h3-...-hN-root` with N artificially large (bounded only by overall message/unit size limits, e.g. tens of thousands of dash-separated 43-44 byte base64 hash-length tokens).
3. Submit the unit for validation. `definition.js`'s `'in merkle'` handler at line 1013-1019 calls `merkle.deserializeMerkleProof` (unbounded split) then `merkle.verifyMerkleProof`, which loops N times performing SHA-256 hashing — consuming CPU proportional to N on every validating node, with no length cap analogous to the 50-sibling cap enforced for the `is_valid_merkle_proof()` formula function.

Note: I was unable to fully confirm within the available searches whether any other global message/authentifier length limit (e.g. `MAX_AUTHENTIFIER_LENGTH` in `constants.js`) caps the raw authentifier string tightly enough to make N negligible; this should be verified against `constants.js` and `validation.js` authentifier-length checks before treating the exploitable N as unbounded in practice.

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

**File:** formula/evaluation.js (L1785-1797)
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
```
