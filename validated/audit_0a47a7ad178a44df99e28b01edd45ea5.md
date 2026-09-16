### Title
Merkle Inclusion Proof Verification Lacks Leaf/Internal-Node Domain Separation, Allowing Forged "in merkle" Membership Proofs - ([File: merkle.js])

### Summary
`merkle.js`'s `verifyMerkleProof` hashes leaves and internal tree nodes with the exact same unsalted `SHA256` function and no domain-separation prefix. This is the classic "node-as-leaf" / second-preimage weakness in naive Merkle trees. Because internal-node hashes leak publicly whenever a legitimate inclusion proof is used on-chain (the `in merkle` authentifier), an attacker can replay two leaked sibling hashes as a forged "element" and pass verification for data that was never part of the original attested set, mirroring the external report's bug class: an edge case in signature/proof verification logic that should cause rejection but instead is mishandled and accepted.

### Finding Description
`getMerkleRoot`/`getMerkleProof` build the tree by repeatedly computing `hash(arrHashes[i] + arrHashes[hash2_index])` for internal nodes, using the same `hash()` (plain SHA256, no prefix) that is used for leaves via `hash(element)`. [1](#0-0) 

`verifyMerkleProof` starts from the caller-supplied `element`, hashes it once (`the_other_sibling = hash(element)`), then walks up combining it with the supplied `proof.siblings`, comparing the final value to `proof.root`. The comment on line 85 explicitly flags the awareness of this class of bug ("Node-as-Leaf issue might matter in some cases") but the code does not implement any mitigation (no leaf/internal prefix byte, no length-prefixing). [2](#0-1) 

Since leaf-hash = `SHA256(leaf_string)` and internal-node-hash = `SHA256(child1_b64 + child2_b64)` share the exact same hash domain, if an attacker learns any two adjacent hash values `h_a`, `h_b` that were combined at some level of a real tree (which are routinely revealed as `siblings` in any legitimately-produced, on-chain-published proof for that same tree/root), the attacker can submit:
- `element = h_a + h_b` (the plain string concatenation)
- `proof.siblings` = the *remaining* siblings from that same leaked real proof, truncated to start one level higher

`hash(element)` will then equal exactly the internal node hash that a genuine proof would have produced at that level, and the remaining chain will validate against the real, unmodified `proof.root`. The forged element is accepted as "included in the tree" even though it was never one of the original leaves.

This verification is directly reachable by an unprivileged unit poster through the `in merkle` op in address/asset-condition definitions: [3](#0-2) 

and through the `is_valid_merkle_proof` oscript/AA-trigger function: [4](#0-3) 

Both paths call `merkle.verifyMerkleProof` (or `merkle.deserializeMerkleProof` + `verifyMerkleProof`) with attacker-controlled `element`/`proof` and no additional structural check that would catch this forgery.

### Impact Explanation
`in merkle` is designed so an oracle (`arrAddresses`) publishes a Merkle root as a data feed (e.g., a KYC/whitelist attestation, an allow-list for a restricted asset's transfer condition, or an access-control gate on an address definition). A legitimate holder normally receives a proof (root + siblings) to unlock spending/authentication. Because the tree hashing has no leaf/node domain separation, once any two legitimate proofs for the same root have been observed on-chain (they are stored permanently and publicly as unit authentifiers), an attacker can synthesize a new "element" that was never part of the original attested set and forge a valid inclusion proof for it. Used against `is_valid_merkle_proof` in an AA, or against an `in merkle` authentifier in an asset transfer condition or address definition, this can let an unauthorized party satisfy a whitelist/KYC condition it never should have satisfied, resulting in unauthorized spending of a restricted asset or unauthorized authentication for an address/AA gated on Merkle-based attestation.

### Likelihood Explanation
Exploitability requires: (1) an oracle/asset issuer relying on `in merkle`/`is_valid_merkle_proof` for access control, and (2) at least one legitimate proof for the target root having been revealed (which happens automatically the first time any legitimate holder uses their proof on-chain, since unit authentifiers/oscript inputs are public). Given ocore's own code comment acknowledges the "Node-as-Leaf issue," and any first real usage of the feature leaks the material needed for forgery, likelihood is moderate-to-high wherever this primitive is used for access control gating value transfer.

### Recommendation
Add domain separation between leaf and internal-node hashing (e.g., prefix leaves with `0x00` and internal nodes with `0x01` before hashing, à la Certificate Transparency/RFC 6962), and reject any `element` value passed to `verifyMerkleProof`/`is_valid_merkle_proof` that structurally decodes as two base64 SHA256 outputs concatenated. This must be a coordinated protocol upgrade (versioned/MCI-gated) since it changes the hash values of existing roots.

### Proof of Concept
1. Oracle O publishes a data feed `root = getMerkleRoot([e0, e1, e2, e3])` used as a KYC allow-list for asset X's transfer condition (`['in merkle', [[O], 'kyc', <element>, min_mci]]`).
2. Legitimate holder of `e0` posts a unit spending asset X, embedding authentifier `serialized_proof0 = index0-siblingA-siblingB-root` (this is now permanently public on the DAG).
3. Attacker extracts `siblingA` (the hash of `e1`) and `siblingB` (the hash of the internal node combining `e2,e3`) from that public proof.
4. Attacker crafts `element' = siblingA + siblingB` and a proof `index'-root` (one level up, no remaining siblings, since `hash(element') == hash(siblingA+siblingB)` equals the real top-level pre-root node).
5. Attacker submits a unit spending asset X using `element'` and this crafted proof; `merkle.verifyMerkleProof(element', proof')` returns `true` against the same real `root`, even though `element'` was never one of `e0..e3`, bypassing the asset's transfer/KYC condition. [2](#0-1) [3](#0-2)

### Citations

**File:** merkle.js (L5-20)
```javascript
function hash(str){
	return crypto.createHash("sha256").update(str, "utf8").digest("base64");
}

function getMerkleRoot(arrElements){
	var arrHashes = arrElements.map(hash);
	while (arrHashes.length > 1){
		var arrOverHashes = []; // hashes over hashes
		for (var i=0; i<arrHashes.length; i+=2){
			var hash2_index = (i+1 < arrHashes.length) ? (i+1) : i; // for odd number of hashes
			arrOverHashes.push(hash(arrHashes[i] + arrHashes[hash2_index]));
		}
		arrHashes = arrOverHashes;
	}
	return arrHashes[0];
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

**File:** formula/evaluation.js (L1768-1806)
```javascript
			case 'is_valid_merkle_proof':
				var element_expr = arr[1];
				var proof_expr = arr[2];
				evaluate(element_expr, function (element) {
					if (fatal_error)
						return cb(false);
					if (typeof element === 'boolean' || isFiniteDecimal(element))
						element = element.toString();
					if (!ValidationUtils.isNonemptyString(element))
						return setFatalError("bad element in is_valid_merkle_proof", { arr }, false, cb);
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
						try {
							res = merkle.verifyMerkleProof(element, objProof);
						}
						catch (e) {
							res = false;
						}
						cb(res);
					});
				});
```
