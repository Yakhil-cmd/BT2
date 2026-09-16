## Finding: Merkle proof forgery via missing leaf/node domain separation (second-preimage attack) - (File: `merkle.js`)

### Summary
The Obyte merkle-tree implementation used to authenticate off-chain data (via the `in merkle` address-definition authentifier and the `is_valid_merkle_proof()` oscript function) hashes leaves and internal nodes with the exact same function and no domain-separation tag. This is the same bug class as the FOOMCASH incident (an unauthenticated/misconfigured verification artifact — there a mis-set zkSNARK verifying key, here a mis-designed hash commitment scheme — lets an attacker fabricate proofs that the verifier accepts as genuine). An attacker who knows any two adjacent node hashes in a published Merkle root can construct a "leaf" element whose hash collides with an internal node hash, then present a forged Merkle proof of "membership" for data that was never actually committed to the tree.

### Finding Description
`merkle.js` computes leaf hashes and internal node hashes identically: [1](#0-0) 

Leaves: `hash(element) = sha256(element)`.
Internal nodes: `hash(childHash_left + childHash_right) = sha256(concatenation_of_base64_strings)`.

Both operations feed a plain string into the same `sha256` hash with no leaf/node prefix (e.g. `0x00` vs `0x01`) to distinguish the two hashing contexts. As a result, if an attacker can choose or predict an "element" string that is literally equal to the concatenation `childHash_left + childHash_right` of some internal node already present in a previously-published tree, that forged element will hash to exactly the same value as the real internal node. The attacker can then submit `{element: forged_element, proof: {index, siblings: <higher-level siblings of that internal node>, root}}` and `verifyMerkleProof` will return `true`: [2](#0-1) 

Additionally, odd-length trees pad by duplicating the last hash with itself (`hash2_index = i` when `i+1 >= arrHashes.length`), a known weakness (CVE-2012-2459-style) that further increases the number of exploitable collision points an attacker can target.

This verification primitive is exposed to two attacker-reachable consumers:
1. Address-definition authentifier `in merkle`, which treats the Merkle root as a trusted "verification key" retrieved from a data feed and accepts any proof that validates against it: [3](#0-2) 
2. The oscript/AA formula function `is_valid_merkle_proof`, callable by any AA trigger sender, which performs the same unguarded verification: [4](#0-3) 

In both cases, the only "misconfiguration" required (mirroring FOOMCASH's verifying-key error) is that the trusted root was produced by this flawed `getMerkleRoot`/`getMerkleProof` construction (i.e. it's how the wallet/oracle publishes it) — there is no cryptographic domain separation protecting it, so any root published this way is forgeable in the way described.

### Impact Explanation
- If an address definition uses `in merkle` gated on a data-feed root as a spending condition (e.g., "prove you know an item in this whitelist/allowlist to spend"), an attacker can forge membership of an arbitrary value and satisfy the authentifier without ever knowing a genuine list element — leading to unauthorized spending from that address.
- If an AA uses `is_valid_merkle_proof()` to gate fund release (e.g., claiming a reward/airdrop only for addresses/items proven to be in a committed set), an attacker can forge a proof for an unlisted item/address and drain AA funds it was never entitled to — direct AA fund loss, analogous to the unauthorized `$FOOM` extraction in the reported incident.

### Likelihood Explanation
Exploitability requires only that the attacker learns two adjacent hash values from a previously-disclosed root construction (siblings and roots are routinely revealed on-chain/off-chain as part of normal proof presentation or discovery, since Merkle roots/data feeds and any historical proofs are public), then crafts a leaf string equal to their concatenation. Given oscript's `is_valid_merkle_proof`/`in merkle` are reachable by any unprivileged unit poster or AA trigger sender, and no additional secrecy protects the internal hash chain, this is a realistic, low-cost forgery once an AA or address definition relies on this primitive for authorization.

### Recommendation
- Add domain separation to `merkle.js`: hash leaves with a distinct prefix (e.g., `sha256(0x00 + element)`) and internal nodes with a different prefix (e.g., `sha256(0x01 + left + right)`), and reject verification unless the prefixes match the expected level.
- Do not silently duplicate the last node for odd-length trees; instead use an explicit domain-tagged padding scheme or carry length metadata that is checked during verification.
- Because this changes an existing hash function used to define committed roots, gate the fix behind an MCI-based feature flag (similar to `pemCurvesFixMci`) and require any oscript/definition code that relies on `is_valid_merkle_proof`/`in merkle` after the activation MCI to use the corrected/prefixed scheme, while old roots computed before the fix are still validated using the legacy method for backward compatibility.

### Proof of Concept
1. Suppose a data feed publishes Merkle root `R` for a list of "eligible" elements `[e0, e1, e2, e3]`, computed via `merkle.getMerkleRoot`.
2. Internally, `H01 = hash(hash(e0) + hash(e1))` and `H23 = hash(hash(e2) + hash(e3))`, and `R = hash(H01 + H23)`.
3. An attacker who observes `hash(e0)` and `hash(e1)` (e.g., because a legitimate proof for `e0` or `e1` was ever published, revealing sibling `hash(e1)`) computes `forged_element = hash(e0) + hash(e1)` (i.e., literally the two base64 hash strings concatenated).
4. `hash(forged_element) = sha256(forged_element) == H01` (since leaf hashing and node hashing are the same function on the same bytes).
5. The attacker submits `is_valid_merkle_proof(forged_element, {index: <index of H01 subtree>, siblings: [H23], root: R})`.
6. `verifyMerkleProof` in [2](#0-1)  computes `hash(hash(forged_element) + H23) == hash(H01 + H23) == R` and returns `true`, even though `forged_element` was never one of `e0..e3`.
7. Any AA formula or address definition gating logic on this result (fund release, authentication) is bypassed with the forged element.

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
