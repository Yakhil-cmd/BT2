## Title
Merkle Leaf/Node Hash Collision Enables Second-Preimage Forgery of `in merkle` Address Conditions and `is_valid_merkle_proof` Membership Checks - (File: merkle.js)

### Summary
`ocore`'s Merkle implementation hashes leaves and internal nodes with the exact same function and no domain-separation prefix, so an attacker can craft a fake "element" that collides with an internal (non-leaf) node of a legitimate Merkle tree and forge a valid membership proof for content that was never actually included as a leaf. This primitive is reachable by any unit poster through the `in merkle` address-definition entry and by any AA trigger sender through the `is_valid_merkle_proof` oscript function.

### Finding Description
The leaf hash and the internal-node hash use identical logic: [1](#0-0) 

`hash(str)` is a plain single-argument `sha256` hash. A leaf's contribution to the tree is `hash(element)`, while an internal node's value is `hash(childHashA + childHashB)` — i.e. `sha256` applied to the concatenation of two child hash strings. There is no prefix or tag distinguishing "this is a leaf" from "this is an internal node," so if an attacker can produce a string `element` equal to the concatenation of two real sibling hash values `hashA + hashB` somewhere in a legitimately published tree, then `hash(element) == hash(hashA + hashB)`, which is exactly the internal node's value. Supplying the corresponding sibling path from that internal node up to the root produces a proof that `verifyMerkleProof` accepts as if `element` were a genuine leaf: [2](#0-1) 

This is the same bug class as the Footium report: leaves and internal nodes are hashed with the same construction, enabling a second-preimage forgery for any internal node whose two children are known.

Two reachable consumers of this primitive exist in `ocore`:

1. **Address-definition `in merkle` entries.** The `element` field is regex-validated but the allowed character class explicitly includes all base64 alphabet characters (`\w`, `+`, `/`, `=`), so a valid base64-encoded concatenation of two hash strings passes validation: [3](#0-2) 
At authentication time, the unit's poster supplies both `element` and a serialized proof as the authentifier; the code only checks that the derived root matches a value already recorded by an oracle in `data_feeds` — it never checks that `element` is an actual leaf rather than a reconstructed internal-node preimage: [4](#0-3) 

2. **`is_valid_merkle_proof` in oscript/AA formulas.** Any AA trigger sender can supply an arbitrary `element` and `proof` object; the only checks are on the syntactic type/length of the proof, not on whether `element` is a genuine leaf versus a forged internal-node preimage: [5](#0-4) 

In both cases, if the full tree (or enough of it to know two sibling hash values under some ancestor) is publicly disclosed — which is the normal, expected way to distribute a Merkle-based allow-list/airdrop/KYC set alongside a root committed to a data feed or AA state variable — an attacker can compute `element = hashA + hashB` for any internal node and derive a valid proof up to the root, without that `element` ever having been an intended leaf.

### Impact Explanation
- Where an address definition uses `in merkle` gated on an oracle-posted root (e.g., an allow-list of eligible addresses/values for spending conditions), an attacker who is not a genuine leaf member can forge a valid proof for an internal-node preimage and satisfy the authentifier check, resulting in **unauthorized use of a spending condition / unauthorized signing** that should have been restricted to genuine leaf members.
- Where an AA relies on `is_valid_merkle_proof(element, proof)` against a root stored as an AA state variable/param (e.g., a merkle-root-gated airdrop or claim mechanism), an attacker can forge membership for values that were never part of the committed set, leading to **AA fund loss** (unauthorized claim/payout) or **freezing/other logic corruption** depending on how the AA branches on the result.

### Likelihood Explanation
Exploitability depends on the attacker knowing (or being able to compute) two sibling hash values under some node of the specific tree whose root is committed on-chain. This is realistic whenever the tree's full leaf set is published off-chain for verification purposes (the normal deployment pattern for allow-lists/airdrops), mirroring the "potential" qualifier in the original report. The base64 charset restriction in the `in merkle` regex does not block this, since standard base64 output (`A-Za-z0-9+/=`) is fully permitted by the pattern.

### Recommendation
Introduce domain separation between leaf hashing and internal-node hashing in `merkle.js` — e.g., prefix leaves with a distinct tag (`hash("leaf:" + element)`) and internal nodes with a different tag (`hash("node:" + left + right)`), as recommended by the OpenZeppelin Merkle Tree documentation referenced in the original report. Apply this consistently to `getMerkleRoot`, `getMerkleProof`, and `verifyMerkleProof` in `merkle.js`, and bump any protocol/consensus-affecting version checks (`mci`-gated behavior) so existing trees/proofs are not silently broken.

### Proof of Concept
1. An oracle/AA maintainer builds and publishes a Merkle tree over a leaf set `L = [l0, l1, ..., ln]` using `merkle.getMerkleRoot(L)` and posts the root via a data feed (or stores it as an AA state variable).
2. An observer inspects the published tree/leaf set and picks any internal node with children `hashA` and `hashB` (available since the full tree is public for verification purposes).
3. The observer sets `element = hashA + hashB` (raw base64 concatenation) and constructs `proof.siblings` as the path from that node up to the root, with `proof.index` set to that node's index at its level.
4. `merkle.verifyMerkleProof(element, proof)` returns `true` because `hash(element) === hash(hashA + hashB)`, matching the internal node value, even though `element` was never a member of `L`.
5. This forged `(element, proof)` pair is submitted either as the authentifier for an `in merkle` address-definition entry (`definition.js:1004-1020`) or as arguments to `is_valid_merkle_proof` in an AA trigger (`formula/evaluation.js:1768-1807`), passing validation and unlocking the gated behavior for a non-member value.

### Citations

**File:** merkle.js (L5-19)
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

**File:** definition.js (L470-478)
```javascript
				if (!isNonemptyString(element))
					return cb("no element");
			//	if (!isStringOfLength(element_hash, constants.HASH_LENGTH))
			//		return cb("incorrect length of element hash");
				if (!element.match(/^[\w ~,.\/\\;:!@#$%^&*\(\)=+\[\]\{\}<>\?|-]{1,100}$/))
					return cb("incorrect format of merkled element");
				if (typeof min_mci !== 'undefined' && !isNonnegativeInteger(min_mci))
					return cb(op+": invalid min_mci");
				return cb();
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

**File:** formula/evaluation.js (L1768-1807)
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
				break;
```
