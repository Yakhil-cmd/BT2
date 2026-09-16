### Title
Merkle Proof Second-Preimage Forgery via Missing Leaf/Node Domain Separation - (File: merkle.js)

### Summary
The Aztec report shows a "proof verifier" (TurboVerifier) accepting a cryptographic proof that should have been rejected, letting an attacker withdraw funds it never legitimately owned. ocore has an analogous, weaker-crypto verifier — `merkle.verifyMerkleProof()` in `merkle.js` — that is reachable from unprivileged address definitions (`in merkle` authentifier) and from AA/oscript logic (`is_valid_merkle_proof`). Because the same SHA-256 hashing routine is used indistinguishably for leaves and for internal nodes (no domain-separation byte), the verifier is vulnerable to the classic Merkle second-preimage attack: a value that is actually an internal node of a legitimately-published tree can be re-submitted as a "leaf" together with a truncated proof, and it will verify against the tree's real, already-published root.

### Finding Description
`getMerkleRoot`/`getMerkleProof` build the tree by repeatedly calling the same `hash()` function on leaf strings and on concatenations of child hashes: [1](#0-0) 
`verifyMerkleProof` reproduces this by hashing the supplied `element` once and then folding in `proof.siblings`: [2](#0-1) 
The function's own comment already flags this weakness: "Node-as-Leaf issue might matter in some cases" [3](#0-2) . Because `hash(str)` is applied identically whether `str` is an original leaf or the concatenation `nodeA+nodeB` of two children, anyone who knows (or can derive) the internal-node values of a tree whose root is already recorded on-chain can present `element = nodeA+nodeB` together with only the siblings from that node up to the root. `verifyMerkleProof` will accept this forged "leaf" as if it were an original tree element, because `hash(nodeA+nodeB)` reproduces exactly the internal node value the real tree already contains at that level.

This verifier is reachable by an unprivileged actor in two places:
- `definition.js`'s `in merkle` authentifier, used to gate address spending on a data-feed-published Merkle root: it deserializes an attacker-supplied proof and calls `merkle.verifyMerkleProof(element, proof)` before checking that the resulting root exists as a data feed value: [4](#0-3) 
- `formula/evaluation.js`'s `is_valid_merkle_proof()` oscript/AA function, exposed to any AA author and evaluated on values taken directly from `trigger.data`: [5](#0-4) 

In both cases, the `element` being "proved" is fixed ahead of time (in the address definition, or in the AA's oscript logic), and the attacker only needs to supply a shorter, forged proof at spend/trigger time. If the attacker (as address definer or AA author) chooses `element` to equal the concatenation of two internal node hashes of a tree whose root a trusted oracle/data feed will legitimately publish, they can satisfy the `in merkle` / `is_valid_merkle_proof` condition without that value ever actually being an original leaf of the referenced tree — bypassing the intended data-feed/oracle-backed authorization check.

### Impact Explanation
Any address definition or AA condition that relies on `in merkle` / `is_valid_merkle_proof` to gate fund release against a third-party (oracle/data-feed) published Merkle root can be satisfied fraudulently, without the oracle ever having published the claimed value. This is a genuine authorization-bypass primitive: it lets a party who should not be entitled to a payout satisfy a Merkle-membership precondition and unlock funds, mirroring the "proof-forgery leading to permissionless unauthorized withdrawal" bug class from the Aztec report, albeit gated to constructs that use this specific oscript/authentifier feature. Any escrow, prediction market, or AA that trusts `is_valid_merkle_proof`/`in merkle` against an oracle-controlled root can lose funds to unauthorized spenders.

### Likelihood Explanation
Exploitation requires the attacker to know (or predict) at least one pair of adjacent node hashes belonging to a tree that a legitimate oracle will publish the root of, and to pre-select their address definition's fixed `element` (or AA logic branch) to match that concatenation. This is feasible whenever the oracle's tree structure/leaf set is public, deterministic, or otherwise learnable in advance (e.g., a well-known, reproducible dataset), which is a realistic scenario for any deployed oracle-style data feed used with this feature. The precondition is real but non-trivial, so likelihood is medium rather than high.

### Recommendation
Add domain separation to `merkle.js`'s hash construction so leaf hashing and internal-node hashing can never collide, e.g., prefix leaves with `0x00` and internal nodes with `0x01` before hashing (as in RFC 6962 / standard Merkle-tree hardening), in both `getMerkleRoot`/`getMerkleProof` (tree construction) and `verifyMerkleProof` (verification). Update `serializeMerkleProof`/`deserializeMerkleProof` and all existing on-chain consumers (`in merkle` authentifier, `is_valid_merkle_proof`) consistently, with a version/MCI-gated activation to preserve compatibility with previously validated units.

### Proof of Concept
1. Attacker observes (or predicts) a Merkle tree that a target oracle/data feed will publish the root of, and computes two adjacent node hashes `nodeA`, `nodeB` at some level of that tree, plus the remaining sibling path from that level to the root.
2. Attacker defines their own address (or writes an AA) with an `in merkle` authentifier (or `is_valid_merkle_proof` check) whose fixed `element` equals the exact string `nodeA + nodeB`, referencing the target oracle's feed root: [6](#0-5) 
3. Once the oracle publishes the real root (which genuinely contains `nodeA`/`nodeB` as internal nodes, not `nodeA+nodeB` as a leaf), the attacker submits a unit spending from that address, supplying a serialized proof consisting only of the siblings from `nodeA+nodeB`'s level up to the root.
4. `merkle.deserializeMerkleProof` + `merkle.verifyMerkleProof(element, proof)` reproduce the true root because `hash(nodeA+nodeB)` collides with the legitimate internal node value, so the authentifier is satisfied and the spend is authorized despite the "proved" value never being an actual leaf of the oracle's dataset: [2](#0-1)

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
