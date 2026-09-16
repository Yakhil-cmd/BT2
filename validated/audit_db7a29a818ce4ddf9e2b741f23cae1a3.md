### Title
Merkle proof verification allows Node-as-Leaf forgery, enabling unauthorized claims/spending via `in merkle` address conditions and `is_valid_merkle_proof()` - ([File: merkle.js])

### Summary
`merkle.js` implements a leaf/internal-node hashing scheme with no domain separation between leaf hashes and internal node hashes, and it silently duplicates the last node when a level has an odd number of elements. This is the same class of weakness as the classic Merkle-tree malleability bug (CVE-2012-2459-style) and is even flagged in the code itself as a known concern. Any address that is defined using the `in merkle` authentifier op, or any AA that authorizes payouts/claims via the oscript `is_valid_merkle_proof()` function, relies on `merkle.verifyMerkleProof()` for correctness. Because the scheme cannot distinguish a leaf hash from an internal node hash, an attacker who knows an internal node's hash value (derivable from public tree data or a partial proof) can present that internal hash as if it were a leaf "element" together with the remaining upper-level siblings, and the verification will accept it as a valid proof of inclusion for data that was never actually one of the original committed leaves. This directly parallels the external report's bug class (a party manufacturing/using a Merkle structure to authorize claiming more than was actually deposited/allowed).

### Finding Description
`getMerkleRoot()`/`getMerkleProof()` in `merkle.js` build the tree by hashing raw leaf strings and internal concatenations with the same `sha256` function and no leaf/node tag: [1](#0-0) 

When a level has an odd count of hashes, the last hash is combined with itself to move up a level: [2](#0-1) 

`verifyMerkleProof()` re-derives the root purely from the element hash and the supplied siblings/index, with no check that the "element" is actually leaf-level data rather than an internal node hash, and the code's own comment acknowledges this: `// Node-as-Leaf issue might matter in some cases`: [3](#0-2) 

This primitive is consumed in two attacker-reachable places:
- The `in merkle` address-definition authentifier, which lets any address owner define spending conditions gated by an arbitrary data-feed-published Merkle root, verified with exactly this function: [4](#0-3) 
- The oscript `is_valid_merkle_proof()` formula function, callable from any AA trigger/formula, which is the documented building block for allowlist/claim-style AAs (analogous to the reported "claimFunds" pattern): [5](#0-4) 

Because leaf and internal-node hashing are indistinguishable, an attacker who can observe (or reconstruct) any internal node hash of a published tree (e.g. from a partial proof it received, or from the tree structure being reconstructable off-chain) can submit that internal-node value as the "element" with a truncated sibling path taken from a higher level, and `verifyMerkleProof`/`is_valid_merkle_proof` will report it as a valid inclusion proof, even though it was never one of the original committed leaves. In an AA that uses this to authorize a payment (e.g., "if is_valid_merkle_proof(trigger.data.element, trigger.data.proof) then pay trigger.data.amount"), or in an address `in merkle` condition gating a payment input, this lets an unprivileged unit/trigger sender fabricate a bogus but "verified" membership claim.

### Impact Explanation
Any AA or address-definition that relies on `is_valid_merkle_proof`/`in merkle` to gate fund release (claim programs, allowlists, airdrops, oracle-anchored authorization) can be tricked into accepting a forged inclusion proof for data that was never actually part of the committed set. This can result in unauthorized withdrawal/claim of AA or contract funds by a party who was never granted that claim right — the same end effect as the reported bug (funds leaving the contract to a party/amount not legitimately entitled to it).

### Likelihood Explanation
Exploitation requires the specific pattern of using `is_valid_merkle_proof`/`in merkle` to authorize value transfer, plus the attacker being able to derive an internal-node hash of the relevant tree (straightforward if the tree/leaf set or any prior proof is public, which is the common case for oracle-published or allowlist Merkle roots used by AAs). This is a realistic construction for claim/airdrop-style AAs, which is exactly the vulnerability pattern flagged in the external report.

### Recommendation
Add domain separation to `merkle.js`: hash leaves with a distinct prefix/tag (e.g. `sha256(0x00 || leaf)`) and internal nodes with a different prefix (e.g. `sha256(0x01 || left || right)`), as recommended by RFC 6962-style Merkle tree designs, so an internal node hash can never be mistaken for a valid leaf hash. Additionally, avoid silently duplicating the last node for odd-sized levels (reject or explicitly pad instead), and have `verifyMerkleProof` reject proofs whose length is inconsistent with any legitimate tree depth for the claimed data set where that is knowable.

### Proof of Concept
1. Build a tree over leaves `[A, B, C]` with `getMerkleRoot`/`getMerkleProof` (`merkle.js` lines 9-55): level-0 hashes are `h(A), h(B), h(C)`; since level-0 has odd length 3, level-1 hashes are `h(h(A)+h(B))` and `h(h(C)+h(C))` (self-duplicate).
2. The root is `h( h(h(A)+h(B)) + h(h(C)+h(C)) )`.
3. An attacker who knows `h(A)+h(B)`'s concatenation value can treat `x = h(A)+h(B)` as a fake "leaf" and submit `element = x`, `proof = {index: 0, siblings: [h(h(C)+h(C))], root}`.
4. `verifyMerkleProof(x, proof)` (`merkle.js` lines 84-102) computes `hash(hash(x) + h(h(C)+h(C)))`, which equals the real root — the forged "element" `x` (an internal node value, never one of the original committed leaves `A/B/C`) is reported as a valid member.
5. Deploy this against any AA that gates a payout on `is_valid_merkle_proof(trigger.data.element, trigger.data.proof)` (`formula/evaluation.js` lines 1768-1807) or an address using the `in merkle` definition op (`definition.js` lines 1004-1020) tied to that root, and the attacker's forged element/proof pair passes validation, letting them trigger fund release they were never authorized for.

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
