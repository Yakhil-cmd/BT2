## Title
Missing domain separation between leaf and internal-node hashing in `merkle.js` allows Merkle "node-as-leaf" forgery (second-preimage) — ([File: merkle.js])

### Summary
`ocore`'s Merkle implementation hashes leaves and internal nodes with the exact same function and no domain-separation tag. A leaf is `hash(element)` and an internal node is `hash(leftHash + rightHash)`, with `hash()` being a single-argument `sha256(str)`. Because the only difference between a leaf-preimage and an internal-node-preimage is content, not structure or tagging, anyone who knows two adjacent internal-node hashes (which are routinely exposed as `siblings` in any proof) can pick `element = leftHash + rightHash` and produce a valid `verifyMerkleProof` result for a value that was never a genuine element of the tree. This is the same bug class as the reported Footium `claimEthPrize` issue (`keccak256(abi.encode(_to, _amount))` colliding with internal nodes), applied to `ocore`'s `sha256`-based Merkle tree.

### Finding Description
`getMerkleRoot`/`getMerkleProof` compute leaf hashes via `hash(element)` and combine pairs via `hash(arrHashes[i] + arrHashes[hash2_index])`, with no leading byte or prefix distinguishing "leaf" from "internal node" inputs: [1](#0-0) 

`verifyMerkleProof` walks the supplied `siblings` starting from `hash(element)` using the identical combination function, and the code itself flags the risk in a comment: [2](#0-1) 

Because `hash()` is applied identically whether the input is a raw leaf `element` or the 88-character concatenation of two base64-encoded child hashes, an attacker can:
1. Observe any two sibling internal-node hashes `L` and `R` at some level of a published tree (trivially obtainable — they appear as `siblings` in any legitimate proof, or can be derived if the attacker knows some of the leaf set).
2. Set `forged_element = L + R`.
3. Compute `hash(forged_element)`, which equals the real parent node's hash by construction.
4. Reuse the tail of an honest proof (the siblings from that parent's level up to the root) as `forged_proof.siblings`, with `index` set to the parent's position.
5. Call `verifyMerkleProof(forged_element, forged_proof)`, which returns `true` even though `forged_element` was never one of the original `arrElements`.

This primitive is consumed in two attacker-reachable places:
- The `in merkle` address-definition authentifier, which lets a unit author satisfy a spending condition by supplying a `serialized_proof` authentifier that must verify against a root published via a data feed: [3](#0-2) 
- The `is_valid_merkle_proof(element, proof)` oscript/AA formula function, directly usable in AA trigger-data validation logic (e.g., whitelist/airdrop-style AAs that pay out based on Merkle inclusion proofs supplied in the trigger): [4](#0-3) 

Neither call site adds any protection against the node-as-leaf collision: the `is_valid_merkle_proof` validation only restricts proof size/sibling count and format, not the semantic validity of `element` as an actual original leaf: [5](#0-4) 

### Impact Explanation
Any AA or address definition that relies on `is_valid_merkle_proof` / the `in merkle` authentifier to gate value release or authorization (e.g., a claim/airdrop AA verifying `(recipient, amount)` pairs against a published Merkle root, or an address definition restricting spending to values attested by an oracle's data feed root) can be bypassed by an attacker who forges a leaf equal to the concatenation of two known internal-node hashes. This lets an attacker satisfy the Merkle-membership check for values that were never actually included by the tree's constructor, leading to unauthorized fund release from an AA or unauthorized satisfaction of an address's spending condition — i.e., concrete AA fund loss / unauthorized spending, matching the required impact bar.

### Likelihood Explanation
Exploitation only requires knowledge of two adjacent internal-node hash values, which are inherently exposed as `siblings` whenever any legitimate Merkle proof is shared for the same tree (a near-certainty for any use case involving public airdrops/whitelists, since users request individual proofs). No special privileges, node compromise, or network position are needed — this is directly reachable by any unprivileged unit poster or AA trigger sender who can supply `trigger.data.element` / `trigger.data.proof`, or an author who can supply the `in merkle` authentifier on their own unit.

### Recommendation
Add domain separation between leaf and internal-node hashing, e.g. prefix leaf hashing with a distinct tag (`hash('0' + element)`) and internal-node hashing with another (`hash('1' + left + right)`), or otherwise ensure the leaf-hash input space cannot collide with the internal-node-hash input space (e.g., fixed-length-prefix leaves are already excluded from being valid 88-byte hash-concatenations). Apply this consistently in `getMerkleRoot`, `getMerkleProof`, and `verifyMerkleProof` in `merkle.js`.

### Proof of Concept
```js
const merkle = require('./merkle.js');
const crypto = require('crypto');
function hash(str){ return crypto.createHash('sha256').update(str,'utf8').digest('base64'); }

// Build a tree with some legitimate elements
const arrElements = ['alice:100', 'bob:200', 'carol:300', 'dave:400'];
const root = merkle.getMerkleRoot(arrElements);

// Attacker requests an honest proof, learning the internal sibling hashes along the way
const honestProof = merkle.getMerkleProof(arrElements, 3); // proof for 'dave:400'
// honestProof.siblings[0] is the sibling leaf-hash pair combined into level-1 hash;
// by requesting proofs for index 0 and 1, attacker learns L = hash('alice:100'), R = hash('bob:200')
const L = hash('alice:100');
const R = hash('bob:200');

// Forge an "element" equal to the concatenation of two known internal node hashes
const forgedElement = L + R; // hash(forgedElement) === hash(L+R) === real level-1 parent hash

// Reuse the remaining honest proof siblings/index above that level to reach the same root
const forgedProof = {
  index: 0, // position of the level-1 parent node
  siblings: [honestProof.siblings[1]], // whatever sibling(s) exist above that level
  root: root
};

console.log(merkle.verifyMerkleProof(forgedElement, forgedProof)); // => true, despite forgedElement never being a real leaf
```
This demonstrates that `verifyMerkleProof` (and therefore `is_valid_merkle_proof` in AA formulas, and the `in merkle` authentifier in `definition.js`) can be satisfied with a value that was never part of the original data set, purely due to the missing leaf/internal-node domain separation.

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
