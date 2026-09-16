### Title
Merkle tree implementation lacks leaf/internal-node domain separation, enabling forged membership proofs - (File: `merkle.js`)

### Summary
The Sherlock report flags that Footium's `claimETHPrize` builds Merkle leaves with `keccak256(abi.encode(_to, _amount))`, which produces a 64-byte pre-image identical in size/shape to an internal node hash (`keccak256(left||right)`), enabling classic second-preimage/leaf-forgery attacks against Merkle proofs. `ocore`'s own Merkle tree implementation in `merkle.js` has the analogous root cause: leaves and internal nodes are hashed with the exact same function and no domain-separation tag, so an internal node can be replayed as a forged "leaf" that verifies against the real root.

### Finding Description
`merkle.js` hashes leaves as `hash(element)` and internal nodes as `hash(arrHashes[i] + arrHashes[hash2_index])`, i.e. the concatenation of two base64-encoded child hashes [1](#0-0) . `verifyMerkleProof` walks up from an attacker-supplied `element`, recomputing `hash(the_other_sibling + proof.siblings[i])` (or the reverse) at each level, and accepts if the final value equals `proof.root` [2](#0-1) . There is no leading tag (e.g., `0x00` for leaves / `0x01` for nodes as in RFC 6962) distinguishing "this is a leaf" from "this is an internal node" hashing. Consequently, given any two known sibling hash strings `h1`/`h2` that appear somewhere in a real tree of depth ≥2, an attacker can submit `element = h1 + h2` as a fabricated "leaf" together with the remaining upper-level siblings taken from the real tree, and `verifyMerkleProof` will validate it against the legitimate root, effectively proving membership of arbitrary attacker-chosen data that was never actually inserted into the tree.

This verification routine is reachable by unprivileged, attacker-controlled input in at least two places:
- The `'is_valid_merkle_proof'` oscript/AA formula operator evaluates an attacker-supplied `element` and `proof` (from AA trigger data or unit payload) against `merkle.verifyMerkleProof` [3](#0-2) . Any AA definition that hard-codes/stores a Merkle root and checks membership of trigger-supplied data via this operator is exposed.
- The `'in merkle'` address-definition operator lets a signer supply an arbitrary serialized proof as an authentifier, which is checked with `merkle.verifyMerkleProof(element, proof)` against a root previously posted by a trusted oracle via a data feed [4](#0-3) . If the definition author intended the tree to whitelist only specific elements (e.g., authorized addresses/secrets), the forgery lets an unauthorized signer satisfy the condition without knowing an actual authorized leaf.

### Impact Explanation
Any address definition or AA that uses `'in merkle'` / `is_valid_merkle_proof` to gate spending or trigger acceptance on Merkle-tree membership (e.g., allow-lists, private-payment commitments, oracle-attested membership sets) can be bypassed by an attacker who observes any valid proof/sibling path for the real tree. This can lead to unauthorized spending from an address protected by such a definition, or an AA accepting/acting on a forged trigger condition, causing fund loss. This matches the "unauthorized spending" / "AA fund loss" impact bar.

### Likelihood Explanation
Exploitation requires that some deployed definition or AA actually relies on `merkle.verifyMerkleProof` for access control, and that the attacker can observe at least one legitimate proof (siblings) from the tree — a low bar since siblings/roots are typically public (posted via data feeds or included in prior AA responses/triggers). The forgery itself is a pure hash-collision construction with no computational cost beyond string concatenation, unlike a cryptographic collision search. Likelihood is Medium: it depends on adoption of this Merkle primitive in security-critical definitions, which is a design choice available to any address/AA author today.

### Recommendation
Add domain separation to `merkle.js`, hashing leaves and internal nodes differently, e.g.:
```js
function hashLeaf(str){ return crypto.createHash("sha256").update("0"+str, "utf8").digest("base64"); }
function hashNode(a, b){ return crypto.createHash("sha256").update("1"+a+b, "utf8").digest("base64"); }
```
and use `hashLeaf` for the original elements and `hashNode` when combining child hashes, both in `getMerkleRoot`/`getMerkleProof` and in `verifyMerkleProof`. Because this changes serialized proof/root values, it needs a protocol-version gate (similar to `bPostPemCurvesFix`/`mci`-based flags already used elsewhere in `formula/evaluation.js`) so existing on-chain roots/proofs remain valid while new trees use the fixed scheme.

### Proof of Concept
1. Build a real tree with `merkle.getMerkleRoot([e0, e1, e2, e3])`; note `arrHashes` at the first level are `h(e0)`, `h(e1)`, `h(e2)`, `h(e3)`, and the parent-level hashes are `H01 = hash(h(e0)+h(e1))` and `H23 = hash(h(e2)+h(e3))`, with `root = hash(H01+H23)`.
2. An attacker who knows `H01` and `H23` (they are visible in any proof for `e0..e3`, or derivable if the attacker is one of the original leaf owners) constructs `forged_element = H01 + H23`.
3. Attacker calls `merkle.verifyMerkleProof(forged_element, {index: 0, siblings: [], root: root})` — since `hash(forged_element) === hash(H01+H23) === root` matches when there are no more levels, or more generally crafts a fake leaf at a lower level equal to the concatenation of two known sibling hashes and supplies the true remaining siblings up to `root`.
4. `verifyMerkleProof` returns `true` for `forged_element`, an element never inserted into the original tree, exactly mirroring the Solidity report's underlying weakness of leaf/internal-node hash-domain collision. [2](#0-1)

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
