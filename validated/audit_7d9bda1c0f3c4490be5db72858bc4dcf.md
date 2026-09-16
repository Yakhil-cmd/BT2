### Title
Second-Preimage / Node-as-Leaf Forgery in Merkle Proof Verification Enables Unauthorized Spending and AA Fund Theft - (File: merkle.js)

### Summary
`merkle.js` builds and verifies Merkle trees using the same, undomain-separated `hash()` function for both leaves and internal nodes. This is the classic CVE-2012-2459-style second-preimage weakness: an attacker who knows any internal node's hash value can present it as a "leaf" together with a truncated sibling path and have `verifyMerkleProof()` accept it as valid, even though that value was never one of the original committed elements. The code itself flags this as a known, unresolved issue but does not mitigate it, and the vulnerable primitive is exposed to unprivileged inputs in two places: the `'in merkle'` address-definition authentifier in `definition.js` and the `is_valid_merkle_proof()` oscript function used by AA formulas in `formula/evaluation.js`.

### Finding Description
`getMerkleRoot()`/`getMerkleProof()` hash leaves with `hash(element)` and combine children with `hash(left + right)` using the identical `sha256`-based `hash()` helper, with no leaf/internal-node prefix or tag to distinguish the two hashing contexts: [1](#0-0) 

`verifyMerkleProof()` walks the sibling list up to the root using this same undifferentiated hash, and the source comment explicitly acknowledges the exact weakness described in the external report ("Node-as-Leaf issue"): [2](#0-1) 

Because internal nodes and leaves are hashed identically, any node in the tree (an internal hash, which can be leaked via a previous proof, via `proof.siblings` values, or via `dataFeeds`/oracle-published intermediate values) can be resubmitted as `element` together with the *remaining upper* siblings, and `verifyMerkleProof` will recompute the same root and return `true` — without that value ever having been a genuine leaf of the original committed set.

This primitive is reachable from two unprivileged, single-message paths:

1. **Address authentifier `'in merkle'`** — used when validating an author's authentifiers against an address definition. It takes attacker-supplied `serialized_proof` from `assocAuthentifiers[path]`, deserializes it, and calls `merkle.verifyMerkleProof(element, proof)`, then checks that `proof.root` matches a value previously posted as a data feed by a trusted oracle: [3](#0-2) 

2. **`is_valid_merkle_proof()` oscript function** — callable by any AA trigger sender inside an AA's bound/response formulas, taking a fully attacker-controlled `element` and `proof` (object or serialized string) straight from `trigger.data` and forwarding them to `merkle.verifyMerkleProof`: [4](#0-3) 

The only length restrictions added later (`bPostPemCurvesFix`) cap proof size and sibling count but do nothing to prevent an internal node from being replayed as if it were a leaf: [5](#0-4) 

### Impact Explanation
- Address definitions using `['in merkle', [addrs, feed_name, element]]` are meant to gate spending on membership of `element` in a set whose Merkle root an oracle attests to via a data feed. Because the tree lacks leaf/node domain separation, an attacker who can observe an internal node hash (leaked through any prior valid proof against the same tree, which is common since proofs reveal sibling hashes) can forge a shorter proof claiming an arbitrary "element" (the internal hash value) is a member, satisfying the authentifier and enabling unauthorized signing/spending from that address.
- AA formulas using `is_valid_merkle_proof()` as an authorization or eligibility check (e.g., Merkle-airdrop/allowlist patterns releasing AA-held funds to elements proven to be in a committed set) can be tricked into accepting forged "leaves" that were never part of the original set, letting an unprivileged trigger sender drain or misdirect AA funds intended for legitimate recipients — a direct AA fund loss.

This matches the external report's core impact category (falsely satisfying inclusion/verification checks via a second-preimage/node-as-leaf attack), translated to ocore's Merkle-based authentifier and oscript primitive instead of Ethereum beacon-chain withdrawal proofs.

### Likelihood Explanation
Any address owner or AA author who uses `'in merkle'` in a definition or `is_valid_merkle_proof()` in an AA formula (a documented, supported oscript feature) exposes this weakness to any party who can send a message/trigger. Obtaining an internal node hash requires only observing one legitimate proof against the tree (e.g., a prior valid oracle-attested proof, or common Merkle-airdrop tooling that publishes full proof sets), which is a realistic, low-cost condition — no privileged access, node compromise, or network-level attack is required.

### Recommendation
Add domain separation between leaf and internal-node hashing in `merkle.js`, e.g. `hash("\x00" + element)` for leaves and `hash("\x01" + left + right)` for internal nodes (or equivalent length/type prefixing), and bump/version the proof format so `verifyMerkleProof` rejects proofs built under the old scheme. Apply this fix consistently to `getMerkleRoot`, `getMerkleProof`, and `verifyMerkleProof` so that root, proof generation, and verification all agree, and audit `definition.js`'s `'in merkle'` authentifier and `formula/evaluation.js`'s `is_valid_merkle_proof` for any assumptions that would break with the new leaf/node distinction.

### Proof of Concept
1. Build a Merkle tree over elements `[A, B, C, D]` with `merkle.getMerkleRoot`, and obtain a valid proof for `A` via `merkle.getMerkleProof([A,B,C,D], 0)`; this proof includes the sibling `hash(hash(C)+hash(D))` (an internal node hash), call it `N`.
2. An attacker who observes this proof (e.g., published by the oracle/dApp as part of a claim/allowlist flow) now knows `N`.
3. Attacker crafts a new "proof" with `element = N`, `index` such that its position matches the internal node's position at the second tree level, and `siblings = [hash(hash(A)+hash(B))]` (the sole remaining sibling to reach the root).
4. Calling `merkle.verifyMerkleProof(N, forged_proof)` recomputes the same root and returns `true`, even though `N` was never one of the original leaf elements `[A,B,C,D]`.
5. Submitting this forged proof as the `serialized_proof` authentifier for an `'in merkle'` address condition, or as `trigger.data.proof`/`trigger.data.element` to an AA using `is_valid_merkle_proof(trigger.data.element, trigger.data.proof)`, causes the check to falsely pass, enabling unauthorized signature validation / AA fund release for a value that was never committed as a genuine leaf. [6](#0-5) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** merkle.js (L1-20)
```javascript
/*jslint node: true */
"use strict";
var crypto = require('crypto');

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
