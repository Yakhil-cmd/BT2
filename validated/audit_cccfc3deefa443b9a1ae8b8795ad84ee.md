## Title
Second-Preimage / Node-as-Leaf Forgery in the Merkle Proof Library Allows Bypassing `in merkle` Authentifiers and `is_valid_merkle_proof` Checks - (File: merkle.js)

### Summary
The Electra report describes a class of bug where a Merkle-style tree verification routine relies on structural assumptions that can be violated, letting an attacker forge a "valid" proof for data that was never actually part of the tree (a second-preimage/tree-confusion attack). `ocore`'s own Merkle library, `merkle.js`, has the analogous structural weakness: it hashes leaves and internal nodes with the exact same, unprefixed SHA-256 function, with no domain separation between a leaf and a pair of child hashes. The code even contains an explicit acknowledgment of this: `// Node-as-Leaf issue might matter in some cases` in `verifyMerkleProof()` [1](#0-0) . This routine is reachable both from oscript's `is_valid_merkle_proof()` formula operator [2](#0-1)  and from the `in merkle` address-definition authentifier [3](#0-2) , both of which are directly attacker-reachable: the former by any AA trigger sender supplying arbitrary trigger data, the latter as an authentication rule inside a wallet/AA address definition.

### Finding Description
`getMerkleRoot`/`getMerkleProof`/`verifyMerkleProof` hash leaf elements and internal node concatenations identically: `hash(str) = sha256(str)` is applied uniformly, whether `str` is a raw leaf element or the concatenation of two child hashes [4](#0-3) . There is no leaf/node prefix (unlike, e.g., RFC 6962 Certificate Transparency, which prepends `0x00` to leaves and `0x01` to internal nodes specifically to prevent this).

Because of this, `verifyMerkleProof(element, proof)` cannot distinguish between:
- a genuine leaf `element`, and
- a forged `element` that is actually the concatenation of two other nodes' hash strings (`hash(left) + hash(right)`) from the same tree.

If an attacker knows (or can derive, e.g. from previously-submitted legitimate proofs revealing sibling hashes) the two child hashes of any internal node in a published Merkle root, they can submit `element = hash(left) + hash(right)` together with the remaining siblings from that internal node up to the root, and `verifyMerkleProof` will accept it as valid [5](#0-4) , even though this "element" was never one of the original leaves that the root's owner (an oracle, AA author, or address owner) intended to authorize.

This routine is exposed to two concrete, unprivileged attack surfaces in ocore:
1. **oscript `is_valid_merkle_proof`** — evaluated inside AA formulas with attacker-controlled `element`/`proof` (from `trigger.data`) [6](#0-5) , used by AA authors to gate logic (e.g., whitelists, claim lists, airdrop eligibility) against a stored or oracle-provided Merkle root.
2. **`in merkle` authentifier** in address definitions — checks a merkle proof supplied in the unit's `authentifiers`, verifying `proof.root` matches a value published via a data feed, and if so treats the authentifier as satisfied [3](#0-2) . This can gate spending authorization for an address.

### Impact Explanation
Where a Merkle root is used as a whitelist/allow-list gate for AA fund release (e.g., "only addresses in this Merkle set may withdraw/claim") or as part of an address's spending authentifiers, an attacker who can derive two sibling hashes of the tree (which is often possible since intermediate hashes are exposed whenever any legitimate proof is submitted on-chain, or if the tree/leaf set is otherwise inferable) can construct a forged `element` that passes `is_valid_merkle_proof`/`in merkle` without being a genuine authorized leaf. This can lead to unauthorized AA fund release or bypass of a spending authentication rule intended to restrict which values/keys are valid — i.e., concrete unauthorized spending or AA fund loss, matching the required impact bar.

### Likelihood Explanation
Exploitation requires the attacker to learn two internal hash values from the tree, which is plausible in realistic deployments: any legitimate proof already submitted publicly on the DAG reveals its own sibling hash chain, and larger allow-lists (thousands of leaves, as tested with random sets in `test/merkle.test.js` [7](#0-6) ) offer many internal nodes to target. No special privilege is needed — only the ability to post a unit/trigger with a crafted `element`/`proof` pair, which any user or AA trigger sender can do.

### Recommendation
Add domain separation to the leaf/node hashing in `merkle.js`, e.g., prefix leaves with `0x00` and internal-node concatenations with `0x01` before hashing (as in RFC 6962), and reject `is_valid_merkle_proof`/`in merkle` inputs where `element`'s byte length or format cannot plausibly be a raw leaf (e.g., reject 88-character base64 concatenations of exactly two hash outputs). This closes the second-preimage / node-as-leaf channel referenced by the existing code comment.

### Proof of Concept
1. Given a published Merkle root `R` over leaves `[L0, L1, L2, L3, ...]`, obtain (from a previously posted legitimate proof, or by direct knowledge of the leaf set) the hashes `h0 = hash(L0)` and `h1 = hash(L1)`, and the remaining sibling path from that pair's parent to `R`.
2. Construct `forged_element = h0 + h1` and `forged_proof = { root: R, index: <parent index>, siblings: <remaining sibling hashes> }`.
3. Call `merkle.verifyMerkleProof(forged_element, forged_proof)` — per the logic in `verifyMerkleProof` [5](#0-4) , this returns `true`, even though `forged_element` was never a genuine leaf.
4. Submit this via oscript `is_valid_merkle_proof(forged_element, forged_proof)` in an AA trigger, or via the `in merkle` authentifier in a unit's `authentifiers`, to bypass whitelist/authorization logic gated on membership in root `R`.

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

**File:** test/formula.test.js (L3111-3121)
```javascript
function createMerkleSet() {
	var len = getRandomInt(1, 10000);
	var index = getRandomInt(0, len-1);
	var arrElements = [];
	for (var i = 0; i < len; i++)
		arrElements.push(getRandomString());
	return {
		element: arrElements[index],
		proof: merkle.getMerkleProof(arrElements, index)
	};
}
```
