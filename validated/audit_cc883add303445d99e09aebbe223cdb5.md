## Analysis

CVE-2017-12842 describes a bug class in Bitcoin Core's Merkle tree design: because leaf hashes and internal-node hashes are computed with the exact same hash function and there is no domain separation between "hash of a single element" and "hash of a concatenation of two child hashes," an attacker can craft a forged element whose hash collides — by construction, not by breaking SHA-256 — with a genuine internal node of the tree. That forged element then verifies as if it were a legitimately included leaf.

`ocore`'s Merkle implementation in `merkle.js` has the identical structural weakness, and the code even flags it in a comment. [1](#0-0) [2](#0-1) 

Both leaf hashing (`hash(element)`) and internal-node hashing (`hash(arrHashes[i] + arrHashes[hash2_index])`) use the same single SHA-256-over-string function with no leaf/node prefix. As a result, for any two adjacent real leaves `X, Y` in a tree, an attacker who knows `hash(X)` and `hash(Y)` (public in any published/oracle-fed Merkle tree) can construct a phantom "leaf" `Z = hash(X) + hash(Y)` (a plain string concatenation). Then `hash(Z)` is *by definition* equal to the internal node value `hash(hash(X)+hash(Y))` that already exists in the real tree — no collision search or preimage attack is required. Feeding `Z` with the sibling path *above* that internal node into `verifyMerkleProof` reproduces the true root, making `Z` verify as an included element even though it was never one.

This primitive is exposed directly to attacker-controlled input through the `is_valid_merkle_proof` oscript function, which is reachable by any AA trigger sender who controls both the `element` and `proof` arguments via trigger data: [3](#0-2) 

AA authors commonly use Merkle-proof primitives to implement whitelist/airdrop/inclusion checks against a root committed in an AA's state variables (e.g., "pay out if `is_valid_merkle_proof(trigger.data.element, trigger.data.proof)` matches the stored root"). Because the hash function used for leaves and internal nodes is undifferentiated, an attacker can submit a forged `element`/`proof` pair derived purely from public hash values already present in the tree (no brute-force, no knowledge of secret preimages) and pass the inclusion check for a value that was never actually enrolled — potentially causing the AA to release funds to an unauthorized claim. The same primitive is also wired into address-definition authentifiers via the `'in merkle'` opcode, which checks a caller-supplied proof against a data-feed-published root: [4](#0-3) 

(In this particular authentifier path the checked `element` is fixed by the address definition itself rather than attacker-chosen, so the forgery primarily threatens designs where the *value being proven* is attacker-influenced — which is the case for `is_valid_merkle_proof` used inside AA oscript logic.)

### Title
Merkle leaf/node hash-domain confusion allows forged inclusion proofs in `is_valid_merkle_proof` / `'in merkle'` — (File: merkle.js)

### Summary
`merkle.js` computes leaf hashes and internal-node hashes with the same undifferentiated `hash()` function and no domain-separation prefix, mirroring the CVE-2017-12842 "leaf-node weakness." Any party who knows the hashes of two sibling leaves in a Merkle tree can construct a phantom leaf `Z = hash(X)+hash(Y)` whose hash equals the real internal node's hash, and combine it with the siblings above that node to reproduce the true root — proving inclusion of an element that was never actually part of the tree, with no cryptographic collision search needed.

### Finding Description
`getMerkleProof`/`verifyMerkleProof` treat the tree purely as a sequence of `(index, siblings, root)` without tagging whether a hash value belongs to the leaf layer or an internal layer: [5](#0-4) [6](#0-5) 
Since `hash(element)` (leaf) and `hash(a+b)` (internal node) live in the same output space with no distinguishing prefix, `hash(hash(X)+hash(Y))` is trivially reproducible by anyone as `hash(Z)` for `Z := hash(X)+hash(Y)`, without needing a preimage attack against SHA-256. `verifyMerkleProof` accepts this `Z` at the corresponding tree position with the true higher-level siblings, reconstructing the genuine root and returning `true`, even though `Z` is not a real element of the underlying data set.

This primitive is exposed to fully attacker-controlled input via the `is_valid_merkle_proof` oscript function: [3](#0-2) 
which AA authors use to validate inclusion claims (e.g. whitelists/airdrop entitlement) against a Merkle root stored in AA state. An AA trigger sender supplies both `element` and `proof` in `trigger.data`, so they can submit the forged `Z`/proof pair described above for any tree whose public leaf hashes they can observe (e.g., published alongside the root, or derivable from the AA's own history/state).

### Impact Explanation
If an AA's business logic (Merkle-based whitelist, airdrop claim, KYC/permission gate, etc.) trusts `is_valid_merkle_proof` to authorize a payout or state transition tied to an opaque token/identity value, an attacker can forge inclusion of a value that was never enrolled and trigger fund release or state changes reserved for legitimate members — resulting in AA fund loss or unauthorized allocation of AA-controlled assets.

### Likelihood Explanation
Exploitation only requires knowledge of two adjacent leaf hashes from the target Merkle tree (typically public, since inclusion trees for whitelists/airdrops are usually published or reconstructable) and the ability to post an AA trigger with attacker-chosen `data.element`/`data.proof` — both trivially available to any unprivileged AA trigger sender. No brute-force or cryptographic break of SHA-256 is required, making this a low-cost, deterministic forgery once the attacker sees the relevant sibling hashes.

### Recommendation
Introduce domain separation between leaf and internal-node hashing in `merkle.js` (e.g., prefix leaf hashing with a distinct tag such as `hash("0"+element)` and internal-node hashing with `hash("1"+left+right)`), and update `getMerkleRoot`/`getMerkleProof`/`verifyMerkleProof` consistently, plus bump a protocol/format version so old proofs are not silently reinterpreted. Until fixed, AA authors should be warned in documentation not to rely on `is_valid_merkle_proof` results as authorization for value transfer without additional binding of the proven element to a signed/committed identity.

### Proof of Concept
1. Suppose an AA stores `root` = Merkle root of real elements `[... , X, Y, ...]` (adjacent leaves) and exposes:
   `if (is_valid_merkle_proof(trigger.data.element, trigger.data.proof) && element_maps_to_grant(trigger.data.element)) payout();`
2. Attacker observes `hash(X)` and `hash(Y)` (public alongside the tree/root) and the real siblings for the node above `X,Y` up to `root`.
3. Attacker sets `Z = hash(X) + hash(Y)` (string concatenation) and builds `proof = { index: <position of the X,Y-node>, siblings: <real siblings from that node up to root>, root: root }`.
4. Attacker posts an AA trigger with `data.element = Z`, `data.proof = serializeMerkleProof(proof)`.
5. `merkle.deserializeMerkleProof` / `merkle.verifyMerkleProof(Z, proof)` in `formula/evaluation.js` returns `true` because `hash(Z) == hash(hash(X)+hash(Y))` exactly matches the real internal node value, and the remaining siblings correctly reproduce `root`.
6. The AA treats `Z` as a proven member of the whitelist/tree and executes the guarded action (payout/grant) despite `Z` never having been a real enrolled element.

### Citations

**File:** merkle.js (L5-7)
```javascript
function hash(str){
	return crypto.createHash("sha256").update(str, "utf8").digest("base64");
}
```

**File:** merkle.js (L9-55)
```javascript
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

function getMerkleProof(arrElements, element_index){
	if (element_index < 0 || element_index >= arrElements.length)
		throw Error("invalid index");
	var arrHashes = arrElements.map(hash);
	var index = element_index;
	var arrSiblings = [];
	while (arrHashes.length > 1){
		var arrOverHashes = []; // hashes over hashes
		var overIndex = null;
		for (var i=0; i<arrHashes.length; i+=2){
			var hash2_index = (i+1 < arrHashes.length) ? (i+1) : i; // for odd number of hashes
			if (i === index){
				arrSiblings.push(arrHashes[hash2_index]);
				overIndex = i/2;
			}
			else if (hash2_index === index){
				arrSiblings.push(arrHashes[i]);
				overIndex = i/2;
			}
			arrOverHashes.push(hash(arrHashes[i] + arrHashes[hash2_index]));
		}
		arrHashes = arrOverHashes;
		if (overIndex === null)
			throw Error("overIndex not defined");
		index = overIndex;
	}
	// add merkle root
	//arrSiblings.push(arrHashes[0]);
	return {
		root: arrHashes[0],
		siblings: arrSiblings,
		index: element_index
	};
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
