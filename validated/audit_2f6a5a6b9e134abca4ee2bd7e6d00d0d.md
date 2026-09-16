## Analysis

The reported bug class — a Merkle scheme where the **leaf hash function has the same output space and input structure as the internal-node hash function**, allowing an attacker to submit an internal subtree hash as a "leaf" and forge a shortened proof — has a direct, acknowledged analog in ocore's own `merkle.js`.

`merkle.js` computes leaves and internal nodes identically: leaf hash is `hash(element)` where `element` is an attacker/definition-supplied string, and each internal node is `hash(childA_string + childB_string)`, i.e. `hash()` applied to the concatenation of two base64-encoded 32-byte hash strings [1](#0-0) . There is no domain separation (no leaf/node prefix), so if an "element" string happens to equal the concatenation of two real sibling hash strings from the tree, `hash(element)` reproduces the internal node's hash exactly. The code even contains an explicit acknowledgment of this: `verifyMerkleProof` has the comment `// Node-as-Leaf issue might matter in some cases` right above the verification loop [2](#0-1) .

This primitive is reachable from two unprivileged surfaces:

1. `is_valid_merkle_proof(element, proof)` in oscript formulas, where an AA-trigger sender fully controls both `element` and `proof` (siblings/index) as expression values evaluated from trigger data [3](#0-2) .
2. The `['in merkle', ...]` address-definition authentifier, where a unit poster supplies the serialized proof (siblings/index) as the authentifier for a definition path, verified against a root that must match a value found via `dataFeeds.dataFeedExists` [4](#0-3) .

Given the confirmed, self-acknowledged root cause in the hash construction, and a concretely reachable path through `is_valid_merkle_proof` (fully attacker-controlled element+proof) that can be used by an AA author to gate fund release, this qualifies as a valid analog.

### Title
Merkle leaf/node hash collision ("Node-as-Leaf") allows proof forgery in `is_valid_merkle_proof` / `in merkle` authentifier - (File: merkle.js)

### Summary
`merkle.js` hashes leaves as `hash(element)` and internal nodes as `hash(left+right)` using the same hash function and same-format (base64 hash-string) inputs, with no domain separation between leaf and node hashing. This is the same class of bug as the reported `claimETHPrize` issue: because leaf and node hashing share encoding, a crafted "leaf" value equal to the concatenation of two real sibling hash strings collides with a genuine internal node hash, letting an attacker present a subtree root as if it were a validated leaf and skip several proof levels.

### Finding Description
`getMerkleRoot`/`getMerkleProof` build internal nodes via `hash(arrHashes[i] + arrHashes[hash2_index])` [5](#0-4) , and `verifyMerkleProof` starts the walk from `hash(element)` and then repeatedly combines with siblings using the exact same `hash(a+b)` construction [6](#0-5) . Because both leaf-hashing and node-hashing use `sha256` over a string that is simply a concatenation, an `element` string chosen to equal `hashA + hashB` for two arbitrary/known sibling hashes will hash to the identical value as the genuine internal node `hash(hashA+hashB)`. Supplying that internal node's position (index) and the real remaining siblings up to the root as the "proof" makes `verifyMerkleProof` return `true`, even though `element` was never one of the tree's original leaves — it is instead a stand-in for an entire subtree. The code comment `// Node-as-Leaf issue might matter in some cases` at [7](#0-6)  shows this was a known, unresolved design gap.

This is directly reachable by an unprivileged AA-trigger sender through the `is_valid_merkle_proof` oscript function, where both the `element` and `proof` (siblings + index) expressions are evaluated from arbitrary AA-formula inputs (e.g., `trigger.data`) with only weak sanity checks (non-empty string, string-array siblings, siblings length ≤ 50) and no structural check that would prevent `element` from being a hash-string concatenation [8](#0-7) .

### Impact Explanation
If an AA author uses `is_valid_merkle_proof` to gate a fund-releasing action (e.g., claiming a reward/allocation from a committed Merkle set, similar in spirit to `claimETHPrize`), a malicious trigger sender who has observed enough legitimate sibling hashes from earlier valid proofs (or knows the intermediate structure of a partially-disclosed tree) can synthesize an `element` equal to a concatenation of two sibling hash strings and forge a "membership" claim for a value that was never committed. This can result in AA fund loss (unauthorized claim/spend) or double-processing of a claim that should only be honored once, without needing to break the underlying `sha256` hash function itself — only to exploit the shared leaf/node encoding.

### Likelihood Explanation
Exploitability depends on the attacker obtaining or guessing hash-string pairs that correspond to a real internal node's children and the correct remaining sibling path to the root — feasible whenever the tree (or a portion of previously-issued proofs) is publicly known, which is a common pattern for oracle/whitelist Merkle trees distributed via data feeds or AA definitions. The `in merkle` definition authentifier is less directly exploitable since the compared `element` is fixed in the address definition rather than attacker-controlled, whereas `is_valid_merkle_proof` in formulas gives full attacker control over both `element` and `proof`, making it the primary exploitable surface. This is rated Medium, matching the original report's severity and caveats.

### Recommendation
Introduce domain separation between leaf and internal-node hashing in `merkle.js`, e.g. prefix leaves with a distinct tag (`hash("leaf:" + element)`) and internal nodes with another (`hash("node:" + a + b)`), or otherwise make leaf encoding structurally distinguishable (e.g., different length/format) from the concatenation of two hash outputs, so a crafted leaf value can never collide with a real internal node hash.

### Proof of Concept
1. Build a tree over leaves `[e0, e1, e2, e3]` using `merkle.getMerkleRoot`. Internal left node `L = hash(hash(e0)+hash(e1))`.
2. An attacker (who has seen `hash(e0)` and `hash(e1)` from previously issued proofs, or controls a whitelisted trigger) sets `element = hash(e0) + hash(e1)` (the literal concatenated base64 strings) and constructs a `proof` with `index` set to `L`'s position and `siblings` = the real remaining path from `L` to the root (e.g., `[hash(hash(e2)+hash(e3))]`).
3. Calling the AA formula `is_valid_merkle_proof(trigger.data.element, trigger.data.proof)` (as evaluated in [8](#0-7) ) returns `true`, because `hash(element) == L`, even though `element` (the raw concatenated hash string) was never a genuine leaf of the tree — matching the same collision technique as the referenced `claimETHPrize` report.

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

**File:** merkle.js (L84-98)
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
