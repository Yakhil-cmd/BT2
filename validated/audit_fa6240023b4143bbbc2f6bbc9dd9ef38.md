## Title
Merkle proof verification allows forging membership for non-existent elements via node-as-leaf confusion - (File: merkle.js)

### Summary
`ocore`'s Merkle proof verifier, used both in the `is_valid_merkle_proof()` oscript function (available to any AA trigger sender) and the `'in merkle'` address-definition authentifier (available to any unit poster whose address uses that clause), hashes a submitted "leaf" the same way as internal tree nodes, with no domain separation between leaf-level and node-level hashing. This is functionally the same bug class as the BNB Bridge exploit: a broken/forgeable proof-of-membership verification routine that an unprivileged party can exploit to make the protocol accept a fabricated element as if it were a real, previously-committed piece of data.

### Finding Description
`merkle.js` defines the hashing scheme: [1](#0-0) 

Leaves are hashed as `hash(element)`, and internal nodes are hashed as `hash(left + right)`. Crucially, both operations funnel into the exact same `hash()` primitive with no leaf/node type prefix or length-prepending to prevent ambiguity between "hash of a single string" and "hash of a concatenation of two strings": [2](#0-1) 

The code even contains a developer comment acknowledging the risk: `// Node-as-Leaf issue might matter in some cases` at `merkle.js:85`, but no mitigation (e.g. a `0x00`/`0x01` domain-separation prefix, as used in Certificate Transparency/RFC 6962 to fix exactly this class of bug) was implemented.

Because of this, if an attacker knows any two sibling hash values that appear together at some internal node of a published Merkle tree (which are ordinarily learned by simply requesting/observing a legitimate proof for any real leaf in that tree — siblings are exposed by design), they can:
1. Concatenate those two hashes into a single string `h1+h2`.
2. Submit that string as the "element" together with the remaining sibling hashes above that node (unmodified) and the correct index.
3. `verifyMerkleProof` will compute `hash(h1+h2)`, which is bit-for-bit identical to the internal node's real hash, and then continue combining upward with the real remaining siblings, reproducing the legitimate root.

This makes `verifyMerkleProof` return `true` for an "element" that was never one of the original leaves committed to the tree — the classic second-preimage/"node-as-leaf" ambiguity (same family as CVE-2012-2459 in Bitcoin's merkle trees).

This verifier is reachable by two unprivileged surfaces:
- The `is_valid_merkle_proof` oscript primitive, evaluated from AA trigger data supplied directly by any trigger sender, with `element` and `proof` both attacker-controlled: [3](#0-2) 
- The `'in merkle'` address-definition authentifier clause, where the `serialized_proof` is supplied by the unit poster as an authentifier and only the resulting `proof.root` is checked against a previously-posted data feed value: [4](#0-3) 

Any AA (or address definition) that uses these primitives to gate value transfer based on Merkle-set membership (e.g. whitelist/airdrop/voucher-redemption AAs verifying `is_valid_merkle_proof(trigger.data.element, trigger.data.proof)` against a stored root) is relying on a soundness guarantee that this implementation does not actually provide.

### Impact Explanation
Any AA logic that trusts `is_valid_merkle_proof()` (or a definition using `'in merkle'`) to authorize a payout, unlock funds, or grant a privileged action based on set membership can be bypassed by an unprivileged trigger sender/unit poster who fabricates a "member" that was never actually part of the committed set. Depending on how the AA maps the proven `element` to an action (e.g., treating it as a claim identifier, address, or amount), this can lead to unauthorized fund release from the AA or double/duplicate claims that a well-formed Merkle-based whitelist was specifically designed to prevent — directly analogous to how BNB Bridge's broken proof verification allowed minting funds from forged proofs.

### Likelihood Explanation
Exploitability is high for any AA design pattern that uses `is_valid_merkle_proof` for whitelist/claim verification, since (a) the attacker only needs data that's normally public in such patterns — sibling hashes from any legitimate proof for any real leaf — and (b) both entry points (`is_valid_merkle_proof` in AA formulas and `'in merkle'` in address definitions) are directly reachable by any ordinary unprivileged unit/trigger poster with no special role required. The severity is bounded only by how the consuming AA logic uses the "proven" element.

### Recommendation
Add domain separation to the Merkle hashing scheme in `merkle.js`: prefix leaf hashing with a distinct tag (e.g. `hash("\x00" + element)`) and internal node hashing with a different tag (e.g. `hash("\x01" + left + right)`), and update `getMerkleRoot`, `getMerkleProof`, and `verifyMerkleProof` consistently. This is a breaking change to the proof format and must be versioned/gated behind an MCI-based upgrade flag (similar to other consensus-affecting fixes such as `bPostPemCurvesFix` in `formula/evaluation.js`) to avoid retroactively invalidating existing valid proofs.

### Proof of Concept
1. Build any Merkle tree of ≥4 elements with `merkle.getMerkleRoot`/`getMerkleProof` (or observe a real one, e.g. an airdrop whitelist tree whose root was posted to a data feed).
2. Request/derive a legitimate proof for two adjacent leaves `L0`, `L1` sharing an immediate parent; from either proof, read off `h0 = hash(L0)` and `h1 = hash(L1)` (available as sibling values in standard proofs).
3. Construct a forged proof object: `element = h0 + h1`, `index = <index of that parent node>`, `siblings = <the original proof's remaining siblings above that level>`.
4. Call `merkle.verifyMerkleProof(element, forgedProof)` (directly, or via `is_valid_merkle_proof(element, forgedProof)` inside an oscript AA formula, or via the `'in merkle'` address-definition clause) — it returns `true`, even though `h0+h1` was never a genuine leaf of the original tree, confirming the forgery.

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
