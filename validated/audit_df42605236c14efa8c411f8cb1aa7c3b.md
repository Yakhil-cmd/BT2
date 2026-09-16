### Title
Merkle Proof Verification Does Not Bind Leaf Hashing to Its Position, Allowing Forged Membership Proofs for the `in merkle` Address Condition - (File: merkle.js)

### Summary
`merkle.verifyMerkleProof()` in `merkle.js` hashes the supplied `element` with the exact same function used to hash internal tree nodes, with no domain separation between "leaf" and "internal node" data. This mirrors the `LineaProofHelper` bug class: a proof is cryptographically self-consistent (it correctly chains up to a known, trusted root) but the verifier never confirms that the "leaf" being proven actually corresponds to the *position/identity* it claims to occupy in the tree. An attacker can therefore construct a forged `element` whose SHA-256 hash equals a genuine internal node value, then reuse the legitimate upper-level siblings to produce a proof that validates against the real, trusted merkle root — for data that was never an actual member of the original set.

### Finding Description
`verifyMerkleProof` recomputes the "leaf" hash the same way as internal-node hashes are computed elsewhere in `merkle.js`: [1](#0-0) 

Note the code's own acknowledgment of the risk in the comment "Node-as-Leaf issue might matter in some cases" directly inside `verifyMerkleProof`: [2](#0-1) 

Both `getMerkleRoot`/`getMerkleProof` (tree construction) and `verifyMerkleProof` (verification) use the identical `hash(str)` helper for leaves and for concatenated internal nodes: [3](#0-2) 

This root is consumed directly by unprivileged, attacker-reachable code paths:

1. **Address authentication (`in merkle` operator)** — evaluated for every unit author who must satisfy this condition when spending from the address. The submitted authentifier is an attacker-controlled serialized proof (`assocAuthentifiers[path]`), and the only checks performed are that the proof verifies against *some* root, and that root was posted by the trusted oracle addresses under `feed_name`: [4](#0-3) 

2. **Definition validation** only constrains the format of the *fixed* `element` string embedded in the address definition (allowing arbitrary printable characters up to 100 bytes, which is wide enough to hold a base64-encoded 44-byte hash concatenation): [5](#0-4) 

Because `hash(leaf)` and `hash(left_child_hash + right_child_hash)` use the identical hash function with no leading domain-separation byte (e.g., `0x00` for leaves vs `0x01` for internal nodes), any two 44-byte base64 hash strings `h1` and `h2` that are already siblings at some internal level of the oracle's real tree can be concatenated by an attacker as `fake_element = h1 + h2`. `hash(fake_element)` will equal the internal node hash `hash(h1 + h2)` that the real tree already computed at that level. The attacker then submits `{index: index_of_that_internal_node, siblings: <the real siblings from that level up to the root>, root: <the real, oracle-posted root>}` as the proof for `fake_element`. `verifyMerkleProof` will report this as valid because it cannot distinguish "this is a leaf" from "this is an internal node being replayed as a leaf."

The oracle's own published sample proofs (needed by legitimate users) leak exactly the intermediate hash values (`siblings`) required to mount this attack, so the tree does not need to be fully known — a handful of legitimate proofs for members near the target internal node are sufficient.

### Impact Explanation
Addresses/AA definitions that use `['in merkle', [oracleAddrs, feed_name, element, min_mci]]` (e.g., whitelist/KYC gating, allow-listed counterparties, or other oracle-attested set-membership conditions controlling spending authority) can have their access-control condition satisfied by a party who was never part of the oracle's attested set. Since this operator is one of the boolean conditions inside an address definition evaluated by `validateAuthentifiers`, successfully forging it can let an unauthorized party satisfy the spending condition of the address, leading to unauthorized spending of funds locked behind such a condition — matching the "concrete unauthorized spending" impact bar.

### Likelihood Explanation
Exploitation requires: (a) an address/AA whose definition uses `in merkle` bound to a real oracle feed, and (b) the attacker's ability to obtain a small number of legitimate merkle proofs from that oracle (which are typically published to let legitimate members prove membership) so intermediate sibling hashes are known. Both conditions are realistic for any deployed oracle-gated whitelist, making this feasible for a moderately resourced attacker without needing any special privilege — only the ability to submit a spending unit with a forged authentifier.

### Recommendation
Add domain separation to the merkle hashing scheme so leaf hashes and internal-node hashes cannot collide: e.g., hash leaves as `hash("0" + element)` and internal nodes as `hash("1" + left + right)` (or use distinct prefixed byte tags) in both `getMerkleRoot`/`getMerkleProof` and `verifyMerkleProof`. Because this is a hashing-scheme change, it must be versioned/gated behind an upgrade MCI (similar to other consensus-affecting fixes in this codebase, e.g. `bPostPemCurvesFix`) so existing proofs/definitions are not broken and all nodes switch enforcement atomically.

### Proof of Concept
1. Oracle publishes a data feed value `V` that is the merkle root of a real element set `{A, B, C, D, ...}`, and later publishes (or it becomes observable via normal client usage) a legitimate proof for `A` that reveals: `hash(A)=h_A`, `hash(B)=h_B`, and the upper-level siblings `S = [s1, s2, ...]` connecting `hash(h_A+h_B)` up to `V`.
2. Attacker computes `fake_element = h_A + h_B` (the literal 88+ byte base64 concatenation string, which is ≤100 bytes and matches the allowed `element` format regex in `definition.js`).
3. Attacker creates (or already controls) an address whose definition contains `['in merkle', [[oracle_address]], feed_name, fake_element, min_mci]`.
4. When spending from this address, attacker supplies authentifier `serializeMerkleProof({index: index_of(h_A,h_B)_pair_at_its_level, siblings: S, root: V})`.
5. `merkle.verifyMerkleProof(fake_element, proof)` in `definition.js` line 1016 returns `true` because `hash(fake_element) === hash(h_A+h_B)`, and the subsequent `dataFeeds.dataFeedExists(...)` check passes because `V` is indeed the value posted by the trusted oracle — even though `fake_element` was never a genuine member of the oracle's attested set. [1](#0-0) [4](#0-3)

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

**File:** definition.js (L470-475)
```javascript
				if (!isNonemptyString(element))
					return cb("no element");
			//	if (!isStringOfLength(element_hash, constants.HASH_LENGTH))
			//		return cb("incorrect length of element hash");
				if (!element.match(/^[\w ~,.\/\\;:!@#$%^&*\(\)=+\[\]\{\}<>\?|-]{1,100}$/))
					return cb("incorrect format of merkled element");
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
