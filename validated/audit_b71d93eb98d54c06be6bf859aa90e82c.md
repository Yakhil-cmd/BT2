## Title
Merkle proof verification lacks leaf/node domain separation, allowing forged "membership" proofs (Node-as-Leaf attack) - (File: `merkle.js`)

## Summary
`ocore`'s Merkle proof primitive, used both in AA formula evaluation (`is_valid_merkle_proof`) and in address-definition authentifiers (`in merkle`), hashes leaves and internal nodes with the exact same function and no domain-separation tag. This is the classical "second preimage"/"node-as-leaf" Merkle-tree forgery: an attacker who knows any two sibling hashes from a legitimate tree can submit their concatenation as a forged "leaf" element and reuse the remaining sibling path to prove inclusion of a value that was never actually a leaf of the tree, against a real, oracle-published Merkle root. This is functionally the same class of "arbitrary message/token-transfer verification" flaw flagged in the Avail report, just landing in Obyte's Merkle-proof code path that is directly reachable from unprivileged AA triggers and address definitions.

## Finding Description
`getMerkleRoot`/`getMerkleProof` build the tree by hashing leaves with `hash(str)` and internal nodes with `hash(child1+child2)` — the same `sha256`-based `hash()` function, with no prefix/tag distinguishing "this is a leaf" from "this is an internal node": [1](#0-0) 

`verifyMerkleProof` walks up from a caller-supplied `element` using caller-supplied `siblings`, again with the same undifferentiated `hash()`: [2](#0-1) 

The code even contains a developer acknowledgment of this exact issue in a comment right above the vulnerable logic ("Node-as-Leaf issue might matter in some cases"), but no fix (e.g., a `0x00`/`0x01` domain-separation prefix) was applied: [3](#0-2) 

This primitive is wired into two places reachable by ordinary, unprivileged actors:

1. **AA formula `is_valid_merkle_proof`** — usable by any AA author in `trigger.data`-driven logic (e.g. to gate token release, whitelist checks, oracle-attested payouts): [4](#0-3) 

2. **Address-definition authentifier `in merkle`** — usable as a spending condition where the caller supplies the `element` and a serialized proof, and the contract checks that `proof.root` matches a value previously published via a data feed (`dataFeedExists`): [5](#0-4) 

Because `element`, `proof.siblings`, and `proof.index` are all attacker-controlled (they come from the spending unit's authentifiers or the AA trigger payload), and only the final `root` is checked against a trusted, previously-published value, an attacker does not need the tree's original data — only knowledge of *any* two sibling hashes anywhere along a valid path to that already-published root (which can often be derived from previously revealed proofs, from a public data source used to build the tree, or from other users' own valid proofs for the same root). With that pair, the attacker computes `forged_element = hash1 + hash2`, and submits `forged_element` together with the remaining siblings from that node up to the root. `verifyMerkleProof` will accept it as a valid membership proof, even though `forged_element` was never one of the tree's original committed leaves.

## Impact Explanation
Any AA or address definition built on `is_valid_merkle_proof` / `in merkle` to gate fund release, whitelist membership, attested transfers, or other authorization decisions can be tricked into treating an attacker-manufactured value as "proven a member of the committed set." Depending on how the AA/definition logic uses the proven element (e.g., as a recipient address, an amount, an allow-listed identifier, or a bridge/attestation payload), this can translate into unauthorized fund release from an AA, bypass of an intended whitelist/authorization gate, or acceptance of a forged attested message — i.e., unauthorized spending or AA fund loss, matching the Medium-severity "arbitrary message/token transfer verification" bug class from the source report.

## Likelihood Explanation
Exploitation requires only: (1) an AA or address definition that relies on `is_valid_merkle_proof`/`in merkle` against a data-feed-published root, and (2) attacker knowledge of any two sibling hashes on a valid path to that root — information that is often available from the tree's public source data, from prior legitimate proofs, or from the oracle's own publication process. No privileged access, node compromise, or network-level attack is needed; the forged proof is submitted as ordinary trigger/authentifier data by a normal unprivileged unit poster or AA trigger sender.

## Recommendation
Add domain separation between leaf and internal-node hashing, e.g. `hash("0" + element)` for leaves and `hash("1" + left + right)` for internal nodes, in both `getMerkleRoot`/`getMerkleProof` (build side) and `verifyMerkleProof` (verify side). This is a breaking format change, so it must be versioned/gated (similar to other MCI-gated protocol changes already present in the codebase, e.g. `bPostPemCurvesFix`) to avoid invalidating existing proofs while closing the forgery for all new usage.

## Proof of Concept
1. Oracle builds a Merkle tree over leaves `[L0, L1, L2, L3]` via `getMerkleRoot`, publishes `root` as a data feed value (as used by `in merkle`) or otherwise reveals it on-chain.
2. Attacker (or any observer) learns the two child hashes `H(L0)` and `H(L1)` that combine into the internal node `N01 = hash(H(L0) + H(L1))` — obtainable from a normal proof for `L0` or `L1`, or from the public source data used to build the tree.
3. Attacker sets `forged_element = H(L0) + H(L1)` (the literal concatenation string) and constructs a proof using `N01`'s sibling (`N23`) as `siblings[0]` with the appropriate `index`.
4. Attacker submits `forged_element` and this proof via `is_valid_merkle_proof(forged_element, proof)` in an AA trigger, or via the `in merkle` authentifier of an address definition.
5. `verifyMerkleProof` computes `hash(forged_element) = hash(H(L0)+H(L1)) = N01`, then `hash(N01 + N23) = root`, matching the trusted published `root` — the AA/definition treats `forged_element` (never an actual leaf) as a verified member of the committed set, satisfying whatever fund-release or authorization logic depends on that check.

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
