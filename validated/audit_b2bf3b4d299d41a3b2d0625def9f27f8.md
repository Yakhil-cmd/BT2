### Title
Merkle proof verification lacks index-range check, allowing the same proof to validate leaf existence at multiple indices - (File: merkle.js)

### Summary
`verifyMerkleProof` in `merkle.js` reconstructs a root hash from a `proof.index` and `proof.siblings` array without ever checking that `index` is bounded by the size of the tree implied by `siblings.length` (i.e., `0 <= index < 2**siblings.length`). Because the loop only uses `index % 2` and `index = Math.floor(index/2)` for `siblings.length` iterations, the exact same `siblings` array validates for `index`, `index + 2**L`, `index + 2*2**L`, etc. (where `L = siblings.length`). This is the same design flaw as the reported `Merkle.checkMembership` bug, transplanted into the `merkle.js` primitive used by `oscript`'s `is_valid_merkle_proof()` (accessible to AAs) and by address-definition's `in merkle` authentifier. [1](#0-0) 

### Finding Description
`verifyMerkleProof` walks the sibling list purely based on the parity of a mutable `index` variable, never validating that the supplied `index` is within the range implied by the proof depth: [1](#0-0) 

The function is invoked from two attacker/AA-author-reachable paths:

1. `is_valid_merkle_proof(element, proof)` in the oscript formula evaluator, callable from any AA triggered by a posted unit. The `proof` object (including its `index`) can come directly from `trigger.data`, fully controlled by the unit poster: [2](#0-1) 

2. The `in merkle` address-definition authentifier, where the `serialized_proof` (containing `index`) is supplied by the unit author as an authentifier at spend time and only checked via `merkle.verifyMerkleProof`: [3](#0-2) 

In both call sites, only `element` and `siblings` content are bounded/sanitized (length limits, hex/base64 checks); `index` itself is never range-checked against `siblings.length`: [4](#0-3) 

Because `is_valid_merkle_proof` exposes the verification result but the underlying `proof.index` field remains fully attacker-controlled and directly readable from `trigger.data` in oscript, any AA logic that (a) verifies inclusion with `is_valid_merkle_proof` and (b) uses the accompanying `index` as part of a uniqueness/anti-replay key (e.g., a state variable like `claimed[index]` to prevent double-claiming a whitelisted/airdropped leaf) can be bypassed: the same valid siblings array remains a valid proof for `index`, `index + 2**L`, `index + 2*2**L`, ... for the same leaf. An attacker resubmits the identical proof with a shifted `index` value, `is_valid_merkle_proof` still returns `true`, but the AA's anti-replay check (keyed by `index`) treats it as a brand-new, never-before-seen leaf.

### Impact Explanation
This directly mirrors the impact described in the reported issue: distinguishability logic keyed on `index` (used by AA developers to prevent double redemption/double-claiming of a merkle-tree-committed leaf) can be defeated, allowing an attacker to re-trigger AA logic that was intended to execute exactly once per leaf. Depending on the AA's use case (e.g., airdrop claim, whitelist-gated payout, voucher redemption), this results in AA fund loss through repeated payouts for a single committed leaf — a concrete impact category accepted for this analysis (AA fund loss). The root cause resides in the core `merkle.js` primitive shared by all AAs and by address definitions using `in merkle`, so the exposure is systemic rather than limited to a single AA.

### Likelihood Explanation
Likelihood is Medium: exploitation requires an AA author to have built a merkle-index-keyed anti-replay/uniqueness mechanism on top of `is_valid_merkle_proof` (a natural and expected pattern for whitelist/airdrop-style AAs, since `is_valid_merkle_proof` returns only a boolean and does not itself enforce a canonical index, forcing AA authors to track claimed indices themselves via `trigger.data.proof.index`). Any AA implementing that common pattern is silently vulnerable, and the attacking unit poster needs no privileged access — merely a validly-included leaf's own genuine merkle proof, which they already possess as the legitimate claimant.

### Recommendation
In `verifyMerkleProof` (and in `deserializeMerkleProof`), validate that `index` is a non-negative integer strictly less than `2**siblings.length` before iterating; reject the proof (return `false`) otherwise. This bound should be enforced unconditionally by the library itself (not left to each AA author to re-derive), analogous to the recommended fix in the original report (`index < 2**(proof.length/32)`), so `is_valid_merkle_proof` and the `in merkle` authentifier cannot be tricked into accepting shifted indices for a legitimate leaf.

### Proof of Concept
1. Build a small merkle tree with `getMerkleProof(arrElements, i)` for a tree of depth `L` (`siblings.length === L`), e.g. 4 leaves → `L = 2`.
2. Take the resulting `proof = { index: i, siblings: [...], root }` for leaf `i` (e.g., `i = 1`).
3. Call `merkle.verifyMerkleProof(arrElements[1], proof)` → returns `true` (expected).
4. Construct `proof2 = { index: i + 2**L /* e.g., 1 + 4 = 5 */, siblings: proof.siblings, root: proof.root }` and call `merkle.verifyMerkleProof(arrElements[1], proof2)` → also returns `true`, because the loop only ever examines `index % 2` for `L` iterations, ignoring the higher bits of `index`.
5. In an AA that stores `var['claimed_' + trigger.data.proof.index]` after validating `is_valid_merkle_proof(trigger.data.element, trigger.data.proof)`, an attacker first claims with `index = 1`, then resubmits the identical siblings/root/element with `index = 5` (or `9`, `13`, ...): `is_valid_merkle_proof` still accepts the proof, but the state-var key differs, so the AA's replay guard is bypassed and the payout logic executes again for the same underlying leaf.

### Citations

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
