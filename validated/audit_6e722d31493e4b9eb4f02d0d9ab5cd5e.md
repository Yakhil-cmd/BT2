### Title
Unbounded Merkle-proof deserialization/verification in address-definition authentifiers enables CPU amplification via `in merkle` - (File: definition.js)

### Summary
The `in merkle` operator in address/asset definitions accepts an attacker-supplied authentifier string as a serialized Merkle proof and deserializes/verifies it without any bound on its size, unlike the equivalent `is_valid_merkle_proof` oscript formula which explicitly caps proof size and sibling count. This mirrors the FFmpeg XBIN issue: attacker-controlled data is parsed/processed as a specific structured format (a Merkle proof) without validating its size/shape first, letting a single poster force disproportionate CPU work.

### Finding Description
`validateAuthentifiers()` in `definition.js` evaluates the `in merkle` definition opcode by taking the corresponding authentifier value directly from `assocAuthentifiers[path]` and feeding it into `merkle.deserializeMerkleProof()` and `merkle.verifyMerkleProof()` with no length or structure checks: [1](#0-0) 

`merkle.deserializeMerkleProof()` simply splits the string on `-` into an arbitrarily long `siblings` array with no cap: [2](#0-1) 

`merkle.verifyMerkleProof()` then iterates over every sibling and performs a SHA-256 hash for each, so the cost is linear in the number of `-`-delimited siblings supplied by the attacker: [3](#0-2) 

Authentifiers are only bounded to `MAX_AUTHENTIFIER_LENGTH = 4096` bytes and otherwise unrestricted in content, checked in `signed_message.js` and `validation.js`: [4](#0-3) 

This is 4096 chars, plenty of room to pack hundreds of short dash-separated segments and force hundreds of SHA-256 computations per authentifier, per author, per unit — with `MAX_AUTHORS_PER_UNIT = 16` authors and `MAX_MESSAGES_PER_UNIT` messages potentially multiplying this further across a single unit, and units validated repeatedly across every full/light node in the network.

Notably, the codebase already recognized this exact class of issue and mitigated it in the oscript formula equivalent, `is_valid_merkle_proof`, in `formula/evaluation.js`, where the proof string is capped at 1024 bytes and (post a specific upgrade MCI) the siblings array is capped at 50 elements: [5](#0-4) 

No equivalent cap exists on the `in merkle` path in `definition.js`, meaning the fix applied to the oscript/AA-triggered path was never applied to the address-definition-based path reachable by ordinary unit authors.

### Impact Explanation
An unprivileged unit poster can define (or already control) an address whose spending/authentication condition uses `in merkle`, then submit a unit signed with a crafted, maximally-sized (4096-byte) "authentifier" string engineered to contain the maximum number of dash-separated tokens. Every node that validates this unit (all full nodes and any light node checking the definition) must run `deserializeMerkleProof` and `verifyMerkleProof`, incurring O(n) SHA-256 hashing proportional to attacker-chosen segment count, repeated for every author/path using `in merkle` in the unit. This is a repeatable, cheap-to-produce CPU amplification primitive triggered by ordinary unit posting — a resource-consumption/DoS class matching the reported FFmpeg flaw (excess CPU load from insufficiently validated format parsing), reachable without any special privilege.

### Likelihood Explanation
Likelihood is moderate-to-high: `in merkle` is a documented, supported oscript-address-definition primitive (present in `definition.js`), so any user can create an address whose definition contains `in merkle` and post units using that address, supplying a self-crafted authentifier value of up to `MAX_AUTHENTIFIER_LENGTH`. No third-party cooperation, hub/peer compromise, or leaked keys are required — only a wallet capable of constructing custom address definitions and authentifiers, well within the reach of a single unprivileged unit poster.

### Recommendation
Apply the same bounds already used in `formula/evaluation.js`'s `is_valid_merkle_proof` to the `in merkle` path in `definition.js`:
- Reject `serialized_proof` strings above a small fixed length (e.g., 1024 bytes) before calling `merkle.deserializeMerkleProof`.
- After deserialization, reject proofs whose `siblings` array exceeds a small bound (e.g., 50 elements), matching the `formula/evaluation.js` mitigation.
- Consider adding the same defensive checks directly inside `merkle.deserializeMerkleProof`/`merkle.verifyMerkleProof` so all call sites are protected consistently, rather than relying on each caller to bound input independently.

### Proof of Concept
1. Create an address whose definition includes an `in merkle` condition, e.g. `["in merkle", [["<oracle_address>"], "feed_name", "expected_value"]]`, and register it as an author's address (or use `definition` supplied inline in the unit's author for a first-time-use address).
2. Compute a legitimate small Merkle proof once to learn the expected format (`index-sib1-sib2-...-root`).
3. Craft an authentifier string of length up to `constants.MAX_AUTHENTIFIER_LENGTH` (4096 bytes) consisting of hundreds of short dash-separated dummy segments followed by a final segment acting as `root`, e.g. `"0-" + "a-".repeat(500) + "root"`.
4. Submit a unit authored by this address with this crafted authentifier for the `in merkle` path.
5. Observe that every validating node runs `merkle.deserializeMerkleProof` (splitting into ~500 siblings) and `merkle.verifyMerkleProof` (looping ~500 times computing SHA-256 each), for cost proportional to attacker-chosen segment count — regardless of whether the proof is ultimately valid — compared to the capped cost enforced on the equivalent `is_valid_merkle_proof` oscript function.

### Citations

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

**File:** merkle.js (L75-82)
```javascript
function deserializeMerkleProof(serialized_proof){
	var arr = serialized_proof.split("-");
	var proof = {};
	proof.root = arr.pop();
	proof.index = arr.shift();
	proof.siblings = arr;
	return proof;
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

**File:** constants.js (L56-56)
```javascript
exports.MAX_AUTHENTIFIER_LENGTH = 4096;
```

**File:** formula/evaluation.js (L1786-1797)
```javascript
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
```
