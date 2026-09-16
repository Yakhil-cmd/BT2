## Title
Unbounded merkle-proof sibling count in address-definition `in merkle` authentifier causes CPU exhaustion analogous to plistlib `read_ints` DoS - (File: `definition.js`, `merkle.js`)

### Summary
The Python `plistlib.read_ints` bug lets an attacker control a count value read from untrusted binary data and use it to drive an unbounded loop/allocation, causing CPU/RAM exhaustion. The analogous pattern in ocore is `merkle.deserializeMerkleProof` / `merkle.verifyMerkleProof`, used by the `'in merkle'` address-definition authentifier evaluator in `definition.js`. The number of proof "siblings" is fully attacker-controlled (derived by splitting an attacker-supplied string on `-`), and each sibling triggers a SHA-256 hash computation in a loop, with **no upper bound enforced** at this call site.

### Finding Description
`deserializeMerkleProof` simply splits the attacker-provided string on `"-"` and treats every remaining token as a sibling hash: [1](#0-0) 

`verifyMerkleProof` then iterates `proof.siblings.length` times, computing a SHA-256 hash per iteration: [2](#0-1) 

This is invoked from the `'in merkle'` case of the address-definition/spending-condition evaluator, which is reachable whenever a unit is authenticated using an `'in merkle'` condition in its definition. The authentifier value (`assocAuthentifiers[path]`) is taken directly from the posted unit/message with **no length or sibling-count validation** before being deserialized and verified: [3](#0-2) 

Contrast this with the AA-oscript equivalent `is_valid_merkle_proof` in `formula/evaluation.js`, which explicitly caps proof string length (`<=1024`) and sibling count (`<=50`) after the `pemCurvesFix` upgrade: [4](#0-3) 

No equivalent cap exists for the `'in merkle'` definition-authentifier path in `definition.js`. The only implicit bound is the overall unit-size limit (`constants.MAX_UNIT_LENGTH`), enforced in `validation.js`, which bounds the total serialized unit size but does not specifically bound how many merkle siblings can be packed into a single authentifier string (a string of `~64000` hyphen-separated base64 hash tokens can still fit well within typical unit-size budgets while requiring tens of thousands of SHA-256 computations per verification, and this validation runs on every full node validating the unit).

### Impact Explanation
Any address whose definition uses an `'in merkle'` condition can be triggered by posting/spending from that address with a crafted authentifier containing an excessive number of "siblings" (many `-`-separated segments). Every node that validates the unit performing this authentifier check will loop the full sibling count performing SHA-256 hashing, unnecessarily burning CPU on all validating nodes (unprivileged-attacker-triggerable CPU exhaustion during validation of a single unit). This does not on its own create double-spend/inflation, but it maps to the "network unable to confirm new units in a timely manner" / resource-exhaustion class explicitly called out as in-scope (CPU/RAM exhaustion via malformed data), since validation of ordinary units in the same batch is delayed by disproportionate work triggered by one authentifier field.

### Likelihood Explanation
Likelihood is limited by two factors I could not fully resolve from the index: (1) whether `'in merkle'` conditions in address definitions are commonly used/enabled features reachable without other preconditions, and (2) whether there is an overall practical limit on authentifier field size elsewhere in the validation pipeline (e.g., generic per-authentifier length caps in `validation.js`) that I was not able to locate a matching guard for specific to this path, despite searching. The unit-size ceiling (`MAX_UNIT_LENGTH`) still allows a large enough authentifier string to encode thousands of siblings, which is sufficient for meaningful CPU amplification relative to a trivial signature check.

### Recommendation
Add an explicit bound on the number of siblings (and/or overall string length) parsed by `merkle.deserializeMerkleProof`/consumed by the `'in merkle'` case in `definition.js`, mirroring the `proof.length > 1024` / `siblings.length > 50` checks already applied in `formula/evaluation.js`'s `is_valid_merkle_proof`. Reject authentifiers whose deserialized sibling count exceeds this bound before calling `verifyMerkleProof`.

### Proof of Concept
1. Create an address whose definition includes an `['in merkle', [[...]], 'feed_name', 'element']` condition.
2. Construct a unit spending from/authenticating with that address where the corresponding entry in `unit.authors[i].authentifiers[path]` is a string of the form `0-h1-h2-h3-...-hN-root`, with N chosen as large as the unit-size budget allows (thousands of dash-separated fake 32-byte base64 hash tokens).
3. Submit the unit to the network / a full node for validation.
4. On the validating node, `definition.js`'s `evaluate` function reaches the `'in merkle'` case and calls `merkle.deserializeMerkleProof` then `merkle.verifyMerkleProof`, which loops N times computing SHA-256 hashes purely because the attacker controlled how many `-`-delimited tokens were present — with no cap enforced at this call site, unlike the equivalent oscript `is_valid_merkle_proof` function.

### Citations

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
