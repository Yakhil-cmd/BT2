### Title
DoS via unbounded siblings array length in `is_valid_merkle_proof` when proof is passed as an object (pre-`pemCurvesFixMci`) - ([File: formula/evaluation.js])

### Summary
`is_valid_merkle_proof(element, proof)` in the oscript formula evaluator lets a unit/AA-trigger author supply an arbitrary "proof" object as trigger/message data. When the proof is a `wrappedObject` (i.e. a literal/derived array, not a base64-encoded string), the code only bounds `objProof.siblings.length` (to 50) and validates each sibling is a non-empty string **if `bPostPemCurvesFix` is true**. Before that MCI upgrade activates for the relevant network context, none of these checks run, and `merkle.verifyMerkleProof()` is invoked with an attacker-fully-controlled `siblings` array of unbounded length and unbounded per-element string size, performing one `sha256` hash concatenation per sibling with no relation to the fixed complexity cost (`complexity++`) charged for the operation.

### Finding Description
The formula op is implemented at [1](#0-0) . The size guard only fires "if (bPostPemCurvesFix)": [2](#0-1) 
When the proof arrives as an object (`proof instanceof wrappedObject`), `objProof = proof.obj` is used directly with no upper bound on `siblings.length` or on the length of each sibling string in the code path that doesn't go through the `bPostPemCurvesFix` branch. The string-encoded proof form is size-limited (`proof.length > 1024`, line 1786-1787), but the object form has no equivalent limit outside the post-fix branch.

`merkle.verifyMerkleProof()` then loops once per sibling, hashing the accumulated value together with each sibling string: [3](#0-2) 

Meanwhile, the *cost accounting* for this op in the static validation pass (`formula/validation.js`) only ever adds a flat `complexity++` regardless of how large the proof turns out to be at evaluation time, since the proof value is runtime data (e.g. `trigger.data.proof`), not a literal known during static validation: [4](#0-3) 

This is directly analogous to the ffmpeg MXF bug: a "count"-controlled loop (`nb_index_entries` in MXF / `siblings.length` here) is trusted from attacker-controlled data and iterated without an adequate bound/cost check relative to the actual work performed, letting a single crafted input (a unit triggering an AA, or a formula evaluated by a wallet/AA) force disproportionate CPU consumption (hashing arbitrarily many, arbitrarily large sibling strings) for a fixed, tiny declared "complexity" cost.

### Impact Explanation
An attacker who can get this formula evaluated — e.g. by triggering an AA whose oscript uses `is_valid_merkle_proof(element, trigger.data.proof)`, or by crafting a `data` message/trigger payload consumed by such a formula — can supply an object-typed `proof` with an unbounded `siblings` array of unbounded-size strings. This forces the node evaluating the trigger (all full nodes validating/executing the AA response) to perform excessive SHA-256 hashing work while only being charged the same flat complexity/op cost as a legitimate small proof. Because complexity/op budgets are the mechanism ocore uses to bound total AA-execution CPU across the network, bypassing the true cost of this operation lets one crafted trigger disproportionately burden all validating nodes — a network-wide CPU exhaustion / inability-to-confirm-new-units risk consistent with the "network unable to confirm new units" acceptance criterion, without touching a p2p/hub/light-client path.

### Likelihood Explanation
Reachable directly by any AA trigger sender or unit author who can get an AA (or any formula evaluation, e.g. an address definition `formula` clause) to call `is_valid_merkle_proof` with attacker-influenced data — a common, encouraged usage pattern for merkle-proof verification against data feeds. No privileged access, hub cooperation, or malicious peer is required; a single posted unit/trigger is sufficient. The main uncertainty is whether `bPostPemCurvesFix` (gated by `constants.pemCurvesFixMci`) is already active on the deployed network for all contexts that reach this code path; if any code path/network state still reaches the pre-fix branch (or if the per-element string-size cap is genuinely absent post-fix as well, since `isNonemptyString` does not bound length), the primitive is exploitable today.

### Recommendation
- Move the siblings-length and per-sibling-length checks out of the `bPostPemCurvesFix` conditional so they always apply, or fail closed by default until validated.
- Add an explicit maximum length for each sibling string (mirroring the 1024-char cap already used for the string-encoded proof form) regardless of proof representation.
- Scale the `complexity`/`count_ops` charge for `is_valid_merkle_proof` (and similarly `sha256`/`chash160` on large wrapped objects) proportionally to the actual size of the runtime data being hashed, not a flat constant, so cost accounting can't be bypassed by inflating array length or string size at evaluation time.

### Proof of Concept
1. Deploy/trigger an AA (or evaluate a formula in an address definition) containing: `is_valid_merkle_proof($element, trigger.data.proof)`.
2. Send a trigger unit whose `data.proof` is an object like `{ index: 0, root: "<any-base64>", siblings: [<N very long strings>] }`, where in a context that does not enforce the `bPostPemCurvesFix` branch (or where sibling string length remains unchecked), `N` and the per-string length are chosen to be very large (e.g. thousands of megabyte-scale strings).
3. Observe that `merkle.verifyMerkleProof` performs SHA-256 over concatenations of these large strings once per sibling, consuming CPU time far exceeding what the flat `complexity++` charge for `is_valid_merkle_proof` accounts for, while the trigger/unit itself is accepted as valid (or cheaply rejected) at negligible declared cost.

### Citations

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

**File:** formula/validation.js (L860-869)
```javascript
			case 'is_valid_merkle_proof':
				complexity++;
				var element = arr[1];
				var proof = arr[2];
				evaluate(element, function (err) {
					if (err)
						return cb(err);
					evaluate(proof, cb);
				});
				break;
```
