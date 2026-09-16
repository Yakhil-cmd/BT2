### Title
Unbounded merkle-proof sibling loop in `is_valid_merkle_proof` causes AA-evaluation DoS on old/pre-fix networks - (File: formula/evaluation.js)

### Summary
`is_valid_merkle_proof(element, proof)` is a formula function callable by any AA author/trigger sender through oscript. When the `proof` argument evaluates to a `wrappedObject` (an AA-constructed/parsed object, e.g. via `json_parse`), the size/shape of `objProof.siblings` is only checked when `bPostPemCurvesFix` is true. Before that gate (`mci < constants.pemCurvesFixMci`), an attacker-controlled trigger/state object can supply an unbounded `siblings` array, which is then iterated element-by-element in `merkle.verifyMerkleProof`, hashing on every iteration — directly analogous to the ClamAV HFS+ CVE-2023-20197 pattern of "an incorrect/late completion check that lets a bounded-looking loop run unboundedly," causing denial of service.

### Finding Description
`merkle.verifyMerkleProof` iterates over `proof.siblings.length`, computing a SHA-256 hash per entry with no upper bound of its own: [1](#0-0) 

The AA formula evaluator calls this from the `is_valid_merkle_proof` opcode. The size/shape guard on `objProof.siblings` (type-check, non-empty-string check, and `length > 50` cap) is applied only `if (bPostPemCurvesFix)`: [2](#0-1) 

For the string-encoded proof path, there is a `proof.length > 1024` cap applied unconditionally, which indirectly bounds the number of siblings. But for the `wrappedObject` path (proof passed as a parsed/constructed object rather than a string, e.g. built via `json_parse` or an object literal in oscript/ojson), no size limit at all applies unless `bPostPemCurvesFix` is true: [3](#0-2) 

`bPostPemCurvesFix` is gated on `constants.pemCurvesFixMci`, an upgrade MCI that is a large, network-specific and time-dependent threshold: [4](#0-3) 

Before this MCI is reached (which is a real historical state every node passes through, and remains the state of any private/devnet or forked network that has not adjusted its upgrade schedule), any AA trigger sender can submit a `trigger.data` payload containing a large `siblings` array (e.g. thousands of entries, each an arbitrary string), pass it into `is_valid_merkle_proof(element, wrapped_obj_proof)`, and force the validator/executor to loop over the entire array computing SHA-256 hashes with no cap — unlike the equivalent string-based code path which is capped at 1024 bytes.

This mirrors the CVE-2023-20197 bug class: the loop's termination is nominally bounded (`for (var i = 0; i < proof.siblings.length; i++)`), but the *completeness/size check that should bound the input before the loop runs* was added later and only wired into one of two code paths (object vs. string), leaving a gap where unbounded work can be triggered by a single crafted input.

### Impact Explanation
An AA trigger sender (unprivileged, only needs to send a payment/trigger to an AA that calls `is_valid_merkle_proof` with a proof object) can force the AA-executing node to perform O(N) SHA-256 hashing operations with N unbounded by the formula complexity/ops accounting (complexity cost for `is_valid_merkle_proof` is a flat `+1`, not proportional to array size — see the validator's cost model at `formula/validation.js:860-869`). This is a resource-consumption/denial-of-service vector during AA response computation, which every full node must perform identically to reach consensus on the AA's response — a wedged/slow evaluation on this path can stall processing of the unit for all nodes attempting to execute the trigger.

### Likelihood Explanation
Reachable by any unprivileged AA trigger sender who can get an AA definition to call `is_valid_merkle_proof` with an object-typed (not string-typed) proof argument — a normal, documented oscript pattern (e.g., constructing/manipulating the proof via `json_parse` or object literals before passing it in). No special privileges, hub/peer position, or key compromise required. The condition only requires operating at an MCI below `pemCurvesFixMci`, which is true for extended periods on real networks and is the default/permanent state for any deployment (fork, private/devnet, or a network lagging behind mainnet's upgrade schedule) that has not crossed that specific upgrade point.

### Recommendation
Move the `siblings` array type/non-emptiness/length (`>50`) validation for `is_valid_merkle_proof` outside the `bPostPemCurvesFix` conditional so it always applies to the `wrappedObject` path, consistent with the always-enforced `proof.length > 1024` cap on the string path. Alternatively, bound `merkle.verifyMerkleProof` itself to reject `siblings` arrays beyond a fixed maximum before iterating, independent of any upgrade-mci gate.

### Proof of Concept
1. Deploy/target an AA whose oscript formula executes `is_valid_merkle_proof($element, $proof)` where `$proof` is derived from `trigger.data` via `json_parse` (making it a `wrappedObject`, not a raw string).
2. As an unprivileged user, send a trigger unit whose `data` field contains a JSON payload like:
   ```json
   { "index": 0, "root": "somehash", "siblings": [ "<44-byte b64>", "<44-byte b64>", ... /* tens of thousands of entries */ ] }
   ```
3. On a node/network operating below `constants.pemCurvesFixMci`, when the AA evaluates `is_valid_merkle_proof(element, json_parse(trigger.data.proof))`, `bPostPemCurvesFix` is false, so the `siblings.length > 50` cap in `formula/evaluation.js:1792-1797` is skipped, and `merkle.verifyMerkleProof` (`merkle.js:89-96`) iterates and hashes every one of the attacker-supplied siblings, consuming CPU proportional to the attacker-chosen array size, while the formula's own complexity cost remains a fixed `+1`.

### Citations

**File:** merkle.js (L84-97)
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

**File:** constants.js (L100-103)
```javascript
exports.tpsFeeRecipientsFixMci = exports.bTestnet ? 3909321 : 11985000;
exports.pemCurvesFixMci = exports.bTestnet ? 3975000 : 12185000;
exports.noPrivateAssetsWithConditionsUpgradeMci = exports.bTestnet ? 3975000 : 12185000;
exports.bestParentPrefersOpUpgradeMci = exports.bTestnet ? 3975000 : 12185000;
```
