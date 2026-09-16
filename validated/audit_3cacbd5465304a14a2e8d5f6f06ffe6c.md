### Title
Uncaught exception in `merkle.deserializeMerkleProof` on malformed serialized proof crashes node during unit validation - ([File: merkle.js])

### Summary
The Wireshark IMAP dissector bug (CVE-2017-7703) is a crash caused by incorrectly computing where a line/field ends when parsing attacker-supplied, unstructured input. `ocore`'s merkle-proof deserializer has an analogous unstructured-string parsing routine, `deserializeMerkleProof`, that blindly `split("-")`s an attacker-controlled string and does no type/format validation before being consumed by address-definition (`in merkle`) evaluation, which is reachable from any unit poster's authentifiers.

### Finding Description
`merkle.js` implements: [1](#0-0) 
which assumes `serialized_proof` is always a string. It is invoked directly from the `'in merkle'` authentifier-evaluation branch in `definition.js`, where `serialized_proof = assocAuthentifiers[path]` comes straight from the authentifiers object supplied in a posted unit, with no prior type check performed at this call site: [2](#0-1) 

If `assocAuthentifiers[path]` is not a string (unit authors fully control the JSON structure of the `authentifiers` object of a unit before it reaches this evaluation code), `serialized_proof.split("-")` throws a `TypeError`. This call is not wrapped in a `try/catch` (unlike the `verifyMerkleProof` call a few lines later, and unlike the `is_valid_merkle_proof` oscript function in `formula/evaluation.js`, which explicitly wraps `merkle.verifyMerkleProof` in try/catch and validates `proof` type/length before calling `deserializeMerkleProof`): [3](#0-2) 

This asymmetry mirrors the IMAP dissector bug class: the parser (`deserializeMerkleProof`) computes "where fields end" via naive `split`/`pop`/`shift` without first validating the shape/type of the untrusted input, and the one call site that reaches it during authentifier/address-definition validation lacks the defensive checks present elsewhere in the same codebase.

### Impact Explanation
An uncaught `TypeError` thrown inside the unit-validation code path (`validateAuthentifiers` → `evaluate` → `'in merkle'` case) is not guaranteed to be caught by the calling validation machinery's error callback because it is a synchronous throw rather than an `Error` passed to `cb2`. Depending on how far up the call stack the exception propagates before being caught, this can produce an unhandled exception that crashes the full node process while validating a broadcast unit. A network-wide crash triggered by a single crafted unit is a "network unable to confirm new units" scenario when many nodes process the same poisoned unit.

### Likelihood Explanation
Reaching this code path requires only that an address controlled by the attacker have a definition containing an `['in merkle', [...]]` clause and that the unit's `authentifiers` field for that path be set to a non-string value (e.g., a number, object, or array) instead of the expected serialized-proof string. Both the address definition and the authentifiers of a posted unit are fully attacker-controlled inputs to `validateAuthentifiers`, making this reachable by any unprivileged unit poster.

### Recommendation
- In `merkle.js`, add input validation to `deserializeMerkleProof` (`typeof serialized_proof === 'string'` check, throwing/returning a controlled error) before calling `.split`.
- In `definition.js`'s `'in merkle'` case, validate that `serialized_proof` is a non-empty string before calling `merkle.deserializeMerkleProof`, and wrap the deserialize+verify sequence in a `try/catch` consistent with how `formula/evaluation.js`'s `is_valid_merkle_proof` handles it, converting any exception into a normal `fatal_error`/`cb2(false)` outcome rather than letting it propagate as an uncaught exception.

### Proof of Concept
1. Construct a unit whose author address has a definition: `['in merkle', [['ADDR32...'], 'feed_name', 'expected_value']]`.
2. In the posted unit's `authentifiers` object, set the value at the corresponding path to a non-string type, e.g. `{"r": 12345}` or `{"r": ["x","y"]}` instead of a `"idx-sib1-sib2-root"` string.
3. Submit the unit for validation; `validateAuthentifiers` → `evaluate` reaches the `'in merkle'` branch and calls `merkle.deserializeMerkleProof(12345)`, which calls `(12345).split("-")`, throwing `TypeError: serialized_proof.split is not a function`, uncaught by the surrounding code at that call site.

*Note: I was not able to fully trace every layer of the async callback chain in `validateAuthentifiers`/`evaluate` in `definition.js` to confirm with certainty whether an outer `try/catch` elsewhere in the validation pipeline ultimately intercepts this specific synchronous throw before it reaches the top-level event loop (which would downgrade this from a process crash to a bounded validation failure). Confirming the exact propagation behavior would require tracing the full call stack from `validateAuthor`/`validateAuthentifiers` up through the unit-processing entry point, which requires broader code context than was retrievable via the indexed search.*

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

**File:** formula/evaluation.js (L1778-1804)
```javascript
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
```
