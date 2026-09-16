### Title
Unhandled Exception in Merkle Proof Deserialization Crashes Unit Validation via `in merkle` Address Definition - ([File: definition.js])

### Summary
The `in merkle` address-definition operator passes an unvalidated, attacker-controlled authentifier value directly into `merkle.deserializeMerkleProof()`, which calls `.split("-")` on it without any type check. Any unprivileged unit poster whose address (or asset transfer condition) uses this legitimate definition primitive can supply a non-string authentifier value (e.g. a number or array) and trigger an uncaught `TypeError` deep inside the unit-validation callback chain, analogous to the crafted-file parsing crash in ALPINE-CVE-2016-9811 (GStreamer's `windows_icon_typefind`), where malformed input to an unguarded parsing routine causes a denial of service.

### Finding Description
`in merkle` is evaluated in `validateAuthentifiers` in `definition.js`: [1](#0-0) 

The only guard is a truthiness check (`if (!assocAuthentifiers[path]) return cb2(false);`); there is no `typeof ... === 'string'` check as exists for the sibling `hash` operator a few lines above: [2](#0-1) 

`assocAuthentifiers` is populated straight from the `authentifiers` map supplied by the unit's author in the posted unit — content that is only checked for non-emptiness at the object level, not for the type of each individual authentifier value used by each op. The value is then handed to: [3](#0-2) 

`deserializeMerkleProof` calls `serialized_proof.split("-")` with no type guard. If `serialized_proof` is a number, boolean, array, or object without a `.split` method, this throws synchronously and uncaught — unlike `verifyMerkleProof`, which wraps its logic in `try/catch` and safely returns `false` on any exception: [4](#0-3) 

Notably, the AA-formula equivalent (`is_valid_merkle_proof` in `formula/evaluation.js`) explicitly checks `typeof proof === 'string'` before calling `deserializeMerkleProof`, and further wraps `verifyMerkleProof` in `try/catch`: [5](#0-4) 

This confirms the developers were aware that untyped/malformed proof input must be defensively handled before reaching `deserializeMerkleProof`/`verifyMerkleProof` — but this defensive check is missing in the address-definition (`definition.js`) code path. This is the same bug class as the CVE: a "typefind"-like parser (`deserializeMerkleProof`) is invoked on attacker-supplied, insufficiently-validated data without bounds/type checking, causing an unhandled fault during processing of untrusted content.

### Impact Explanation
`validateAuthentifiers` is invoked both for ordinary address definitions and, via `evaluateAssetCondition`, for asset-issuance/transfer conditions: [6](#0-5) 

Because `evaluate()` runs inside `async.eachSeries` iterator callbacks (often scheduled via `setImmediate`/`process.nextTick` boundaries by the `async` library), a synchronous throw here escapes any `try/catch` that might exist higher up the original call stack. The immediate, guaranteed effect is that `cb2()` is never invoked, so the validation callback chain for that unit stalls permanently, and the surrounding `async.eachSeries`/mutex-protected validation of the unit never completes — a DoS against the node processing that unit. If no `process.on('uncaughtException')` handler intercepts the throw at that point, the default Node.js behavior is to crash the process, taking the node offline and preventing it from confirming/validating further units — matching the CVE's denial-of-service classification, but reachable here by a single unprivileged unit poster or asset issuer rather than a malicious peer/hub.

### Likelihood Explanation
Any user can create an address whose definition contains `['in merkle', [...]]` and post a unit signed by/authored from that address, supplying an arbitrary (non-string) value at the corresponding authentifier path — no special privileges, hub cooperation, or node compromise are required. The same primitive is usable in asset transfer/issuance conditions, widening the reachable surface to asset issuers as well.

### Recommendation
Add a defensive type check before calling `merkle.deserializeMerkleProof` in `definition.js`'s `in merkle` handler, mirroring the check already present for the `hash` operator and in `formula/evaluation.js`'s `is_valid_merkle_proof`:
```js
if (!assocAuthentifiers[path] || typeof assocAuthentifiers[path] !== 'string')
    return cb2(false);
```
Additionally, wrap the call to `merkle.deserializeMerkleProof` (and the subsequent `verifyMerkleProof` call) in a `try/catch` that resolves to `cb2(false)` on any exception, so malformed input can never propagate an unhandled exception into the validation pipeline.

### Proof of Concept
1. Create an address whose definition is `["in merkle", [["ORACLE_ADDRESS"], "feed_name", "expected_value"]]` at some path `r`.
2. Craft a unit authored by that address where `authors[0].authentifiers.r` is set to a non-string value, e.g. `12345` (a JSON number) instead of the expected `"index-sibling1-sibling2-root"` string.
3. Submit the unit to a node for validation. During `validateAuthentifiers`, `evaluate()` reaches the `'in merkle'` case, passes `12345` to `merkle.deserializeMerkleProof`, which executes `(12345).split("-")`, throwing `TypeError: (intermediate value).split is not a function`, uncaught, stalling or crashing the validating node's process.

### Citations

**File:** definition.js (L641-643)
```javascript
function evaluateAssetCondition(conn, asset, arrDefinition, objUnit, objValidationState, cb){
	validateAuthentifiers(conn, null, asset, arrDefinition, objUnit, objValidationState, null, cb);
}
```

**File:** definition.js (L756-772)
```javascript
			case 'hash':
				// ['hash', {algo: 'sha256', hash: 'base64'}]
				if (!assocAuthentifiers[path] || typeof assocAuthentifiers[path] !== 'string')
					return cb2(false);
				arrUsedPaths.push(path);
				var algo = args.algo || 'sha256';
				if (algo === 'sha256'){
					var res = (args.hash === crypto.createHash("sha256").update(assocAuthentifiers[path], "utf8").digest("base64"));
					if (!res)
						fatal_error = "bad hash at path "+path;
					cb2(res);
				}
				else {
					fatal_error = "unsupported hash algo at path "+path;
					return cb2(false);
				}
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
