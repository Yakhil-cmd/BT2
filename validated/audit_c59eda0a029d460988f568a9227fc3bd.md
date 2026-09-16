## Analog Found

### Title
Unvalidated authentifier type in `in merkle` address-definition check causes uncaught exception on malformed proof - (File: `definition.js`)

### Summary
CVE-2017-11112 is a crash in ncurses' `append_acs` caused by processing attacker-controlled terminfo data without validating its structure before an unsafe access. The analogous pattern in `ocore` is in `definition.js`'s `validateAuthentifiers()`, in the `'in merkle'` branch, where a unit author's untrusted `authentifiers[path]` value is fed straight into `merkle.deserializeMerkleProof()` without confirming it is actually a string, unlike the sibling `'hash'` branch which explicitly checks `typeof assocAuthentifiers[path] !== 'string'`.

### Finding Description
In `definition.js`: [1](#0-0) 
the `'in merkle'` case does:
```
if (!assocAuthentifiers[path])
    return cb2(false);
arrUsedPaths.push(path);
...
var serialized_proof = assocAuthentifiers[path];
var proof = merkle.deserializeMerkleProof(serialized_proof);
```
There is no `typeof serialized_proof !== 'string'` guard, unlike the `'hash'` branch a few lines above it: [2](#0-1) 
which explicitly rejects non-string authentifiers.

`merkle.deserializeMerkleProof` assumes a string and calls `.split("-")` on it directly: [3](#0-2) 
If `serialized_proof` is not a string (e.g. it is a number, boolean, array, or object — all valid JSON leaf values an author can put in the `authentifiers` map of a posted unit), `.split` is not a function on that value, causing an unhandled `TypeError` to be thrown synchronously inside `deserializeMerkleProof`.

This call is not wrapped in a `try/catch`, unlike the formula-language equivalent (`formula/evaluation.js`'s `is_valid_merkle_proof`) which wraps the same deserialize/verify call in `try { ... } catch (e) { res = false; }`: [4](#0-3) 
So the oscript/AA formula path is hardened against this exact class of malformed input, but the address-definition authentifier path (`definition.js`) is not.

The entry point for reaching this code is any unit whose author uses an `'in merkle'` clause in their (new or referenced) address definition and supplies a non-string value at the corresponding `authentifiers` path — this is fully attacker-controlled and reachable by any unprivileged unit poster via `validateAuthor()` → `Definition.validateAuthentifiers()`: [5](#0-4) 

### Impact Explanation
An uncaught `TypeError` thrown deep inside the synchronous `evaluate()`/`async.eachSeries` callback chain of unit validation is not something the surrounding async-style error handling (`cb`/`cb2` callbacks) can catch, since it's a JS exception, not a callback error. Depending on how the node process handles unhandled exceptions, this either crashes the node process or aborts validation of that unit in an inconsistent, non-deterministic way relative to other implementations, leading to a remote, low-cost, unauthenticated denial-of-service against any full node that validates the crafted unit (mirroring the "remote denial of service... if terminfo library code is used to process untrusted data" impact of the original CVE). If some nodes fail to process the unit while others don't, this also risks disagreement on unit validity across the network.

### Likelihood Explanation
High reachability: any unprivileged party can post a unit whose author definition contains an `'in merkle'` condition and control the `authentifiers` payload for that path with an arbitrary JSON type, with no privileged role, hub cooperation, or timing requirement needed to trigger the code path.

### Recommendation
Add an explicit type check before calling `merkle.deserializeMerkleProof` in the `'in merkle'` branch of `definition.js`, mirroring the `'hash'` branch:
```js
if (!assocAuthentifiers[path] || typeof assocAuthentifiers[path] !== 'string')
    return cb2(false);
```
Additionally, wrap `merkle.deserializeMerkleProof`/`merkle.verifyMerkleProof` in a `try/catch` (as already done in `formula/evaluation.js`) so malformed proof strings (e.g. missing dashes) fail safely instead of throwing.

### Proof of Concept
1. Craft an address whose definition is `['in merkle', [['SOME_ADDR'], 'feed_name', 'element']]`.
2. Post a unit authored by that address (or referencing it) where `authentifiers` for the corresponding path (`'r'` or nested path) is set to a non-string JSON value, e.g. `authentifiers: { "r": 12345 }` or `{ "r": [] }`.
3. When the node validates the unit and reaches `validateAuthentifiers` → the `'in merkle'` case in `definition.js` (lines 1004-1020), `serialized_proof.split` is invoked on a non-string, throwing an uncaught `TypeError` inside the validation call chain, crashing/destabilizing the validating node. [1](#0-0) [3](#0-2)

### Citations

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

**File:** formula/evaluation.js (L1783-1804)
```javascript
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

**File:** validation.js (L1243-1254)
```javascript
	function validateAuthentifiers(arrAddressDefinition){
		Definition.validateAuthentifiers(
			conn, objAuthor.address, null, arrAddressDefinition, objUnit, objValidationState, objAuthor.authentifiers, 
			function(err, res){
				if (err) // error in address definition
					return callback(err);
				if (!res) // wrong signature or the like
					return callback("authentifier verification failed");
				checkSerialAddressUse();
			}
		);
	}
```
