### Title
Unhandled Type-Confusion Crash in Merkle-Proof Authentifier Deserialization — ([File: definition.js])

### Summary
CVE-2016-7130 is a PHP WDDX NULL-pointer dereference that happens because `php_wddx_pop_element` blindly casts an attacker-supplied "binary" element without validating its structure before dereferencing it, crashing the process. The `'in merkle'` authentifier handler in ocore's address-definition evaluator has an analogous root cause: it accepts an attacker-controlled `authentifiers[path]` value with only a truthiness check and passes it directly into `merkle.deserializeMerkleProof()`, which performs `.split("-")` on the value with no type guard and no surrounding `try/catch`.

### Finding Description
In `validateAuthentifiers()`, the `'sig'` and `'hash'` authentifier branches type-check the corresponding `assocAuthentifiers[path]` value (the `'hash'` branch explicitly checks `typeof assocAuthentifiers[path] !== 'string'`): [1](#0-0) 

But the `'in merkle'` branch only checks truthiness before treating the value as a serialized proof string: [2](#0-1) 

`merkle.deserializeMerkleProof()` calls `.split("-")` unconditionally with no type check and no `try/catch`: [3](#0-2) 

`verifyMerkleProof()` itself is wrapped in a `try/catch`, so malformed *string* proofs are handled gracefully: [4](#0-3) 

But `deserializeMerkleProof()` is invoked *outside* any `try/catch` at `definition.js:1014`, and the only other in-repo caller (`formula/evaluation.js`) safely wraps it in `try/catch`: [5](#0-4) 

The `authentifiers` object comes from `objAuthor.authentifiers`, which is part of the raw, attacker-supplied unit JSON, keyed by arbitrary signing paths chosen to match an `'in merkle'` node of an address definition. An unprivileged unit poster who controls (or co-signs with) an address whose spending definition contains an `'in merkle'` condition can set the authentifier for that path to a non-string, truthy JSON value (a number, boolean `true`, array, or object) instead of the expected dash-separated proof string. Because there is no `typeof ... === 'string'` check, this value reaches `serialized_proof.split("-")`, which throws an uncaught `TypeError` (`serialized_proof.split is not a function`) since `.split` does not exist on non-string types.

### Impact Explanation
`validateAuthentifiers()` is executed by every node that validates the unit (including full nodes maintaining consensus). An uncaught synchronous `TypeError` thrown from inside the `async.eachSeries` evaluation chain is not handled by any surrounding `try/catch` in this code path, which can crash the Node.js process validating the unit (unhandled exception), exactly mirroring the WDDX NULL-pointer crash triggered by a malformed base64 binary element. Because the crash is triggered deterministically by the bytes of a single posted unit, an attacker can broadcast such a unit to make every full node that attempts to validate it crash — a network-wide denial-of-service that prevents further unit confirmation, or causes nodes that crash/restart at different points to diverge on which units they have processed (validity/stability disagreement).

### Likelihood Explanation
Reaching this code path requires only:
1. Defining (or co-authoring) an address whose spending definition contains an `'in merkle'` condition (a standard, unprivileged oscript/definition feature).
2. Posting a unit that supplies a non-string value for the corresponding authentifier path.

No special privileges, hub/node compromise, or private key material beyond normal unit posting is needed, so likelihood is high once an `'in merkle'`-based address exists (attacker can create their own such address to trigger it).

### Recommendation
Add an explicit `typeof assocAuthentifiers[path] !== 'string'` (and reasonable length) check in the `'in merkle'` branch of `definition.js`, mirroring the `'hash'` branch, and additionally wrap the `merkle.deserializeMerkleProof()` / `merkle.verifyMerkleProof()` calls in a `try/catch` so malformed authentifier values fail the branch (`cb2(false)`) instead of throwing.

### Proof of Concept
1. Create an address whose definition includes an `'in merkle'` condition, e.g. `["in merkle", [["ORACLE_ADDR"], "feed_name", "element"]]`.
2. Construct and post a unit spending from that address where `author.authentifiers["r"]` (or the relevant path) is set to a non-string truthy value, e.g. `12345` or `true` or `["not","a","string"]`, instead of the expected `"index-sibling1-sibling2-root"` string.
3. When validating nodes call `validateAuthentifiers` → `evaluate()` for the `'in merkle'` op, `merkle.deserializeMerkleProof(12345)` executes `(12345).split("-")`, throwing an uncaught `TypeError` that is not caught anywhere in the call chain, crashing the validating process.

Note: I could not execute this against a live node to directly observe process termination vs. a caught rejection higher up the stack (e.g., a top-level `db.query`/mutex wrapper); confirming the exact failure mode (hard crash vs. silently rejected unit) would require running the validation pipeline end-to-end, which is out of scope for static analysis.

### Citations

**File:** definition.js (L756-760)
```javascript
			case 'hash':
				// ['hash', {algo: 'sha256', hash: 'base64'}]
				if (!assocAuthentifiers[path] || typeof assocAuthentifiers[path] !== 'string')
					return cb2(false);
				arrUsedPaths.push(path);
```

**File:** definition.js (L1004-1014)
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

**File:** merkle.js (L84-101)
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
```

**File:** formula/evaluation.js (L1785-1804)
```javascript
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
