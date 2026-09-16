### Title
Type confusion / uncaught exception in `merkle.deserializeMerkleProof` reachable via `in merkle` address-definition authentifier - ([File: definition.js])

### Summary
The `in merkle` definition-element evaluator in `definition.js` passes an attacker-controlled authentifier value directly into `merkle.deserializeMerkleProof()` without first validating that it is a string. `deserializeMerkleProof()` unconditionally calls `.split("-")` on its argument, which throws an uncaught `TypeError` if the value is not a string (e.g. a number, object, array, boolean, or `null`). This mirrors the CVE-2017-9083 bug class: a parsing routine dereferences/consumes attacker-supplied structured input without validating its type/shape first, causing an unhandled crash while processing a single, otherwise well-formed untrusted input.

### Finding Description
`in merkle` is a definition template element type (`['in merkle', [addresses, feed_name, element, min_mci]]`) whose satisfaction is proven by an authentifier value supplied by the unit's author in `unit.authors[i].authentifiers[path]`. In `definition.js`, `validateAuthentifiers`'s `evaluate()` handles this case: [1](#0-0) 

`serialized_proof` is taken straight from `assocAuthentifiers[path]` — the raw authentifier value attached by the unit author — with only a truthiness check (`if (!assocAuthentifiers[path]) return cb2(false);`), not a type check. It is then handed to: [2](#0-1) 

`deserializeMerkleProof` calls `serialized_proof.split("-")` immediately, with no type guard and no `try/catch`. If `serialized_proof` is anything other than a string (e.g. a JSON number, boolean, array, or object placed in the authentifiers map of a posted unit), `.split` is not a function on that value and a `TypeError` is thrown synchronously inside `evaluate()`, which is itself invoked synchronously from `validateAuthentifiers` during unit validation. Unlike the sibling `is_valid_merkle_proof` oscript function, which wraps the analogous call in `try { ... } catch (e) { res = false; }`: [3](#0-2) 

the `in merkle` definition-element branch in `definition.js` has no such protection.

Whether this throw is caught by an outer handler in the validation pipeline (e.g. a top-level `validate()` try/catch or an async wrapper) determines whether the effect is merely "this unit fails to validate" or "the calling process/promise chain crashes/hangs uncaught." I was not able to fully trace every call path from unit posting through to `validateAuthentifiers` within the available search budget to confirm whether validation code wraps this call in `try/catch` at a higher level; this is the main uncertainty in this analysis.

### Impact Explanation
If the surrounding validation code does not catch the exception, any node evaluating a unit whose author places a non-string value at the `in merkle` authentifier path throws an unhandled `TypeError`. Because unit validation is on the hot path for accepting/relaying new units, an uncaught exception here can crash the validating node process or leave the validation callback chain in an inconsistent state (never calling `ifUnitError`/`ifOk`), which is a denial-of-service against the specific node processing the malicious unit — impacting the network's ability to confirm new units if propagated to multiple nodes using an address that has an `in merkle` definition element.

### Likelihood Explanation
Likelihood is contingent on the definition actually containing an `in merkle` element that some address uses, and on an unprivileged unit author supplying a wrong-typed value into the corresponding authentifier slot of the unit they post — both of which are within reach of a single posted unit with attacker-chosen authors/definition/authentifiers, requiring no privileged access. However, `in merkle` definitions require the address owner (or an author of a shared/multi-sig address) to have set up this definition element in advance, which somewhat limits realistic exploitation to addresses/wallets that already use `in merkle`.

### Recommendation
- In `merkle.js`, harden `deserializeMerkleProof` to validate that its input is a non-empty string before calling `.split`, and to validate the resulting `proof.root`/`proof.index`/`proof.siblings` shapes, returning/throwing a normal validation error rather than a raw TypeError.
- In `definition.js`'s `in merkle` case, explicitly check `typeof assocAuthentifiers[path] === 'string'` before calling `merkle.deserializeMerkleProof`, and wrap the deserialize/verify call in `try/catch`, treating any failure as `cb2(false)` (mirroring the `is_valid_merkle_proof` oscript implementation in `formula/evaluation.js`).

### Proof of Concept
1. Create/have an address whose definition contains an `in merkle` element (e.g. `['in merkle', [['SOME_ORACLE_ADDRESS'], 'feed_name', 'expected_value']]`) at authentifier path `r`.
2. Craft and post a unit authored by that address where `unit.authors[0].authentifiers.r` is set to a non-string JSON value (e.g. `123`, `true`, `[]`, or `{}`) instead of the expected `"index-sibling1-sibling2-root"` string.
3. Submit the unit to a node for validation. `validateAuthentifiers` reaches the `'in merkle'` case, calls `merkle.deserializeMerkleProof(123)`, which executes `(123).split("-")`, throwing an uncaught `TypeError` inside the synchronous evaluation callback, disrupting validation of that unit (and, depending on surrounding error handling, potentially crashing/hanging the validating process).

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

**File:** formula/evaluation.js (L1798-1804)
```javascript
						try {
							res = merkle.verifyMerkleProof(element, objProof);
						}
						catch (e) {
							res = false;
						}
						cb(res);
```
