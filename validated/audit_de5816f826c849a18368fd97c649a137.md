## Title
Unvalidated Merkle-proof `index` allows attacker-controlled hash-path selection in `verifyMerkleProof` - (File: merkle.js)

### Summary
`merkle.js`'s `deserializeMerkleProof()` builds a `proof.index` field directly from an attacker-supplied string with no type or range check, and `verifyMerkleProof()` then uses that raw value to decide, at every level of the tree, whether to hash `element` on the left or right side (`index % 2 === 0`). This mirrors the audify CWE-129 pattern: an index value coming straight from external input is consumed by an array/positional operation without validating that it is a proper non-negative integer within bounds.

### Finding Description
`getMerkleProof()` (producer side) does validate the index: [1](#0-0) 
but the consumer path never performs an equivalent check. `deserializeMerkleProof()` simply splits an attacker-controlled string on `-` and assigns the first token to `proof.index` as a **string**, with no numeric/format validation: [2](#0-1) 

`verifyMerkleProof()` then consumes `proof.index` directly: [3](#0-2) 
Because JavaScript coerces the string in `index % 2` and `Math.floor(index / 2)`, an attacker can supply `index` as any string (negative, fractional, non-numeric, or arbitrarily large), fully controlling the left/right ordering used to combine `element` with each attacker-chosen sibling hash at every tree level. There is no check that `index` corresponds to a valid position (`0 <= index < 2^siblings.length`) as is enforced on the producer side.

This code path is reachable from unprivileged unit posters and AA triggers in two places:
- `definition.js`'s `'in merkle'` opcode, which parses a serialized proof taken directly from an author's `authentifiers` field of a posted unit and passes it into `merkle.verifyMerkleProof`: [4](#0-3) 
- The oscript/AA formula function `is_valid_merkle_proof`, which parses attacker-supplied `proof` (as an object or as a string via `deserializeMerkleProof`) coming from `trigger.data` and calls `merkle.verifyMerkleProof`: [5](#0-4) 

Note that a later `bPostPemCurvesFix` hardening path added constraints on `siblings` (must be non-empty strings, capped at 50 entries) but does **not** constrain `index`: [6](#0-5) 

### Impact Explanation
Because both the `element`/`siblings` and now the `index` are fully attacker-controlled, and the only real cryptographic constraint is that the resulting `root` must equal a value already established (a previously-posted data feed value in `'in merkle'`, or an arbitrary comparison value in `is_valid_merkle_proof`), the missing index validation removes one of the few structural constraints intended to make forging a proof harder. An attacker who can also influence or predict the target root (e.g., a data feed value they or a colluding oracle posted) gains additional freedom (unconstrained tree depth/direction) to search for a colliding hash path. In `'in merkle'`, satisfying this condition can unlock spending or authorization paths gated by that address's definition, i.e., unauthorized spending. In AA formulas, it can cause bad-actor triggers to satisfy assertions that gate fund release, contributing to AA fund loss. Because the check is deterministic and executed identically by all full nodes, it does not itself cause a stability/consensus split, but it weakens a security check that unlocks spending authority.

### Likelihood Explanation
Reaching this code requires only posting a normal unit whose definition contains an `'in merkle'` clause (attacker or victim can define such an address) with attacker-supplied `authentifiers`, or triggering an AA that uses `is_valid_merkle_proof` on trigger-supplied data — both are standard, unprivileged actions available to any unit poster / AA trigger sender. However, actually leveraging the missing index check to forge a valid proof still requires finding a hash collision against a fixed target root, which is a strong cryptographic hurdle (SHA-256). This significantly limits practical exploitability, so likelihood is assessed as Medium (reachable with a single posted unit/trigger, but not trivially weaponizable without a hash collision or a colluding root generator).

### Recommendation
In `merkle.js`, validate `proof.index` in `deserializeMerkleProof()` (or at the start of `verifyMerkleProof()`): require it to be a non-negative integer, parse it with `parseInt`/`Number`, and reject the proof (return `false`) if it is not an integer, is negative, or exceeds the value implied by `2^siblings.length`. This restores parity with the validation already performed in `getMerkleProof()` and removes the attacker's ability to manipulate hash-path direction via a malformed index.

### Proof of Concept
1. Craft a unit whose author's address definition contains `["in merkle", [[oracle_address], "feed_name", "some_element"]]`.
2. In the posted unit, supply `authentifiers[path]` as a serialized proof string of the form `<arbitrary_index>-<sibling1>-<sibling2>-...-<root>`, where `<arbitrary_index>` is any string such as `-99999` or `abc` (not validated) and `siblings`/`root` are chosen so that `verifyMerkleProof('some_element', proof)` evaluates the hash chain using attacker-chosen left/right ordering at each level (`index % 2 === 0` branch taken per attacker choice via non-numeric or out-of-range index coercion).
3. Because the ordering constraint imposed by a well-formed index is bypassed, an attacker searching for a value of `root` that matches an existing data-feed entry (or an `is_valid_merkle_proof` comparison target in an AA formula) has strictly more freedom than intended by the design in `getMerkleProof`, demonstrating that the consumer path accepts index values the producer path would reject as `"invalid index"`.

### Citations

**File:** merkle.js (L22-24)
```javascript
function getMerkleProof(arrElements, element_index){
	if (element_index < 0 || element_index >= arrElements.length)
		throw Error("invalid index");
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
