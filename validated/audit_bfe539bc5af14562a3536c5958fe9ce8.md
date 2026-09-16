### Title
Missing size limit on `in merkle` authentifier proof allows unbounded-cost hash-loop DoS during unit validation - (File: `definition.js`)

### Summary
The `in merkle` address-definition operator deserializes an attacker-supplied authentifier string into an array of "siblings" with no upper bound on how many siblings it may contain, then iterates that array performing a SHA-256 hash per element inside `verifyMerkleProof`. This mirrors the Pillow `PsdImageFile` bug class (CVE-2021-28675): a declared/implicit item count taken from untrusted input is used to drive parsing/processing work without a sanity check bounding it against a reasonable maximum, letting one malicious input trigger disproportionate CPU work during validation.

### Finding Description
In `definition.js`'s `validateAuthentifiers`, the `'in merkle'` case reads the raw authentifier value supplied by the unit's author and hands it straight to the merkle-proof code: [1](#0-0) 

`deserializeMerkleProof` builds the `siblings` array purely by splitting the attacker-controlled string on `-`, with no cap on the number of resulting elements: [2](#0-1) 

`verifyMerkleProof` then loops once per sibling, computing a SHA-256 hash on every iteration: [3](#0-2) 

By contrast, the equivalent oscript function `is_valid_merkle_proof` (used inside AA formulas) was hardened with an explicit bound after the "PEM curves fix": it requires `siblings` to be a non-empty-string array and caps its length at 50 elements before calling `verifyMerkleProof`: [4](#0-3) 

No such length check exists on the `'in merkle'` address-authentifier path in `definition.js`. Furthermore, `validateAuthentifiers`'s `evaluate` function (unlike `validateDefinition`'s `evaluate`) does not track `complexity`/`count_ops` at all, so this operator's cost is not throttled by the definition's `MAX_COMPLEXITY`/`MAX_OPS` limits: [5](#0-4) 

The only bound on the authentifier string's raw length is the unit-wide size ceiling (`MAX_UNIT_LENGTH`), which is orders of magnitude larger than what's needed to build tens of thousands of dash-separated tokens (each just a few bytes long), so an attacker can pack a huge number of "siblings" into one signed authentifier.

### Impact Explanation
An unprivileged unit poster who controls (or bootstraps) an address whose definition contains an `['in merkle', ...]` clause on one authentifier path can submit a unit whose authentifier for that path is a string with an enormous number of dash-separated fake "siblings." Every full node that receives and validates this unit — during normal gossip/validation, not just a malicious peer scenario — will execute `verifyMerkleProof`'s loop, performing one SHA-256 hash per sibling with no cap and no complexity accounting. This is a synchronous, CPU-bound computation performed inline during unit validation (`validateAuthentifiers` → `validateAuthor` → `validate`), which can stall processing of legitimate units on that node while it validates the oversized proof, degrading the node's ability to confirm new units in a timely manner — consistent with the "network unable to confirm new units" impact category for a validation-cost DoS triggered by a single posted unit.

### Likelihood Explanation
Likelihood is moderate-to-high: any unprivileged user can create an address whose definition uses `'in merkle'`, and can be the "unit poster" who signs/submits a unit using that address, controlling the authentifier value passed on that path (there is no requirement that the string be a real, cryptographically meaningful proof for it to be parsed and iterated — `deserializeMerkleProof` accepts anything splittable by `-`, and the loop runs regardless of whether the proof will ultimately verify). No cooperation from other nodes, hubs, or peers is required; the attack surface is the standard unit-validation path any full node performs on any incoming unit.

### Recommendation
Add a sanity check on the number of siblings (and/or the raw authentifier string length) before calling `merkle.verifyMerkleProof` in the `'in merkle'` authentifier-evaluation path in `definition.js`, mirroring the existing 50-sibling cap used in `formula/evaluation.js`'s `is_valid_merkle_proof`. Additionally, consider adding the same check inside `merkle.deserializeMerkleProof`/`verifyMerkleProof` themselves so all callers are protected uniformly, and factor the cost of `'in merkle'` evaluation into `validateAuthentifiers`'s complexity accounting the way `validateDefinition` already does for other operators.

### Proof of Concept
1. Create an address whose definition is `['in merkle', [[oracleAddress], 'feed_name', 'element']]` (a valid, unremarkable definition).
2. Compose a unit signed from that address where the authentifier for this path is set to a string of the form `"0-<X>-<X>-<X>-...-<root>"` with tens of thousands of short dash-separated tokens `<X>` instead of a real few-sibling proof.
3. Submit the unit to the network as an ordinary unprivileged poster.
4. Each validating node calls `validateAuthentifiers` → `merkle.deserializeMerkleProof(serialized_proof)` (`definition.js:1013-1014`), producing a `siblings` array with tens of thousands of entries, then `merkle.verifyMerkleProof` (`definition.js:1016`) iterates it, computing a SHA-256 hash per entry (`merkle.js:89-96`), with no length cap and no complexity-limit rejection anywhere on this path — unlike the analogous `is_valid_merkle_proof` oscript function which rejects proofs with more than 50 siblings.

Note: I was not able to run the code to empirically measure the exact wall-clock cost multiplier for a given unit-size budget; this assessment is based on static analysis of the reachable code paths and the absence of the same guard that was deliberately added to the sibling `formula/evaluation.js` counterpart.

### Citations

**File:** definition.js (L646-711)
```javascript
function validateAuthentifiers(conn, address, this_asset, arrDefinition, objUnit, objValidationState, assocAuthentifiers, cb){
	
	function evaluate(arr, path, cb2){
		var op = arr[0];
		var args = arr[1];
		switch(op){
			case 'or':
				// ['or', [list of options]]
				var res = false;
				var index = -1;
				async.eachSeries(
					args,
					function(arg, cb3){
						index++;
						evaluate(arg, path+'.'+index, function(arg_res){
							res = res || arg_res;
							cb3(); // check all members, even if required minimum already found
							//res ? cb3("found") : cb3();
						});
					},
					function(){
						cb2(res);
					}
				);
				break;
				
			case 'and':
				// ['and', [list of requirements]]
				var res = true;
				var index = -1;
				async.eachSeries(
					args,
					function(arg, cb3){
						index++;
						evaluate(arg, path+'.'+index, function(arg_res){
							res = res && arg_res;
							cb3(); // check all members, even if required minimum already found
							//res ? cb3() : cb3("found");
						});
					},
					function(){
						cb2(res);
					}
				);
				break;
				
			case 'r of set':
				// ['r of set', {required: 2, set: [list of options]}]
				var count = 0;
				var index = -1;
				async.eachSeries(
					args.set,
					function(arg, cb3){
						index++;
						evaluate(arg, path+'.'+index, function(arg_res){
							if (arg_res)
								count++;
							cb3(); // check all members, even if required minimum already found, so that we don't allow invalid sig on unchecked path
							//(count < args.required) ? cb3() : cb3("found");
						});
					},
					function(){
						cb2(count >= args.required);
					}
				);
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

**File:** formula/evaluation.js (L1792-1797)
```javascript
						if (bPostPemCurvesFix) {
							if (!Array.isArray(objProof.siblings) || !objProof.siblings.every(ValidationUtils.isNonemptyString))
								return cb(false);
							if (objProof.siblings.length > 50)
								return cb(false);
						}
```
