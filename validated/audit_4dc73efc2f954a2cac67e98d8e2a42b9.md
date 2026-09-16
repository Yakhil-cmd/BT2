## Title
Merkle proof verification lacks leaf/node domain-separation and index-completion checks, enabling forged membership proofs in AA merkle checks - (File: merkle.js)

### Summary
`merkle.verifyMerkleProof` in [1](#0-0)  hashes both leaves and internal tree nodes with the same `hash()` function with no domain separation, and never checks that the final `index` has been fully consumed / that the proof length actually corresponds to the claimed position's real depth in the tree. This mirrors the reported "unbalanced tree" class of bug: the verifier accepts any attacker-chosen `(element, index, siblings, root)` combination as long as the resulting hash chain matches `root`, without any structural guarantee that the supplied path is consistent with a genuine leaf at a genuine depth.

### Finding Description
`getMerkleRoot`/`getMerkleProof` build the tree by repeatedly hashing pairs of node values with `hash(str)` = `sha256` [2](#0-1) , and internal nodes are produced exactly the same way as leaves (`hash(arrHashes[i] + arrHashes[hash2_index])`) [3](#0-2) . `verifyMerkleProof` then does:
```
var the_other_sibling = hash(element);
for (var i = 0; i < proof.siblings.length; i++) { ... index = Math.floor(index/2); }
return (the_other_sibling === proof.root);
``` [1](#0-0) 

There is no domain-separation prefix distinguishing "this is a leaf" from "this is an internal node", and the code's own comment flags the risk: `// Node-as-Leaf issue might matter in some cases` (line 85). Because of this, anyone who can compute (or has previously observed) the concatenation of two sibling hashes at some internal level of a tree can present that raw concatenation string as the "element" and supply the remaining upper-level siblings/index as the "proof" — `hash(element)` will equal that internal node's real hash, and the rest of the chain up to `root` verifies successfully, even though the concatenation string was never one of the tree's actual data elements.

This routine is exposed to fully attacker-controlled input via the `is_valid_merkle_proof` oscript function, used in AA formulas: `element` and `proof` (including `proof.root`) come directly from `evaluate()` of attacker-supplied expressions (typically `trigger.data.*`) [4](#0-3) , with only length/type sanity checks (max 1024 chars, siblings array of strings, max 50 siblings) — no leaf/node domain check.

It is also reachable in address-definition authentifiers via `'in merkle'` [5](#0-4) , but there `element` is fixed at definition-authoring time and constrained by a strict regex [6](#0-5) , so the attacker cannot choose it — the AA path is the practically exploitable one because both `element` and the whole `proof` object are dynamic trigger data.

### Impact Explanation
If an AA's oscript logic uses `is_valid_merkle_proof(trigger.data.element, {index, siblings, root: <trusted root>})` to gate a fund-releasing action (e.g., verifying a claimant is part of a whitelist/allocation set whose root the AA trusts, coming from a data feed or a previously stored state var), an attacker who can derive any internal node's two children (which is generally derivable for any public, deterministically-constructed tree, e.g. a published whitelist) can craft `element` = concatenation of those two child hash strings and a `proof` consisting of the remaining upper path, causing the check to pass for a value that was never a genuine tree leaf. This lets the attacker satisfy a membership check they should not pass, potentially triggering unauthorized fund release/allocation from the AA — an AA fund-loss scenario.

### Likelihood Explanation
Exploitability requires: (1) an AA that uses `is_valid_merkle_proof` against a root value that is trusted/fixed but whose full leaf set is public or otherwise learnable (so internal node preimages can be computed), and (2) the AA's downstream logic treating a positive `is_valid_merkle_proof` result as sufficient authorization without further binding the "element" to caller identity. This is a plausible but non-universal AA design pattern; the underlying library flaw itself is unconditionally present and already flagged in code comments as a known risk that was never mitigated.

### Recommendation
Add domain separation to `merkle.js`'s hashing: prefix leaf hashing and internal-node hashing with distinct tags/bytes (e.g., `hash("\x00"+element)` for leaves vs `hash("\x01"+left+right)` for internal nodes) so a forged concatenation can never be mistaken for a genuine leaf. Additionally, since the number of loop iterations in `verifyMerkleProof` is driven entirely by the length of `proof.siblings` (attacker-controlled), consider binding/validating that length against the real tree depth (or otherwise validating `proof.index`/`proof.siblings.length` consistency) wherever the resulting root is compared against a trusted value, analogous to the recommended `log2(index) == proof.length` check in the original report.

### Proof of Concept
1. Oracle/admin publishes (or it is otherwise publicly known) a set of elements `E = [e0, e1, ..., en]` and posts `getMerkleRoot(E)` as a data feed value / AA state var that some AA treats as a "trusted whitelist root".
2. Anyone can locally recompute the full tree using `merkle.getMerkleRoot`/`getMerkleProof` logic [7](#0-6)  since the hash function and combination rule are public and elements are known/public.
3. Pick any internal node at some level with children hash strings `h_left`, `h_right`. Set `forged_element = h_left + h_right`.
4. Build `proof = { index: <position of that internal node one level up>, siblings: <the siblings from that level up to the root>, root: <trusted root> }`.
5. Call the AA trigger with `trigger.data.element = forged_element`, `trigger.data.proof = proof`; `is_valid_merkle_proof` in [8](#0-7)  returns `true` even though `forged_element` was never a genuine element of `E`, because `verifyMerkleProof` only checks the final hash equals `root`, never that the leaf-level input was actually hashed as a "leaf" rather than as a pre-existing internal node value [9](#0-8) .

### Citations

**File:** merkle.js (L5-55)
```javascript
function hash(str){
	return crypto.createHash("sha256").update(str, "utf8").digest("base64");
}

function getMerkleRoot(arrElements){
	var arrHashes = arrElements.map(hash);
	while (arrHashes.length > 1){
		var arrOverHashes = []; // hashes over hashes
		for (var i=0; i<arrHashes.length; i+=2){
			var hash2_index = (i+1 < arrHashes.length) ? (i+1) : i; // for odd number of hashes
			arrOverHashes.push(hash(arrHashes[i] + arrHashes[hash2_index]));
		}
		arrHashes = arrOverHashes;
	}
	return arrHashes[0];
}

function getMerkleProof(arrElements, element_index){
	if (element_index < 0 || element_index >= arrElements.length)
		throw Error("invalid index");
	var arrHashes = arrElements.map(hash);
	var index = element_index;
	var arrSiblings = [];
	while (arrHashes.length > 1){
		var arrOverHashes = []; // hashes over hashes
		var overIndex = null;
		for (var i=0; i<arrHashes.length; i+=2){
			var hash2_index = (i+1 < arrHashes.length) ? (i+1) : i; // for odd number of hashes
			if (i === index){
				arrSiblings.push(arrHashes[hash2_index]);
				overIndex = i/2;
			}
			else if (hash2_index === index){
				arrSiblings.push(arrHashes[i]);
				overIndex = i/2;
			}
			arrOverHashes.push(hash(arrHashes[i] + arrHashes[hash2_index]));
		}
		arrHashes = arrOverHashes;
		if (overIndex === null)
			throw Error("overIndex not defined");
		index = overIndex;
	}
	// add merkle root
	//arrSiblings.push(arrHashes[0]);
	return {
		root: arrHashes[0],
		siblings: arrSiblings,
		index: element_index
	};
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

**File:** definition.js (L445-478)
```javascript
			case 'in merkle':
				if (bInNegation)
					return cb(op+" cannot be negated");
				if (objValidationState.bNoReferences)
					return cb("no references allowed in address definition");
				if (bAssetCondition)
					return cb("asset condition cannot have "+op);
				if (!Array.isArray(args))
					return cb(op+" arg must be array");
				if (args.length !== 3 && args.length !== 4)
					return cb(op+" must have 3 or 4 args");
				var arrAddresses = args[0];
				var feed_name = args[1];
				var element = args[2];
				var min_mci = args[3];
				if (!isNonemptyArray(arrAddresses))
					return cb("no addresses in "+op);
				for (var i=0; i<arrAddresses.length; i++)
					if (!isValidAddress(arrAddresses[i])) // it is ok if the address was never used yet
						return cb("oracle address not valid");
				complexity += arrAddresses.length-1; // 1 complexity point for each address (1 point was already counted)
				if (!isNonemptyString(feed_name))
					return cb("no feed_name");
				if (feed_name.length > constants.MAX_DATA_FEED_NAME_LENGTH)
					return cb("feed_name too long");
				if (!isNonemptyString(element))
					return cb("no element");
			//	if (!isStringOfLength(element_hash, constants.HASH_LENGTH))
			//		return cb("incorrect length of element hash");
				if (!element.match(/^[\w ~,.\/\\;:!@#$%^&*\(\)=+\[\]\{\}<>\?|-]{1,100}$/))
					return cb("incorrect format of merkled element");
				if (typeof min_mci !== 'undefined' && !isNonnegativeInteger(min_mci))
					return cb(op+": invalid min_mci");
				return cb();
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
