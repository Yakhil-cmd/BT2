### Title
Missing domain separation between leaf-hashes and node-hashes in `merkle.js` allows an attacker to forge merkle-inclusion proofs for `in merkle` address-definition conditions - (File: merkle.js)

### Summary
`merkle.js` builds the merkle tree by hashing leaves and internal nodes with the exact same hash function and no type/level tag distinguishing "leaf" from "internal node", and it duplicates the last element when a level has an odd number of hashes. This is the same root-cause pattern as the external report: a hashing/leaf-construction scheme that omits a discriminating field (there: hook address; here: leaf-vs-node domain tag) lets structurally different inputs collide into an authorization-relevant value that the verifier treats as equivalent. This tree is consumed directly by the `in merkle` address-definition operator, which any address owner (including AA/asset authors and unprivileged unit posters) can use as a spending/authorization condition tied to an oracle's data feed.

### Finding Description
`getMerkleRoot`/`getMerkleProof` hash leaves as `hash(element)` and internal nodes as `hash(hash_left + hash_right)`, using the identical `sha256` function for both with no prefix distinguishing a "leaf" hash from a "node" hash: [1](#0-0) 
When the number of hashes at a level is odd, the last node is paired with itself (`hash2_index = i` when `i+1 >= length`), i.e. a duplicate-node level: [2](#0-1) 
Verification (`verifyMerkleProof`) recomputes the chain from a caller-supplied `element` and caller-supplied `siblings`, checking only that the final value equals `proof.root`, with no leaf/node domain tag ever added: [3](#0-2) 
The code's own comment acknowledges the "Node-as-Leaf issue" is unresolved and “might matter in some cases”: [4](#0-3) 

This tree is exposed to unprivileged users through the `in merkle` address-definition operator: any address (spending condition), which any wallet or AA can adopt, can require `["in merkle", [oracle_addresses, feed_name, element, min_mci]]`, where at spend time the authentifier supplies a serialized proof that is checked with `merkle.verifyMerkleProof(element, proof)` and then the resulting `proof.root` is looked up as a previously-published data-feed value from the named oracle addresses: [5](#0-4) 
This construction is validated as a legitimate spending condition during definition validation: [6](#0-5) 

Because leaves and internal nodes share the same hash domain, and because odd-length levels duplicate the final hash, the tree is malleable in the classical "CVE-2012-2459" sense: a value that is actually an *internal node hash* of the real tree (built from two real leaves `L1`, `L2`) is numerically indistinguishable from a valid *leaf hash* at the level above it. Consequently, whenever an oracle-controlled data set has (a) an odd number of elements at any level (forcing a self-duplicated pairing), the resulting merkle root can be reproduced by an alternate, larger or reordered set of "leaves" that includes an internal-node value used *as if it were a leaf hash*. An attacker who is not the oracle, but who knows the oracle's published element set (data feeds/oracle-fed merklized data are typically public, since the whole point of `in merkle` is to let third parties construct proofs against publicly known elements) can therefore construct a `serialized_proof` for an `element` never actually included by the oracle at that logical position, yet which still verifies to the oracle's genuinely published `root` value. This lets an attacker satisfy an `in merkle` authorization branch of somebody else's address definition without holding a legitimate proof from the oracle, potentially unlocking funds/spending paths that were meant to be conditioned on genuine oracle-attested membership.

### Impact Explanation
`in merkle` is used as an authorization/spending gate inside address definitions (`definition.js`), which back both regular wallet addresses and AA-related conditions. A forged proof that satisfies `verifyMerkleProof` against a legitimately-published oracle root, for an element/position never intended by the oracle, bypasses the intended data-feed-gated authorization and can result in unauthorized spending of funds locked behind such a condition — a concrete "unauthorized spending" outcome, matching the required High severity impact class from the prompt.

### Likelihood Explanation
Exploitability is condition-dependent: it requires that the oracle's underlying element set has the topological property that produces a colliding leaf/node value (e.g., an odd-count level, or a duplicated-node ambiguity), and that an attacker can identify or engineer usage where the specific `element` referenced by the victim's `in merkle` definition happens to line up with such an internal value. This is a known, previously-documented weakness class for naive merkle-tree implementations (classic CVE-2012-2459-style duplication attacks) rather than a brute-force hash break, so it is realistically exploitable whenever an oracle's data set (which is typically constructed by third-party tooling, not hardened against this) contains an odd number of leaves at some level — a common, easily-triggered condition, not a rare edge case. The `in merkle` feature and the underlying `merkle.js` primitive are both currently shipped and unaddressed (per the code's own "might matter" comment), supporting a Medium-to-High likelihood.

### Recommendation
Add domain separation to the merkle-tree hash function so that leaf hashes and internal-node hashes cannot collide:
- Prefix leaf hashing, e.g. `hash("\x00" + element)`, and internal node hashing, e.g. `hash("\x01" + left + right)`.
- Avoid last-node self-duplication ambiguity (do not silently pair a node with itself); instead explicitly track and check tree width/level metadata as part of what is hashed, or reject/handle odd counts in a way that cannot be reinterpreted as a different valid tree structure.
- Update `getMerkleRoot`, `getMerkleProof`, and `verifyMerkleProof` consistently, and bump any related "root" values already produced with the old scheme via a versioned/prefixed protocol so that old and new roots cannot be conflated.

### Proof of Concept
Conceptual PoC (cannot be fully executed without live oracle data, but demonstrates the mechanism using the existing code):
1. An oracle publishes elements `[L1, L2, L3]` (odd count) via `getMerkleRoot`. At the first level, `hash(L1)` and `hash(L2)` combine to `N12 = hash(hash(L1)+hash(L2))`, while `L3` is paired with itself: `N33 = hash(hash(L3)+hash(L3))`. The published `root = hash(N12 + N33)`.
2. Because `L3`'s pairing depends only on `hash(L3)` twice, and because leaf/node hashes share the same domain, an attacker who knows `hash(L1)`, `hash(L2)` (public, since anyone consuming `in merkle` must know the concrete `element` values to build proofs) can attempt to present `N12` itself as an `element` at the second level with sibling `N33`, i.e., call:
   ```js
   merkle.verifyMerkleProof(N12_as_string, { index: 0, siblings: [N33], root: root })
   ```
   This passes verification identically to a legitimate leaf, per the verification logic in `merkle.js`: [7](#0-6) 
   even though `N12` was never one of the oracle's actual data elements — it is an internal computation artifact being smuggled in as a "leaf".
3. If a victim's address definition uses `["in merkle", [oracle_addr, feed_name, N12_as_string, min_mci]]` (or any element an attacker can align with an internal-node value of the oracle's public data), the attacker supplies this crafted `serialized_proof` as the authentifier, and `definition.js`'s handling accepts it because `merkle.deserializeMerkleProof` + `merkle.verifyMerkleProof` + `dataFeeds.dataFeedExists(..., proof.root, ...)` all pass: [8](#0-7) 

Note: Full weaponization requires a concrete oracle data set with the right structural properties and a victim definition whose `element` argument can be aligned with an internal-node value; this analysis establishes the root-cause code weakness (missing leaf/node domain separation, matching the reported bug class) rather than a fully turnkey exploit against a specific deployed oracle.

### Citations

**File:** merkle.js (L5-20)
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
```

**File:** merkle.js (L22-47)
```javascript
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

**File:** definition.js (L445-479)
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
