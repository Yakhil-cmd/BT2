### Title
Merkle "node-as-leaf" hash collision lets a forged element pass an `in merkle` oscript authentifier check - (File: merkle.js)

### Summary
The `in merkle` oscript/address-definition authentifier (`definition.js`, `formula/evaluation.js`, grammar in `formula/grammars/oscript.ne`) verifies inclusion of an attacker-supplied "element" in an oracle-posted Merkle-root data feed by calling `merkle.verifyMerkleProof()`. The Merkle implementation in `merkle.js` hashes leaves and internal nodes with the exact same `hash()` function and no domain-separation prefix, so an internal node's pre-image (`h_left + h_right`) is indistinguishable from a leaf's pre-image (a raw element string). This is functionally the same class of flaw as the JetKVM report: content ("element") and its accompanying "proof" (the hash path) can both be crafted by the attacker to satisfy an equality-only integrity check that has no independent binding to what the trusted party (the oracle) actually attested.

### Finding Description
`merkle.js` builds and verifies proofs with:
```js
function hash(str){ return crypto.createHash("sha256").update(str, "utf8").digest("base64"); }
``` [1](#0-0) 
used identically for leaves (`hash(element)`) and internal nodes (`hash(arrHashes[i] + arrHashes[hash2_index])`). `verifyMerkleProof` recomputes the path the same way:
```js
function verifyMerkleProof(element, proof){
	// Node-as-Leaf issue might matter in some cases
	var the_other_sibling = hash(element);
	for (...) {
		the_other_sibling = index%2===0 ? hash(the_other_sibling+proof.siblings[i]) : hash(proof.siblings[i]+the_other_sibling);
		...
	}
	return (the_other_sibling === proof.root);
}
``` [2](#0-1) 
The code itself contains a developer comment flagging the exact weakness ("Node-as-Leaf issue might matter in some cases") but it was never fixed.

This proof scheme is exposed to unit posters through the `in merkle` definition/authentifier opcode:
```js
case 'in merkle':
    var serialized_proof = assocAuthentifiers[path];
    var proof = merkle.deserializeMerkleProof(serialized_proof);
    if (!merkle.verifyMerkleProof(element, proof)){
        fatal_error = "bad merkle proof at path "+path;
        return cb2(false);
    }
    dataFeeds.dataFeedExists(arrAddresses, feed_name, '=', proof.root, min_mci, objValidationState.last_ball_mci, false, cb2);
``` [3](#0-2) 
and to AA formulas via the `in_data_feed`/`data_feed` combination as well as the `in merkle` grammar rule in oscript. [4](#0-3) 

Because leaf and internal-node hashing share the same function with no type tag, any pair of sibling hash strings `(h_L, h_R)` seen anywhere in the tree can be resubmitted by an attacker as a forged "element" (`element' = h_L + h_R`) together with the remaining true sibling path from that node up to the root. `verifyMerkleProof` will compute `hash(element')`, which equals the real internal node's hash, and continue up the authentic remaining path to the (real, oracle-attested) root — accepting an element that was never actually one of the oracle's committed leaves. This mirrors the firmware bug's root cause: the verification only checks a hash equation, not the authenticity/origin of the pre-image, so attacker-controlled "content" (the fake element) plus attacker-controlled "proof data" (crafted from genuine internal siblings) satisfies the check.

### Impact Explanation
Any address definition or AA (via oscript formula) that uses an `in merkle` (or the underlying `dataFeeds.dataFeedExists` root check) as a spending/authorization condition against an oracle-published whitelist can be bypassed by a party who was never included in the whitelist, provided they can learn at least one legitimate sibling-hash pair from the tree (commonly available, since Merkle-whitelist designs typically reveal proofs/leaves progressively to legitimate members, or the full leaf set may be published for auditability). A successful forgery lets an unauthorized spender satisfy the authentifier condition on a posted unit, resulting in unauthorized spending of funds guarded by that address/AA — a concrete fund-loss/authorization-bypass impact within Ocore's own AA/address-definition trust model, reachable purely by posting a crafted unit.

### Likelihood Explanation
`in merkle` is a first-class, documented oscript feature intended precisely for building oracle-backed allow-lists inside address definitions and AA formulas, so any deployed contract using it is exposed. Exploitation requires no special network position or privileged role — a normal unit poster simply needs knowledge of two sibling hash values from the target tree, which is realistic in typical usage patterns (progressive/partial disclosure of leaves and proofs, or a publicly auditable leaf set). The vulnerable code even contains an unresolved internal comment acknowledging the exact defect, indicating it is a known, latent weakness rather than a theoretical one.

### Recommendation
Add domain separation to the Merkle hashing scheme in `merkle.js`: prefix leaf hashing (e.g. `hash("\x00" + element)`) and internal-node hashing (e.g. `hash("\x01" + left + right)`) differently so that an internal node's pre-image can never be replayed as a valid leaf pre-image. Because this changes the hash values used in data feeds and definitions, it must be introduced as a versioned/MCI-gated protocol upgrade (similar to other `constants.*UpgradeMci` gates already used for other validation changes), with both old and new schemes supported until deployed contracts migrate.

### Proof of Concept
1. An oracle builds a Merkle tree over a set of whitelisted values and posts only the `root` via a `data_feed` message (as expected for `in merkle`/`dataFeedExists` usage).
2. Through normal, legitimate use of the whitelist (e.g., proofs being handed out to real members, or an openly published leaf list for auditability), an attacker learns two adjacent hash values `h_L` and `h_R` at some tree level (siblings that combine into a parent node `hash(h_L + h_R)`), plus the sibling path from that parent up to the root.
3. The attacker crafts `element' = h_L + h_R` (literal string concatenation) and a `proof'` object: `{ index: parent_index, siblings: [<remaining real siblings from parent to root>], root: <the same real root> }`, serialized via `merkle.serializeMerkleProof`/matching format expected by `merkle.deserializeMerkleProof`.
4. The attacker posts a unit whose author uses an address definition (or AA trigger) containing `['in merkle', [[oracleAddress], 'feed_name', <arbitrary chosen element_value>, min_mci]]`, supplying `assocAuthentifiers[path] = proof'`.
5. `definition.js`'s `in merkle` handler calls `merkle.verifyMerkleProof(element', proof')` [5](#0-4) , which succeeds because `hash(element')` equals the real internal node value and the remaining path is genuine, then confirms `proof.root` matches the oracle's actual posted data-feed root via `dataFeeds.dataFeedExists`.
6. The unit validates as authorized even though the attacker's chosen "element" was never a leaf actually committed by the oracle, allowing unauthorized spending/authorization under that address's definition.

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

**File:** formula/grammars/oscript.ne (L454-468)
```text
    | "attestation" ("[" "[") attestation_param_list ("]" "]") (%dotSelector|"[" expr "]"):? {% function (d, location, reject){
		var params = {};
		var arrParams = d[2];
		for(var i = 0; i < arrParams.length; i++){
			var name = arrParams[i][0];
			var operator = arrParams[i][1];
			var value = arrParams[i][2];
			if(params[name]) return reject;
			params[name] = {operator: operator, value: value};
		}
		var field = null;
		if (d[4])
			field = (d[4][0].type === 'dotSelector') ? d[4][0].value.substr(1) : d[4][1];
		return addLocation(["attestation", params, field], d);
	}%}
```
