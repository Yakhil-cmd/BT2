### Title
Unvalidated/Type-Confused Deserialization of Attacker-Supplied Merkle Proofs in `in merkle` Authentifier Evaluation - ([File: merkle.js])

### Summary
The `in merkle` address-definition operator lets a unit's author supply an arbitrary, unvalidated "authentifier" string that is deserialized by `deserializeMerkleProof()` and then verified by `verifyMerkleProof()` before being used to satisfy a signing/spending condition. Neither function validates the structure, length, or numeric type of the fields extracted from the attacker-controlled string, mirroring the CVE's root cause: crafted, structurally-unchecked metadata from an untrusted party is trusted and used directly in security-critical processing.

### Finding Description
`deserializeMerkleProof()` blindly splits the caller-supplied string on `"-"` and pulls out `root`/`index`/`siblings` with no checks that the string has the expected shape: [1](#0-0) 

`verifyMerkleProof()` then uses `proof.index` directly in numeric operations (`index % 2`, `Math.floor(index/2)`) without ever confirming it is a valid non-negative integer, and iterates `proof.siblings` without validating that each element is a well-formed base64 hash: [2](#0-1) 

This is reachable from a fully untrusted, unprivileged actor: any address whose definition contains an `in merkle` clause accepts the serialized proof as part of `assocAuthentifiers[path]`, which is populated straight from the unit author's self-supplied authentifier field when the unit is posted: [3](#0-2) 

Because JavaScript coerces strings to numbers in arithmetic contexts, a `proof.index` that is not a clean, validated integer (e.g. an empty string produced by a crafted `serialized_proof` with unexpected leading/trailing `"-"`, or a non-numeric fragment) is silently coerced (`Number("") === 0`, `NaN % 2` behaves unpredictably) rather than rejected. Combined with the fact that `deserializeMerkleProof` never verifies the number of `"-"`-delimited fields matches the number of siblings actually used by `getMerkleProof`/`getMerkleRoot`, an attacker who controls both the *shape* of the serialized proof string and the values placed in it can attempt to engineer an `index`/`siblings` sequence that make `verifyMerkleProof` compute a `the_other_sibling` equal to a target `proof.root` (i.e., the data-feed value the address definition expects), without ever holding a genuine inclusion proof from the oracle.

This is structurally analogous to the reported CVE: an unvalidated, attacker-crafted metadata blob (there: stored-procedure output parameter metadata; here: a serialized merkle-proof string) is parsed and consumed by security logic (there: ODBC driver memory operations; here: authentifier/signature-equivalent verification) without confirming that its type/shape/length matches what the verification algorithm assumes.

### Impact Explanation
If exploitable, this allows an attacker to satisfy an `in merkle` authentifier clause in an address definition (or asset condition) without a legitimate merkle proof from the referenced oracle/data feed. Since `in merkle` clauses are typically used to gate spending conditions or AA-adjacent authorization logic on oracle-attested data, a successful bypass would let the attacker authorize signing/spending from that path without the oracle's actual endorsement — a concrete unauthorized-spending / node-disagreement-on-validity scenario, since some nodes may accept the malformed proof as valid ('good' sequence) while others might not, depending on any implicit assumptions elsewhere in the codebase about the shape of merkle proof strings.

### Likelihood Explanation
Likelihood is limited by two factors: (1) `in merkle` is a relatively rarely used definition op compared to `sig`/`hash`, so exposure is limited to addresses/assets that explicitly define such a clause; (2) actually engineering an `index`/`siblings` combination whose resulting hash chain equals the target `root` still requires defeating SHA-256's preimage/second-preimage resistance for at least one hash step unless the coercion bug produces a degenerate case (e.g., zero siblings, or an `index` value that causes the loop to be skipped/short-circuited in a way that trivially matches `root`). The primary, clearly demonstrable weakness — lack of type/format validation on `index`, `root`, and `siblings` before they are used in verification — is concretely present in the code regardless of whether a full end-to-end forgery is trivial; at minimum it permits type-confusion inputs that were never intended by the proof format, which is exactly the "no bounds/metadata validation" class of bug described in the report.

### Recommendation
- In `merkle.deserializeMerkleProof()`, validate: the number of `"-"`-delimited tokens is consistent with a well-formed proof, `index` is a valid non-negative integer string, `root` and each `sibling` are valid base64-encoded SHA-256 hashes of the expected length, and reject with an explicit error otherwise instead of silently producing `undefined`/coerced values.
- In `merkle.verifyMerkleProof()`, explicitly reject the proof (return `false`) if `proof.index` is not a safe non-negative integer, or if any sibling is not a properly formatted hash string, before entering the verification loop.
- Add unit tests for malformed/short/empty `serialized_proof` inputs and for non-numeric `index` values to ensure `verifyMerkleProof` fails closed.

### Proof of Concept
Conceptual (cannot be fully executed without a live oracle data feed to target, but demonstrates the missing validation):
1. An address is defined with `['in merkle', [['ORACLE_ADDR'], 'feed_name', 'target_element']]`.
2. When posting a unit that spends from this address, the attacker sets `assocAuthentifiers['r'] = "-BADSIBLING-"+targetRoot` (deliberately malformed: empty `index` token due to leading `"-"`).
3. `deserializeMerkleProof` produces `proof.index = ""`, `proof.siblings = ["BADSIBLING"]`, `proof.root = targetRoot` — none of these are validated.
4. `verifyMerkleProof` executes `index % 2 === 0` where `index === ""`, which JS evaluates as `true` (via `Number("") === 0`), proceeding through the loop with attacker-chosen `siblings` values instead of rejecting the malformed proof outright. [4](#0-3) [3](#0-2)

### Citations

**File:** merkle.js (L75-102)
```javascript
function deserializeMerkleProof(serialized_proof){
	var arr = serialized_proof.split("-");
	var proof = {};
	proof.root = arr.pop();
	proof.index = arr.shift();
	proof.siblings = arr;
	return proof;
}

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
