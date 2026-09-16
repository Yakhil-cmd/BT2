### Title
Authorization decisions computed on ambiguous authentifier-path prefix matching may diverge from actual per-path signature checks - (File: definition.js)

### Summary
The CVE describes krb5's certauth interface performing certificate-to-principal authorization decisions on an ambiguous mapping between multiple validators, letting one validator's "no opinion" or partial match improperly control the identity that gets authorized. In `ocore`, address-spending-condition evaluation (`definition.js`) similarly derives authorization-relevant decisions from a helper, `pathIncludesOneOfAuthentifiers`, that performs a raw string-prefix comparison between the current definition path and the caller-supplied authentifier paths, rather than a path-segment-aware comparison.

### Finding Description
`pathIncludesOneOfAuthentifiers` is defined as: [1](#0-0) 

It checks `authentifier_path.substr(0, path.length) === path`, which is a naive prefix test. Because sub-path components are numeric indices separated by `.` (e.g. `r.1`, `r.10`, `r.11`), a path such as `r.1` is considered a "prefix match" of `r.10`, `r.11`, `r.100`, etc., even though these are semantically distinct branches of the definition tree. This helper feeds two separate decisions:

1. `needToEvaluateNestedAddress`, used inside `validateDefinition` to decide whether a nested `['address', …]` branch needs to be structurally re-validated against complexity/loop limits: [2](#0-1) 

2. The `'address'` op inside `validateAuthentifiers`'s `evaluate`, which gates whether a referenced address's definition is evaluated at all for authorization purposes: [3](#0-2) 

Both call sites use `arrAuthentifierPaths = Object.keys(assocAuthentifiers)` (the exact paths for which the unit author supplied authentifiers) as the set to prefix-match against the current definition path. The actual authorization of an individual leaf (`sig`/`hash`) still performs an *exact* key lookup on `assocAuthentifiers[path]`, so a forged signature cannot be injected purely through this prefix confusion. However, the confusion means the "is this branch relevant/needs evaluation" gate can be satisfied by an authentifier at an unrelated numeric sibling path (e.g. supplying only `r.10`'s signature makes the gate for path `r.1` believe an authentifier is present), which:
- can cause `needToEvaluateNestedAddress` to skip re-validating a nested `address` branch that should have been re-checked (e.g. after complexity/loop-limit or upgrade-mci logic changes), and
- can cause the `'address'` authorization branch to be evaluated (attempted) even though no authentifier was actually supplied for that exact branch, relying entirely on the exact-match failure inside the nested evaluation to reject it.

This is the same bug class as CVE-2017-7562: an authorization-relevant identity/path mapping is derived from an imprecise (prefix-only) match rather than an exact, delimiter-aware comparison, creating the potential for the wrong branch of the trust decision to be considered "in scope."

### Impact Explanation
If the exact-match check inside the nested `sig`/`hash` evaluation is the only backstop, this is contained to spurious rejections (fail-closed) in the common case, not spending. But `needToEvaluateNestedAddress` controls whether `validateDefinition`'s structural checks (complexity/loop detection for the *whole* address graph) are re-run for a nested address branch. An unposted-yet-locally-relevant nested address whose path happens to be a numeric prefix of an authentifier path used elsewhere in the same signature set can be skipped from structural re-validation, potentially allowing a redefinition-induced complexity blow-up or an unnoticed loop to pass validation on some nodes and not others in edge cases governed by `skipEvaluationOfUnusedNestedAddressUpgradeMci`. This raises the risk of node disagreement on unit validity for crafted multi-signature/nested-address definitions, which is a stability/consensus concern for the DAG.

### Likelihood Explanation
Exploitability is low-to-moderate: an attacker must craft an address definition with nested `['address', …]` branches whose numeric paths are prefixes of one another (e.g. `r.1` vs `r.1x` collisions only arise from numeric concatenation without a path-boundary check, which is deterministic and fully attacker-controlled since the attacker defines the definition tree and which authentifier paths to supply). No malicious peer/hub/network condition is required — a single unit poster or AA/private-payment author who controls their own address definition and authentifier set can trigger the mismatched gating deterministically.

### Recommendation
Change `pathIncludesOneOfAuthentifiers` to require either an exact match or a match followed by the `.` path-separator boundary (i.e. `authentifier_path === path || authentifier_path.substr(0, path.length + 1) === path + '.'`), eliminating the numeric-prefix ambiguity between sibling paths such as `r.1` and `r.10`.

### Proof of Concept
1. Construct an address definition containing at least two nested `['address', otherAddr1]` and `['address', otherAddr2]` branches under an `or`/`and` such that one branch's path is `r.1` and a sibling ends up serialized with path `r.10` (achievable by nesting enough `or`/`and`/`r of set` elements so index concatenation produces this collision, e.g. `['or', [ten_elements..., ['address', otherAddr1]]]` giving path `r.0.10` vs a separate branch at `r.0.1`).
2. Supply `assocAuthentifiers` containing only a key for the numerically-longer path (e.g. `"r.0.10.<inner-path>"`) while omitting any authentifier for `"r.0.1"`.
3. Observe that `pathIncludesOneOfAuthentifiers("r.0.1", arrAuthentifierPaths, …)` returns `true` due to the prefix match against `"r.0.10.…"`, causing the `'address'` branch at `r.0.1` to be evaluated even though the author never intended to authenticate through it, and causing `needToEvaluateNestedAddress` to treat `r.0.1`'s nested address as "in use" and skip/alter its intended re-validation path — demonstrating the ambiguous path-matching root cause described above. Full exploitation to a concrete double-spend/consensus split requires further tree construction, which is unverified due to index limitations on file coverage; a Devin session with full repo access would be needed to confirm end-to-end reachability of a stability-affecting outcome.

### Citations

**File:** definition.js (L31-40)
```javascript
function pathIncludesOneOfAuthentifiers(path, arrAuthentifierPaths, bAssetCondition){
	if (bAssetCondition)
		throw Error('pathIncludesOneOfAuthentifiers called in asset condition');
	for (var i=0; i<arrAuthentifierPaths.length; i++){
		var authentifier_path = arrAuthentifierPaths[i];
		if (authentifier_path.substr(0, path.length) === path)
			return true;
	}
	return false;
}
```

**File:** definition.js (L94-100)
```javascript
	function needToEvaluateNestedAddress(path){
		if (!arrAuthentifierPaths) // no signatures, just validating a new definition
			return true;
		if (objValidationState.last_ball_mci < constants.skipEvaluationOfUnusedNestedAddressUpgradeMci) // skipping is enabled after this mci
			return true;
		return pathIncludesOneOfAuthentifiers(path, arrAuthentifierPaths, bAssetCondition);
	}
```

**File:** definition.js (L774-800)
```javascript
			case 'address':
				// ['address', 'BASE32']
				if (!pathIncludesOneOfAuthentifiers(path, arrAuthentifierPaths, bAssetCondition))
					return cb2(false);
				var other_address = args;
				storage.readDefinitionByAddress(conn, other_address, objValidationState.last_ball_mci, {
					ifFound: function(arrInnerAddressDefinition){
						evaluate(arrInnerAddressDefinition, path, cb2);
					},
					ifDefinitionNotFound: function(definition_chash){
						try {
							var arrDefiningAuthors = objUnit.authors.filter(function(author){
								return (author.address === other_address && author.definition && objectHash.getChash160(author.definition) === definition_chash);
							});
						}
						catch (e) {
							return cb2(false);
						}
						if (arrDefiningAuthors.length === 0) // no definition in the current unit
							return cb2(false);
						if (arrDefiningAuthors.length > 1)
							throw Error("more than 1 address definition");
						var arrInnerAddressDefinition = arrDefiningAuthors[0].definition;
						evaluate(arrInnerAddressDefinition, path, cb2);
					}
				});
				break;
```
