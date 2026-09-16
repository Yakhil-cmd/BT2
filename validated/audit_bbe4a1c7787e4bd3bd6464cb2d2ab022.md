### Title
Authentifier-path prefix confusion allows use of an unrelated signature to satisfy a nested `address` branch that requires no signature - ([File: definition.js])

### Summary
The Cedar/Express advisory shows an authorization bypass caused by a *string-matching interpretation conflict*: the middleware decided which action to authorize by matching against `req.originalUrl` (a superset string), while Express actually routed on the bare path, so a string that "looked like" it belonged to one route was silently treated as belonging to a more permissive one. `ocore`'s `definition.js` contains a structurally identical interpretation conflict in `pathIncludesOneOfAuthentifiers()`, which decides whether a nested `address` branch of a spending condition is "in use" (i.e., whether the signer actually intends to satisfy it) by doing a naive string-prefix comparison instead of a path-boundary-aware comparison.

### Finding Description
`pathIncludesOneOfAuthentifiers()` is: [1](#0-0) 

```
for (var i=0; i<arrAuthentifierPaths.length; i++){
    var authentifier_path = arrAuthentifierPaths[i];
    if (authentifier_path.substr(0, path.length) === path)
        return true;
}
```

This is a pure string-prefix test with **no boundary check** for the character following the matched prefix. Definition paths are dot-separated array indices (e.g. `r.1`, `r.10`, `r.1.0`). Because `'r.10'.substr(0, 'r.1'.length) === 'r.1'`, the branch path `r.1` is falsely reported as "included" by an authentifier that was actually submitted for the unrelated, sibling branch `r.10` (the 11th element of the same array, not a descendant of the 2nd element).

This helper gates the `address` op inside `validateAuthentifiers`'s recursive `evaluate()`: [2](#0-1) 

```
case 'address':
    // ['address', 'BASE32']
    if (!pathIncludesOneOfAuthentifiers(path, arrAuthentifierPaths, bAssetCondition))
        return cb2(false);
    var other_address = args;
    storage.readDefinitionByAddress(conn, other_address, objValidationState.last_ball_mci, {
        ifFound: function(arrInnerAddressDefinition){
            evaluate(arrInnerAddressDefinition, path, cb2);
        },
        ...
```

The purpose of the guard is to require that the signer *declare intent* to activate a nested-address branch before it is evaluated (an anti-DoS/logic-consistency optimization): if none of the authentifiers submitted with the unit falls under this path, the branch is skipped and treated as unsatisfied. Because of the prefix bug, an authentifier at a numerically-larger sibling path (`r.10`, `r.11`, ...) is misinterpreted as "belonging" to `r.1`, `r.11` as belonging to `r.1`, etc., letting the guard pass even though the signer never submitted anything for that branch.

Crucially, the inner address's own definition can be a condition that requires **no signature at all** — e.g. `attested`, `in data feed`, `cosigned by`, `seen`, `seen address`, `seen definition change` — none of which push to `arrUsedPaths` or otherwise consume an authentifier: [3](#0-2) [4](#0-3) 

Combined with `evaluate`'s `or`/`and` reducers in `validateAuthentifiers` (which simply OR/AND the boolean results of each branch, with no requirement that the "signature-less" branch actually correspond to the authentifier that unlocked it): [5](#0-4) 

...an attacker constructing an address definition with ≥11 branches under one `or`/`and`/`r of set` array can arrange for the branch at index `1..9` to be a signature-free nested `address` condition (e.g., a purely oracle/attestation-gated branch), and for the branch at index `10+` to be a normal `sig` requirement. Submitting only the real signature for the `sig` branch (`r.10`) is enough to also make `pathIncludesOneOfAuthentifiers('r.1', ['r.10'])` return `true`, causing the signature-free branch to be evaluated and potentially satisfied "for free," even though the actual definition author's intent was that both spending paths be independent, mutually exclusive alternatives requiring their own distinct declared authentifier.

### Impact Explanation
This is the same class of bug as the advisory: a *matching* decision (whether a branch is "in scope"/authorized) is based on a different, coarser interpretation of the same identifier (`path`) than the one actually used elsewhere (exact authentifier key lookup at `sig`/`hash`). Where the resulting nested branch is signature-free (`attested`, `in data feed`, `cosigned by`, `seen*`), the mismatch lets a payer/AA author who signs only one branch of a shared/multisig-style address definition unlock an additional, logically distinct spending condition that was never meant to be activated by that signature — a real authorization bypass over how the address's `or`/`and`/`r of set` conditions are composed. This can enable spending funds under conditions the address owner did not intend to expose together (e.g. bypassing an "and" requiring both a signature and a distinct oracle/cosigner clause meant to gate a *different* branch), i.e., unauthorized spending from the same address/asset condition.

### Likelihood Explanation
Exploitation requires the attacker (who is constructing/using the definition, e.g., a shared-address co-author, AA definer, or asset-condition author) to deliberately craft a definition with ≥11 sibling branches so that index numbers collide as substrings (`r.1` vs `r.10`), and to know which nested branch is signature-free. This is a self-inflicted "shared address" style definition (any unprivileged unit poster/AA author/asset issuer can define such definitions), so it is fully reachable without special privilege, though it requires deliberate, non-obvious crafting (11+ array elements) rather than being triggered by an incidental single-digit setup.

### Recommendation
Fix `pathIncludesOneOfAuthentifiers()` to require a proper path-boundary match, e.g. check that `authentifier_path === path` or `authentifier_path.charAt(path.length) === '.'` after the prefix match, so `r.10` never satisfies a lookup for `r.1`. Add regression tests for arrays with 11+ elements at a single depth to ensure the disambiguation.

### Proof of Concept
1. Define an address whose definition is `['and', [branch0, branch1, ..., branch10, ...]]` (or similarly structured `or`) such that:
   - `branch1` (`path = 'r.1'`) is `['address', X]`, where `X`'s definition is `['attested', ['this address', [oracleAddr]]]` (no signature required).
   - `branch10` (`path = 'r.10'`) is `['sig', {pubkey: attackerPubkey}]`.
2. Submit a unit with `authors[0].authentifiers = {'r.10': validSignature}` only (no entry for `r.1` or anything under it).
3. In `validateAuthentifiers`, evaluating `branch1` calls `pathIncludesOneOfAuthentifiers('r.1', ['r.10'], ...)`, which returns `true` due to the unguarded `substr` prefix check, so `X`'s `attested` condition is evaluated and can independently return `true` if the oracle attestation exists — satisfying `branch1` without any authentifier ever having been declared for it, alongside the legitimately signed `branch10`.

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

**File:** definition.js (L646-670)
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

**File:** definition.js (L904-923)
```javascript
			case 'attested':
				// ['attested', ['BASE32', ['BASE32']]]
				var attested_address = args[0];
				var arrAttestors = args[1];
				if (attested_address === 'this address')
					attested_address = address;
				storage.filterAttestedAddresses(
					conn, {arrAttestorAddresses: arrAttestors}, objValidationState.last_ball_mci, [attested_address], function(arrFilteredAddresses){
						cb2(arrFilteredAddresses.length > 0);
					}
				);
				break;
				
			case 'cosigned by':
				// ['cosigned by', 'BASE32']
				var cosigner_address = args;
				var arrAuthorAddresses = objUnit.authors.map(function(author){ return author.address; });
				console.log(op+" "+arrAuthorAddresses.indexOf(cosigner_address));
				cb2(arrAuthorAddresses.indexOf(cosigner_address) >= 0);
				break;
```

**File:** definition.js (L933-940)
```javascript
			case 'in data feed':
				// ['in data feed', [['BASE32'], 'data feed name', '=', 'expected value']]
				var arrAddresses = args[0];
				var feed_name = args[1];
				var relation = args[2];
				var value = args[3];
				var min_mci = args[4] || 0;
				dataFeeds.dataFeedExists(arrAddresses, feed_name, relation, value, min_mci, objValidationState.last_ball_mci, false, cb2);
```
