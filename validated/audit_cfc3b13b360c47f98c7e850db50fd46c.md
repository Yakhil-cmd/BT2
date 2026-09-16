### Title
Erroneous security declaration in address-definition validation lets an `["address", X]` branch satisfy the "must have a signature" requirement without any real authorization check - ([File: definition.js])

### Summary
`Definition.validateDefinition()` is the structural check that every new address (or asset-condition) definition must pass, and it enforces that "each branch must have a signature" so that no address can be spent without real authorization [1](#0-0) . Inside the `'address'` op handler, when the referenced inner address's definition cannot yet be resolved, the code is supposed to consult `objValidationState.bAllowUnresolvedInnerDefinitions` to decide whether to trust the branch — but that check is commented out and replaced with a hardcoded `var bAllowUnresolvedInnerDefinitions = true;`, so the branch is unconditionally treated as if it "has a signature" (`cb(null, true)`) even though nothing about the referenced address was actually verified [2](#0-1) .

### Finding Description
This is the same bug class as CVE-2006-4247: a security-relevant declaration/permission check ("this branch is authenticated") is asserted unconditionally instead of being gated on the real condition, so an operation that should require proof of authorization is granted for free.

`validateDefinition` walks the whole definition tree and only accepts it if `bHasSig` is true, i.e. some branch resolves to an actual signature requirement [3](#0-2) . For a `'sig'` op the code legitimately returns `cb(null, true)` because a public key and signature are explicitly required [4](#0-3) . For an `['address', 'BASE32']` op that references another (not-yet-authored, not-yet-known) address, the correct behavior is to defer/reject validation until the inner definition is known, exactly as is properly done in the separate authorization-time function `validateAuthentifiers`, which returns `cb2(false)` when the inner definition can't be resolved [5](#0-4) .

In `validateDefinition`, however, the analogous safety check was disabled: the intended flag-driven check `if (objValidationState.bAllowUnresolvedInnerDefinitions) return cb(null, true);` is commented out and unconditionally replaced by `var bAllowUnresolvedInnerDefinitions = true;` [6](#0-5) . As a result, any newly-declared address definition that contains an `['address', OTHER_ADDRESS]` branch where `OTHER_ADDRESS` has no known/co-authored definition yet is treated as though that branch already provides a valid signature guarantee (`cb(null, true)`), satisfying the "each branch must have a signature" rule at line 626-627 without any actual authentication content being present or verified.

### Impact Explanation
An unprivileged unit poster (or anyone composing a shared/complex address, e.g. via `wallet_defined_by_addresses.js`'s `validateAddressDefinition`, which calls straight into `Definition.validateDefinition` [7](#0-6) ) can register a new address whose definition is, for example, `["or", [["address", "SOME_UNUSED_ADDRESS"], ["in data feed", [...]]]]`. Because `SOME_UNUSED_ADDRESS` has no definition on chain yet, the `'address'` branch is rubber-stamped as "has signature" and the whole definition passes structural validation, even though the only real, unfaked branch (e.g. a data-feed condition) requires no private key at all. Anyone who can satisfy the public data-feed condition (not the address's true owner) could later author units from that address once its content_hash/first-use definition is accepted, i.e. spend funds sent to it without ever proving ownership — a form of unauthorized spending analogous to resetting another user's "password" (their spending authorization) with no real credential.

### Likelihood Explanation
Reachable by any ordinary unit author or wallet user composing a custom/shared address definition — no special network position, hub role, or privileged key is required; only a definition referencing an address that is not yet defined on-chain is needed, which is a normal and expected situation (new shared addresses are commonly defined before use).

### Recommendation
Restore the conditional check so `validateDefinition` never blindly trusts an unresolved `['address', X]` branch as satisfying the signature requirement — either always require `cb("definition of inner address not found")` when unresolved (mirroring `validateAuthentifiers`'s `cb2(false)`), or gate the trust strictly behind an intentional, narrowly-scoped `objValidationState.bAllowUnresolvedInnerDefinitions` flag set only for the specific pre-validation use cases where it is safe, instead of the always-`true` literal.

### Proof of Concept
Not runnable from this analysis alone (would need to trace the exact flag-check history/commit that disabled `bAllowUnresolvedInnerDefinitions`, and confirm end-to-end that a `'good'` first-use `address_definition_change`/initial author definition referencing such an unresolved inner address is later accepted for spending by `validateAuthentifiers` under a light/first-use scenario). Conceptually:
1. Attacker composes address `A` with definition `["or", [["address", "B"], ["in data feed", [["ORACLE"], "flag", "=", "1"]]]]`, where `B` is any syntactically valid address never used on-chain.
2. `validateDefinition(A's definition)` reaches the `'address'` op for `B`; `storage.readDefinitionByAddress` calls `ifDefinitionNotFound`, and since `bAllowUnresolvedInnerDefinitions` is hardcoded `true`, `cb(null, true)` is returned, making `bHasSig = true` for the whole tree.
3. Definition passes structural validation and address `A` becomes usable/fundable.
4. Anyone able to get `ORACLE` to post `flag=1` in a data feed can author a spend from `A` via the second `'or'` branch, without ever controlling `B` or any private key tied to `A`. [2](#0-1)

### Citations

**File:** definition.js (L42-43)
```javascript
// validate definition of address or asset spending conditions
function validateDefinition(conn, arrDefinition, objUnit, objValidationState, arrAuthentifierPaths, bAssetCondition, handleResult){
```

**File:** definition.js (L244-250)
```javascript
				if (args.algo === "secp256k1")
					return cb("default algo must not be explicitly specified");
				if ("algo" in args && args.algo !== "secp256k1")
					return cb("unsupported sig algo");
				if (!isStringOfLength(args.pubkey, constants.PUBKEY_LENGTH))
					return cb("wrong pubkey length");
				return cb(null, true);
```

**File:** definition.js (L284-297)
```javascript
					ifDefinitionNotFound: function(definition_chash){
					//	if (objValidationState.bAllowUnresolvedInnerDefinitions)
					//		return cb(null, true);
						var bAllowUnresolvedInnerDefinitions = true;
						try {
							var arrDefiningAuthors = objUnit.authors.filter(function (author) {
								return (author.address === other_address && author.definition && objectHash.getChash160(author.definition) === definition_chash);
							});
						}
						catch (e) {
							return cb("failed to calc definition hash of co-author "+other_address+": "+e.message);
						}
						if (arrDefiningAuthors.length === 0) // no address definition in the current unit
							return bAllowUnresolvedInnerDefinitions ? cb(null, true) : cb("definition of inner address "+other_address+" not found");
```

**File:** definition.js (L623-627)
```javascript
	evaluate(arrDefinition, 'r', false, function(err, bHasSig){
		if (err)
			return handleResult(err);
		if (!bHasSig && !bAssetCondition)
			return handleResult("each branch must have a signature");
```

**File:** definition.js (L783-793)
```javascript
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
```

**File:** wallet_defined_by_addresses.js (L520-528)
```javascript
function validateAddressDefinition(arrDefinition, handleResult){
	var objFakeUnit = {authors: []};
	var objFakeValidationState = {last_ball_mci: MAX_INT32, bAllowUnresolvedInnerDefinitions: true};
	Definition.validateDefinition(db, arrDefinition, objFakeUnit, objFakeValidationState, null, false, function(err){
		if (err)
			return handleResult(err);
		handleResult();
	});
}
```
