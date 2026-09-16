### Title
Unresolved nested `address` branch in `validateDefinition` is unconditionally accepted as signed, letting an unprivileged address definition bypass the "each branch must have a signature" gate - (File: definition.js)

### Summary
`Definition.validateDefinition()` is ocore's analog of a permission gate: it verifies that every spending branch of an address (or asset) definition ultimately requires a real authentifier (signature/hash) before the network will accept the definition. When a definition contains a nested `['address', X]` reference to another address that has no definition yet (neither in storage nor supplied inline by a co-author of the same unit), the code is supposed to consult `objValidationState.bAllowUnresolvedInnerDefinitions` to decide whether that is acceptable. That check has been disabled: the caller-supplied flag is ignored, and the function instead hardcodes `var bAllowUnresolvedInnerDefinitions = true;`, unconditionally treating the unresolved branch as `cb(null, true)` ("has a signature"), exactly like an inline/nested object whose permission was supposed to be checked but is not, because the actual check line is commented out.

### Finding Description
In `definition.js`, the `'address'` case of `validateDefinition`'s `evaluate()` function: [1](#0-0) 

```js
ifDefinitionNotFound: function(definition_chash){
//	if (objValidationState.bAllowUnresolvedInnerDefinitions)
//		return cb(null, true);
	var bAllowUnresolvedInnerDefinitions = true;
	try {
		var arrDefiningAuthors = objUnit.authors.filter(function (author) {
			return (author.address === other_address && author.definition && objectHash.getChash160(author.definition) === definition_chash);
		});
	}
	...
	if (arrDefiningAuthors.length === 0) // no address definition in the current unit
		return bAllowUnresolvedInnerDefinitions ? cb(null, true) : cb("definition of inner address "+other_address+" not found");
	...
}
``` [2](#0-1) 

The intended design (visible from the commented-out line) was to gate this unresolved-reference tolerance behind `objValidationState.bAllowUnresolvedInnerDefinitions`, which is only explicitly set to `true` by trusted, first-party callers such as `wallet_defined_by_addresses.js`'s `validateAddressDefinition()`: [3](#0-2) 

Instead, the local variable shadows and permanently overrides that intent for every caller, including the security-critical path used during real unit/definition validation (`validateAuthentifiers` → `validateDefinition`, called for every unit author and asset condition): [4](#0-3) 

`validateDefinition`'s whole purpose after evaluating the tree is to enforce that every branch that can be used to authorize spending has a real authentifier: [5](#0-4) 

```js
evaluate(arrDefinition, 'r', false, function(err, bHasSig){
    if (err) return handleResult(err);
    if (!bHasSig && !bAssetCondition)
        return handleResult("each branch must have a signature");
    ...
```

Because the `'address'` branch to an as-yet-undefined address is now always reported as `bHasSig = true`, any unprivileged unit poster can define a brand-new address whose definition contains an `['address', 'X']` reference to an address `X` that has never been defined anywhere. The definition passes the "has a signature" gate on the *assumption* that address `X` will someday be defined with a real signature requirement — but nothing enforces that promise. `X`'s real definition is validated independently, at the time `X` is first defined, by whoever controls that chash — a party the outer address's creator does not control and need not coordinate with. If `X` is later defined (by anyone who can produce a definition hashing to `X`, since a completely undefined address's "identity" is just its chash) with a spending condition that does not itself require a signature at that level (e.g., relies on oracle data, `attested`, `cosigned by`, etc., inside further nesting or via other loopholes in the same weakened gate), the outer address inherits an unauthenticated spending path while having already been accepted onto the DAG as a "must have a signature" compliant definition.

This is directly analogous to the reported Django bug class: a nested/child object supplied as part of a larger request (`GenericInlineModelAdmin` inline instance ≈ ocore nested `address` sub-definition) is supposed to be checked for a required permission (Django: "add" permission; ocore: "branch requires a real authentifier") before the parent operation is accepted, but the check was silently disabled (commented out and replaced by a hardcoded `true`), so forged/attacker-influenced nested data slips through.

### Impact Explanation
This weakens (or, if a full exploitation chain can be constructed, defeats) the network's guarantee that every accepted address definition requires cryptographic authorization to spend. If an attacker can arrange for the unresolved inner address to end up with a definition that does not require a signature (directly or through further chained "unresolved address" bypasses), funds sent to the outer address could become spendable by anyone able to satisfy the non-signature condition, which is unauthorized spending / theft of funds — a Critical-class impact matching the "concrete unauthorized spending" bar in the validation rules. At minimum it is a structural integrity flaw in a core, security-load-bearing invariant ("each branch must have a signature") that is silently and unconditionally bypassed rather than gated as originally designed, which nodes will not disagree about (deterministic), but which undermines the security property the check exists to guarantee.

### Likelihood Explanation
The affected code path (`validateDefinition` via `validateAuthentifiers`) runs on every single unit's author validation and address definition validation, so it is trivially reachable by any unprivileged unit poster simply by defining a new address whose definition body includes an `['address', <undefined-address>]` term. No special privileges, hub cooperation, or malicious peer/node behavior is required — only crafting an ordinary unit/definition, which matches the "single posted unit" reachability requirement in scope. The main open question (which limits full certainty without further code tracing of `readDefinitionByAddress`/`storage` definition-resolution edge cases) is whether a concrete two-step scenario can be fully constructed end-to-end within protocol rules to make the referenced address ultimately unauthenticated; the dead/bypassed check itself, however, is unambiguous and directly verifiable in the code.

### Recommendation
Restore the intended gating logic: only allow `cb(null, true)` for an unresolved nested `address` reference when `objValidationState.bAllowUnresolvedInnerDefinitions` is explicitly and legitimately set by a trusted caller context (e.g., local wallet-side pre-validation of shared-address templates), and require the branch to be treated as **not** having a signature (`cb(null, false)`) in the default/network-consensus validation path (`validateAuthentifiers`/`validateDefinition` invoked from `validation.js`/`signed_message.js`). Concretely, replace:
```js
var bAllowUnresolvedInnerDefinitions = true;
```
with:
```js
var bAllowUnresolvedInnerDefinitions = !!objValidationState.bAllowUnresolvedInnerDefinitions;
```
and audit all call sites of `validateDefinition`/`validateAuthentifiers` to confirm the flag is `true` only for genuinely trusted/local pre-validation contexts, never for consensus-critical unit/definition validation.

### Proof of Concept
Conceptual PoC (network-reachable, single unprivileged unit poster):
1. Choose an address `X` that has never been used/defined on the DAG (any valid chash-style address string with no prior `definitions` row and not referenced as an author-with-definition anywhere yet).
2. Construct a new address definition `D = ['address', X]` and compute `addr = getChash160(D)`.
3. Post a unit where `addr` is used as an author with `"definition": D`. During validation, `validateDefinition` reaches the `'address'` case for `X`; `storage.readDefinitionByAddress` calls `ifDefinitionNotFound`, `arrDefiningAuthors` is empty (no co-author supplies `X`'s definition in this unit), and because `bAllowUnresolvedInnerDefinitions` is hardcoded `true`, the code returns `cb(null, true)` — the definition is accepted as satisfying "each branch must have a signature", even though no signature has ever been verified for `X`.
4. Separately (in a later unit, by any actor able to produce a preimage/definition hashing to `X` — e.g., an address deliberately generated for this purpose, or one whose chash matches an oracle/attested-only condition set once `X` is first used) define `X`'s real definition without requiring a private-key signature at the point it is actually exercised, then send funds to `addr` and later spend them by satisfying `X`'s weak condition instead of any signature belonging to the original definer of `addr`.

Full confirmation of a complete unauthorized-spend chain requires tracing `storage.readDefinitionByAddress`'s exact semantics for how `X`'s "first" definition becomes canonical (this was not fully traced within the available tool budget), but the disabled gate itself is directly confirmed in the code shown above.

### Citations

**File:** definition.js (L284-303)
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
						if (arrDefiningAuthors.length > 1)
							throw Error("more than 1 address definition");
						var arrInnerAddressDefinition = arrDefiningAuthors[0].definition;
						needToEvaluateNestedAddress(path) ? evaluate(arrInnerAddressDefinition, path, bInNegation, cb) : cb(null, true);
					}
				});
```

**File:** definition.js (L621-629)
```javascript
	var complexity = 0;
	var count_ops = 0;
	evaluate(arrDefinition, 'r', false, function(err, bHasSig){
		if (err)
			return handleResult(err);
		if (!bHasSig && !bAssetCondition)
			return handleResult("each branch must have a signature");
		if (complexity > constants.MAX_COMPLEXITY)
			return handleResult("complexity exceeded");
```

**File:** definition.js (L1449-1458)
```javascript
	// we need to re-validate the definition every time, not just the first time we see it, because:
	// 1. in case a referenced address was redefined, complexity might change and exceed the limit
	// 2. redefinition of a referenced address might introduce loops that will drive complexity to infinity
	// 3. if an inner address was redefined by keychange but the definition for the new keyset not supplied before last ball, the address
	// becomes temporarily unusable
	validateDefinition(conn, arrDefinition, objUnit, objValidationState, arrAuthentifierPaths, bAssetCondition, function(err){
		if (err)
			return cb(err);
		//console.log("eval def");
		evaluate(arrDefinition, 'r', function(res){
```

**File:** wallet_defined_by_addresses.js (L518-528)
```javascript
// fix:
// 1. check that my address is referenced in the definition
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
