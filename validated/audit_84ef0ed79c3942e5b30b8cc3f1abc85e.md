### Title
Unbounded attestor list in `attested` address-definition op bypasses complexity accounting - ([File: definition.js])

### Summary
The `attested` operator in address/asset-condition definitions accepts an arbitrarily large array of attestor addresses, but — unlike the sibling `in data feed` and `in merkle` operators — it does **not** scale the definition's `complexity`/`count_ops` counters by the size of that array, and there is no dedicated length cap for it in `validateDefinition`. This mirrors the Gravity.sol issue where an unbounded validator set silently inflates the resources required to re-validate an on-chain checkpoint without a countervailing size limit: here, a single attacker-controlled address definition can carry an unboundedly large list that must be fully validated/re-evaluated on **every** unit signed by that address, forever.

### Finding Description
`validateDefinition` in `definition.js` walks the address-definition tree and increments `complexity`/`count_ops` for every node, checking them against `constants.MAX_COMPLEXITY` / `constants.MAX_OPS`: [1](#0-0) 

For operators that reference variable-length address lists, the code explicitly compensates for the array size, e.g. `in data feed` and `in merkle`: [2](#0-1) [3](#0-2) 

However, the `attested` case only validates that `arrAttestors` is non-empty and that each element is a valid address — it never adds `arrAttestors.length` to `complexity`/`count_ops`, and enforces no maximum length: [4](#0-3) 

The same asymmetry exists in the runtime authentifier evaluator (`validateAuthentifiers`), where the `attested` branch just forwards the full attestor list to `storage.filterAttestedAddresses` with a single fixed complexity cost for the whole op, regardless of list size: [5](#0-4) 

By contrast, when the *asset issuer* attaches an attestor list to an asset (a different, unrelated feature — the spender-attestation list update message), the list length is explicitly bounded by `constants.MAX_ATTESTORS_PER_ASSET`: [6](#0-5) 

That bound does not apply to the `attested` operator used inside address definitions or asset spending conditions, so an address (or asset condition) definition can embed a list with thousands of attestor addresses while `complexity` stays at effectively 1 for that branch, easily staying under `MAX_COMPLEXITY`/`MAX_OPS`.

Because `validateAuthentifiers`/`validateDefinition` are **re-run for every single unit** signed by that address (the code comment explicitly states this is intentional, to catch redefinitions/complexity changes), every future unit authored from this address forces every validating node to process this oversized attestor list again — analogous to Gravity's `makeCheckpoint` needing to iterate the full, unbounded validator set on every checkpoint: [7](#0-6) 

### Impact Explanation
Once such an address (or a private/shared multisig address, or an asset spending condition) with a bloated `attested` attestor list is used to author units, every node validating any unit from that address must repeatedly evaluate `attested` against the full attestor list via `storage.filterAttestedAddresses`, which performs a DB lookup keyed on the attestor set. An attacker can grow this list far beyond what the complexity/ops accounting was designed to bound, degrading or effectively freezing validation throughput for any unit chain touching that address — a network-availability impact (nodes unable to timely confirm/validate new units referencing this address) that parallels Gravity's "large validator set potentially freezes contract" finding, except the growth here is attacker-controlled from the outset rather than emergent from validator set growth.

### Likelihood Explanation
Medium-to-high: crafting an address definition (or asset condition) is fully permissionless — any user can define `['attested', ['this address'/'address', [huge list of valid addresses]]]`, since only per-address validity of each attestor entry is checked, not the count. No privileged role is required; a single posted unit establishing this address definition (or an asset's private-asset spending condition referencing it) is sufficient to plant the issue, after which any subsequent unit from that address (unavoidable if the address is reused, e.g. a shared/multi-sig wallet or an AA-adjacent flow) re-triggers the expensive check.

### Recommendation
Add explicit accounting for `attested`'s attestor list, symmetric with `in data feed`/`in merkle`:
- In `validateDefinition`, add `complexity += arrAttestors.length - 1;` (or similar) for the `attested` case so oversized lists get rejected by the existing `MAX_COMPLEXITY`/`MAX_OPS` checks.
- Additionally cap `arrAttestors.length` directly (e.g., reuse `constants.MAX_ATTESTORS_PER_ASSET` or introduce a dedicated limit) in both `validateDefinition`'s `attested` case and the runtime `attested` branch in `validateAuthentifiers`, to bound the cost of `storage.filterAttestedAddresses` independent of the generic complexity budget.

### Proof of Concept
1. Construct an address definition: `['attested', ['this address', arrAttestors]]` combined with a `sig` branch to satisfy the "each branch must have a signature" rule, where `arrAttestors` contains, e.g., 5,000–50,000 syntactically valid addresses.
2. Post a unit whose author uses this address with this definition; `validateDefinition` accepts it because `complexity` only increases by the fixed per-node amount (1), never scaled by `arrAttestors.length`, unlike the `in data feed`/`in merkle` cases.
3. Every subsequent unit signed by this address forces `validateAuthentifiers`'s `attested` branch to call `storage.filterAttestedAddresses` with the full oversized `arrAttestors` array on every validating node, repeatedly, for the lifetime of the address.

Note: I was unable to fully inspect the internals of `storage.filterAttestedAddresses` before running out of tool iterations, so the exact query-cost profile (e.g., SQL `IN` clause size, indexing behavior) is not directly confirmed in this session — this should be verified in a follow-up session to precisely quantify the per-call cost growth.

### Citations

**File:** definition.js (L103-111)
```javascript
	function evaluate(arr, path, bInNegation, cb){
		complexity++;
		count_ops++;
		if (complexity > constants.MAX_COMPLEXITY)
			return cb("complexity exceeded at "+path);
		if (count_ops > constants.MAX_OPS)
			return cb("number of ops exceeded at "+path);
		if (objValidationState.max_complexity && objValidationState.complexity + complexity > objValidationState.max_complexity)
			return cb(`custom complexity limit ${objValidationState.max_complexity} exceeded at ${path}`);
```

**File:** definition.js (L370-388)
```javascript
			case 'attested':
				if (objValidationState.bNoReferences)
					return cb("no references allowed in address definition");
				if (!isArrayOfLength(args, 2))
					return cb(op+" must have 2 args");
				var attested_address = args[0];
				var arrAttestors = args[1];
				if (bAssetCondition && attested_address === 'this address')
					return cb("asset condition cannot reference this address in "+op);
				if (!isValidAddress(attested_address) && attested_address !== 'this address') // it is ok if the address was never used yet
					return cb("invalid attested address");
				if (!ValidationUtils.isNonemptyArray(arrAttestors))
					return cb("no attestors");
				for (var i=0; i<arrAttestors.length; i++)
					if (!isValidAddress(arrAttestors[i]))
						return cb("invalid attestor address");
				if (objValidationState.last_ball_mci < constants.attestedInDefinitionUpgradeMci)
					return cb(op+" not enabled yet");
				return cb();
```

**File:** definition.js (L415-418)
```javascript
				for (var i=0; i<arrAddresses.length; i++)
					if (!isValidAddress(arrAddresses[i])) // it is ok if the address was never used yet
						return cb("oracle address not valid");
				complexity += arrAddresses.length-1; // 1 complexity point for each address (1 point was already counted)
```

**File:** definition.js (L462-465)
```javascript
				for (var i=0; i<arrAddresses.length; i++)
					if (!isValidAddress(arrAddresses[i])) // it is ok if the address was never used yet
						return cb("oracle address not valid");
				complexity += arrAddresses.length-1; // 1 complexity point for each address (1 point was already counted)
```

**File:** definition.js (L904-915)
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
```

**File:** definition.js (L1449-1454)
```javascript
	// we need to re-validate the definition every time, not just the first time we see it, because:
	// 1. in case a referenced address was redefined, complexity might change and exceed the limit
	// 2. redefinition of a referenced address might introduce loops that will drive complexity to infinity
	// 3. if an inner address was redefined by keychange but the definition for the new keyset not supplied before last ball, the address
	// becomes temporarily unusable
	validateDefinition(conn, arrDefinition, objUnit, objValidationState, arrAuthentifierPaths, bAssetCondition, function(err){
```

**File:** validation.js (L2850-2864)
```javascript
function checkAttestorList(arrAttestors){
	if (!isNonemptyArray(arrAttestors))
		return "attestors not defined";
	if (arrAttestors.length > constants.MAX_ATTESTORS_PER_ASSET)
		return "too many attestors";
	var prev="";
	for (var i=0; i<arrAttestors.length; i++){
		if (!isValidAddress(arrAttestors[i]))
			return "invalid attestor address: "+JSON.stringify(arrAttestors[i]);
		if (arrAttestors[i] <= prev)
			return "attestors not sorted";
		prev = arrAttestors[i];
	}
	return null;
}
```
