Confirmed: in `aa_validation.js`'s `validateAttestors` (lines 41-61), when an AA definition validates an `asset` or `asset_attestors` message's `attestors` array, it checks each element is a valid address or formula, but never checks for duplicates or sorted/strict-ascending order — unlike the unit-level equivalent `checkAttestorList` in `validation.js` (lines 2850-2864), which explicitly rejects unsorted/duplicate entries via `if (arrAttestors[i] <= prev) return "attestors not sorted";`.

This asymmetry matches the reported bug class ("add() doesn't check for duplicates before pushing to an array/list").

### Title
AA-defined `asset`/`asset_attestors` messages allow duplicate attestor addresses to be written to storage - (File: `aa_validation.js`)

### Summary
`validateAttestors()` inside `validateAADefinition()` in `aa_validation.js` (lines 41-61) validates each entry of an AA's `attestors` array/formula only for being a valid address or a resolvable formula. It performs no duplicate check and no ordering/uniqueness check, unlike the unit-level `checkAttestorList()` used for regular (non-AA) `asset`/`asset_attestors` messages in `validation.js` (lines 2850-2864), which explicitly enforces `arrAttestors[i] <= prev → "attestors not sorted"`, guaranteeing uniqueness.

### Finding Description
When an AA definer writes an `asset` or `asset_attestors` message whose `attestors` field is a formula (evaluated at trigger time) or when the formula evaluation resolves the array dynamically, the resulting attestor list is validated at AA-definition time by `validateAttestors` in `aa_validation.js:41-61`, which only checks `isValidAddress`/formula validity per element — never checking for duplicates. At execution time (`aa_composer.js:1882-1883`) the code does `payload.attestors.sort()` before sending the unit, but `sort()` does not deduplicate; it only orders the array. The resulting unit is subsequently persisted via `writer.js`'s asset/asset_attestors handling, which iterates `payload.attestors` and inserts one row per entry into the `asset_attestors` table without a distinctness check. This mirrors the `Dispatcher.add()` bug class: a "collection" (the attestors list persisted per asset) can contain duplicate entries because the addition path lacks a duplicate check that its sibling validation path (`checkAttestorList`) does enforce.

### Impact Explanation
Duplicate attestor entries are wasted storage/bandwidth at minimum, but more importantly they break the invariant depended upon elsewhere in the code that assumes a unique, sorted attestor list (e.g., `storage.js` reading `asset_attestors` rows back into `payload.attestors` for re-serialization/hashing, and `filterAttestedAddresses`/spender-attestation checks that iterate the list). If any downstream logic assumes uniqueness (e.g., counting attestors against `MAX_ATTESTORS_PER_ASSET`, or hashing consistency when the unit is reconstructed from DB rows for other nodes), duplicated entries could cause hash mismatches between the original AA-generated unit and later reconstructions, or allow bypassing intended attestor-count limits — a correctness/consensus-adjacent issue affecting AA-defined asset attestor management, not merely a cosmetic one.

### Likelihood Explanation
Requires an AA definer to craft an AA whose `asset`/`asset_attestors` message attestors formula can evaluate to a list containing duplicate addresses (fully within reach of any unprivileged AA author posting an AA definition — no special privilege needed). Given ocore's general pattern of enforcing strict sort-order to guarantee uniqueness elsewhere (units authors, earned_headers_commission_recipients, denominations, input keys, spend proofs) but omitting it specifically in the AA-formula attestors validator, this is a plausible oversight reachable by any user deploying an AA.

### Recommendation
Add the same strict-sort/duplicate check used in `checkAttestorList` (`validation.js:2850-2864`) to `validateAttestors` in `aa_validation.js`, or at minimum enforce deduplication after formula evaluation before the attestor list is persisted (e.g., in `aa_composer.js` after `payload.attestors.sort()`), and verify `writer.js`'s asset_attestors persistence rejects duplicate `(asset, attestor_address)` pairs.

### Proof of Concept
1. Deploy an AA whose bound `asset` message has `attestors` set to a formula that evaluates (at trigger time) to an array such as `[address1, address1, address2]` (e.g., built via `array_slice`/`concat` formula operations reachable to any AA author).
2. `validateAADefinition` (`aa_validation.js:41-61`) accepts the AA because each individual array element is a valid address; no duplicate check is applied.
3. When the AA is triggered, `aa_composer.js:1878-1883` sorts `payload.attestors` (sort does not dedupe) and sends the unit.
4. `writer.js` persists one row per attestor entry into `asset_attestors`, resulting in a duplicate `(asset, attestor_address)` row pair, unlike what `checkAttestorList` (`validation.js:2850-2864`) would have rejected for a manually-authored (non-AA) equivalent message. [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** aa_validation.js (L41-61)
```javascript
			function validateAttestors(attestors, cb3) {
				if (isNonemptyString(attestors)) {
					var f = getFormula(attestors);
					if (f === null)
						return cb3("attestors is a string but not formula: " + attestors);
					return cb3();
				}
				if (!isNonemptyArray(attestors))
					return cb3("wrong attestors: " + JSON.stringify(attestors));
				for (var i = 0; i < attestors.length; i++) {
					var attestor = attestors[i];
					if (!isNonemptyString(attestor))
						return cb3("bad attestor: " + JSON.stringify(attestor));
					if (!isValidAddress(attestor)) {
						var f = getFormula(attestor);
						if (f === null)
							return cb3("bad formula in attestor");
					}
				}
				cb3();
			}
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

**File:** aa_composer.js (L1878-1884)
```javascript
			messages.forEach(function (message) {
				var payload = message.payload;
				if (message.app === 'asset' && isNonemptyArray(payload.denominations) && payload.denominations.every(d => isNonemptyObject(d) && ValidationUtils.isPositiveInteger(d.denomination)))
					payload.denominations.sort(sortDenominations);
				if ((message.app === 'asset' || message.app === 'asset_attestors') && isNonemptyArray(payload.attestors) && payload.attestors.every(ValidationUtils.isValidAddress))
					payload.attestors.sort();
			});
```
