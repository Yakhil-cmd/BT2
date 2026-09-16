### Title
Case-insensitive address validation (`isValidAddressAnyCase`) allows address-identity collisions in payment outputs - ([File: validation.js])

### Summary
`validatePaymentInputsAndOutputs` in `validation.js` selects between two different address-validity checks depending on `last_ball_mci`: [1](#0-0) 

For units whose `last_ball_mci` is below `constants.timestampUpgradeMci`, output addresses are validated with `ValidationUtils.isValidAddressAnyCase` instead of the strict `ValidationUtils.isValidAddress`: [2](#0-1) 

`isValidAddress` requires the string to match `/^[A-Z2-7]{32}$/` (canonical uppercase base32) *and* pass the checksum, while `isValidAddressAnyCase` only checks that the string is 32 characters long and passes the chash checksum — it does not enforce case. This is structurally analogous to the Django CVE-2019-19844 bug class: two different textual representations (upper/lower/mixed case) can be treated as the "same" identity by one part of the system (checksum validation) while other parts of the codebase (string equality/sorting logic in the same function, `arrOutputAddresses.indexOf`, address comparisons elsewhere in wallet/device code) treat them as different strings.

### Finding Description
`chash.isChashValid` (used by both `isValidAddress` and `isValidAddressAnyCase`) decodes the base32 payload and verifies only the embedded checksum bits, with no case normalization enforced by `isValidAddressAnyCase` itself: [3](#0-2) 

In `validatePaymentInputsAndOutputs`, for older units (`last_ball_mci < timestampUpgradeMci`), `isValidAddressWithCase` resolves to `isValidAddressAnyCase`, and this relaxed check is applied to public payment output addresses that are also used for sort-order verification and deduplication in the very same loop: [4](#0-3) 

Because `prev_address` comparisons (`prev_address > output.address`) and `arrOutputAddresses.indexOf(output.address)` are plain JavaScript string comparisons, a lower-/mixed-case variant of an address string is a *different* string from its canonical uppercase form even though `isChashValid` accepts both as valid pointers to the *same* underlying 20-byte chash-160 value (once base32-decoded). This means the same real spending destination can appear under multiple distinct string identities in one unit, defeating "outputs must be sorted"/duplicate-detection logic that assumes address strings uniquely identify a payment destination.

### Impact Explanation
If two textually different (but chash-equivalent) address strings are accepted as valid outputs in the same unit, code elsewhere in ocore that keys off address string equality (deduplication for total output computation, `arrOutputAddresses`, downstream indexing in `outputs` table, wallet history matching by `address`, or "seen"/"has" oscript conditions and AA balance bookkeeping that compare a trigger/output address to a definition-stored address string) can disagree about whether an output that pays a given address exists once or twice, or fail to recognize it as paying the address at all if the definitions/queries always store/compare the canonical uppercase form. This can lead to inconsistent interpretation of a unit's outputs across full/light nodes and AA logic (funds appearing to go to an "unknown" address from the AA's perspective while actually crediting a party's real chash — a fund-loss/fund-misdirection vector), and it undermines an invariant ("outputs are sorted/deduplicated by address string") several validators rely on for stable behavior.

### Likelihood Explanation
The relaxed path is intentionally scoped to legacy units below `timestampUpgradeMci`, so it is not reachable for freshly composed units past that upgrade point on mainnet — this limits exploitability going forward, but the analog itself (the same conceptual bug pattern as CVE-2019-19844: two distinct representations resolving to the same underlying identity while application logic treats them as different keys) is present in the code and could resurface if `isValidAddressAnyCase` is reused elsewhere (e.g., light wallets, historical validation, or future feature branches) without accompanying case-canonicalization before string-equality comparisons.

### Recommendation
Wherever `isValidAddressAnyCase` is used to accept legacy/format-tolerant addresses, canonicalize (e.g., uppercase) the address string immediately after validation and before using it in any string-equality, sort-order, deduplication, or indexing logic, so a single chash-160 value always maps to exactly one string representation throughout the validation and storage pipeline.

### Proof of Concept
Not independently verifiable without executing the validator against a crafted legacy-era unit (pre-`timestampUpgradeMci`) containing two outputs whose address strings are case-variants of the same base32 chash-160 value (e.g., `"abcdefgh...”` lowercase and `"ABCDEFGH..."` uppercase, both passing `chash.isChashValid`), and observing that `arrOutputAddresses`/`prev_address` treat them as two distinct addresses in `validatePaymentInputsAndOutputs`. This would require constructing a full unit and running it through `validation.js` in a test harness, which was not performed here.

### Citations

**File:** validation.js (L2145-2145)
```javascript
	const isValidAddressWithCase = objValidationState.last_ball_mci >= constants.timestampUpgradeMci ? ValidationUtils.isValidAddress : ValidationUtils.isValidAddressAnyCase;
```

**File:** validation.js (L2174-2194)
```javascript
			if ("address" in output && !isValidAddressWithCase(output.address))
				return callback("output address " + JSON.stringify(output.address) + " invalid");
			if (output.address)
				count_open_outputs++;
		}
		else{
			if ("blinding" in output)
				return callback("public output must not have blinding");
			if ("output_hash" in output)
				return callback("public output must not have output_hash");
			if (!isValidAddressWithCase(output.address))
				return callback("output address " + JSON.stringify(output.address) + " invalid");
			if (prev_address > output.address)
				return callback("output addresses not sorted");
			else if (prev_address === output.address && prev_amount > output.amount)
				return callback("output amounts for same address not sorted");
			prev_address = output.address;
			prev_amount = output.amount;
		}
		if (output.address && arrOutputAddresses.indexOf(output.address) === -1)
			arrOutputAddresses.push(output.address);
```

**File:** validation_utils.js (L52-62)
```javascript
function isValidChash(str, len){
	return (isStringOfLength(str, len) && chash.isChashValid(str));
}

function isValidAddressAnyCase(address){
	return isValidChash(address, 32);
}

function isValidAddress(address){
	return (typeof address === "string" && /^[A-Z2-7]{32}$/.test(address) && isValidChash(address, 32));
}
```
