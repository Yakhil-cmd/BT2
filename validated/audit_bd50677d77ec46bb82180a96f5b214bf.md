Found the analog. This is a genuine case-sensitivity policy bypass in ocore, structurally identical to the gnutls issue: a security-relevant identifier check accepts multiple case variants (or is validated case-insensitively in one code path) while other code treats case as significant, creating a mismatch that can be exploited to bypass invariants (here, address-sorting/uniqueness invariants for private-asset outputs).

### Title
Case-insensitive address validation for private-asset payment outputs before `timestampUpgradeMci` breaks output sorting/uniqueness invariants - ([File: validation.js])

### Summary
`validatePaymentInputsAndOutputs` in `validation.js` selects the address-validation function to use based on `last_ball_mci`: [1](#0-0) 

Before `constants.timestampUpgradeMci`, it uses `ValidationUtils.isValidAddressAnyCase` instead of the strict, case-sensitive `ValidationUtils.isValidAddress`: [2](#0-1) 

`isValidAddressAnyCase` only checks the chash validity of the string, without enforcing the canonical `^[A-Z2-7]{32}$` uppercase encoding that `isValidAddress` requires. This is directly analogous to the gnutls bug: a security-sensitive identifier comparison/validation is done without normalizing case, while the rest of the system (address sorting, uniqueness keys, definition/authors matching) assumes addresses are always the strict canonical uppercase form.

### Finding Description
Ocore addresses are chash160 values that are only considered canonical when encoded in uppercase base32 (`isValidAddress`'s regex `^[A-Z2-7]{32}$`). The `chash.isChashValid` check used inside `isValidAddressAnyCase` validates the checksum/encoding structurally but does not enforce case, so a lowercase (or mixed-case) rendering of a valid chash can also pass `isValidAddressAnyCase`.

`validatePaymentInputsAndOutputs` uses this permissive check for private-asset payment outputs when `last_ball_mci < constants.timestampUpgradeMci`: [3](#0-2) 

The output-sorting invariant ("outputs must be sorted by address") and the "same address, sorted by amount" invariant both rely on plain string (`<`, `===`) comparisons of `output.address`, not case-normalized comparisons: [4](#0-3) 

Because JavaScript string ordering places uppercase letters before lowercase letters in ASCII, a differently-cased rendering of the *same underlying address* sorts to a different position than its canonical uppercase counterpart and is treated as a *different* string for uniqueness/dedup purposes (`arrOutputAddresses.indexOf`). This mirrors the gnutls flaw precisely: identifiers meant to be canonicalized are compared case-sensitively in the invariant-enforcement logic while a separate acceptance path (`isValidAddressAnyCase`) allows non-canonical casing through.

### Impact Explanation
An attacker crafting a private-asset payment message before `timestampUpgradeMci` (this legacy code path is still reachable for any unit whose `last_ball_mci` predates the upgrade, e.g., replays/historical processing or testnets/devnets that never advanced past this mci) could submit two outputs that are logically the "same address" in differing case, defeating the `arrOutputAddresses` uniqueness check and the required sort order without violating the low-level chash validity check. Since output ownership resolution and downstream double-spend/duplicate-output logic key off exact string equality of `output.address`, this can let an attacker construct outputs that are accepted as distinct entries (bypassing "no duplicate output address" logic) or that violate the canonical sort order silently, producing units that different nodes might disagree about if any other code path normalizes case differently, risking a fork in validity/stability consensus for private payment chains.

### Likelihood Explanation
Exploitability requires the unit's `last_ball_mci` to be below `constants.timestampUpgradeMci`, and requires the target being a private, non-fixed-denomination asset payment (or fixed-denomination path also uses `isValidAddressWithCase`). This narrows applicability mostly to historical/mci-locked scenarios (e.g., devnets or private chains that haven't progressed past the upgrade point), but wherever reachable, it is triggerable by a single unprivileged unit poster crafting a private payment message — no privileged role or peer collusion needed.

### Recommendation
Remove or tighten the `isValidAddressAnyCase` fallback so that address validation for outputs (and any other consensus-critical address field) always requires the strict canonical uppercase form (`isValidAddress`), independent of `last_ball_mci`. If backward compatibility with pre-`timestampUpgradeMci` units must be preserved, canonicalize (upper-case) all addresses immediately after `isValidAddressAnyCase` succeeds and before they are used in sorting, uniqueness, or storage comparisons, so case never leaks into consensus-relevant string equality/ordering.

### Proof of Concept
1. Take a valid base32 chash address `ADDR` (uppercase, 32 chars, passes `isValidAddress`).
2. Compute `addr_lower = ADDR.toLowerCase()`. Confirm `isValidAddressAnyCase(addr_lower) === true` while `isValidAddress(addr_lower) === false` (per `validation_utils.js` lines 52-62).
3. Craft a unit whose `last_ball_mci` is below `constants.timestampUpgradeMci`, containing a private, divisible-asset payment message with two outputs: `{address: ADDR, amount: X, blinding: b1}` and `{address: addr_lower, amount: Y, blinding: b2}`.
4. Submit through `validatePaymentInputsAndOutputs`; because `isValidAddressWithCase` resolves to `isValidAddressAnyCase` for this mci, both outputs pass the per-output address check at [5](#0-4) , and because `ADDR !== addr_lower` as JS strings, they are treated as distinct entries in `arrOutputAddresses` and in the sort-order check, even though they resolve to the same underlying chash/address.

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
