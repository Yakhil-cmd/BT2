### Title
Case-insensitive address validation for private-payment outputs before `timestampUpgradeMci` allows lowercase-address checksum collisions - (File: `validation.js`)

### Summary
The Jetty CVE is a classic CWE-20 case-manipulation bug: a strict, case-sensitive check (`.jsp`) is bypassed by presenting the same string in a different case, producing security-relevant misclassification of input. `ocore--013` contains an analogous case-manipulation weakness in payment-output address validation: for units before `constants.timestampUpgradeMci`, output addresses are checked with `ValidationUtils.isValidAddressAnyCase()` instead of the case-sensitive `ValidationUtils.isValidAddress()`, allowing lowercase/mixed-case renderings of a 32-byte c-hash to validate as legitimate addresses.

### Finding Description
`validatePaymentInputsAndOutputs()` chooses which address-validity check to apply based on `last_ball_mci`: [1](#0-0) 

```
const isValidAddressWithCase = objValidationState.last_ball_mci >= constants.timestampUpgradeMci ? ValidationUtils.isValidAddress : ValidationUtils.isValidAddressAnyCase;
```

`isValidAddress()` enforces the canonical uppercase base32 alphabet with a regex (`/^[A-Z2-7]{32}$/`) plus a checksum check, whereas `isValidAddressAnyCase()` performs **only** the checksum check (`isValidChash`), with no case restriction: [2](#0-1) 

Because the underlying c-hash checksum algorithm (`chash.isChashValid`) operates on the raw decoded bytes and the base32 decoder is typically case-insensitive/case-normalizing, the *same* 160-bit c-hash payload can be represented as multiple distinct-cased strings that each pass `isValidChash`. When `isValidAddressAnyCase` is used (units below `timestampUpgradeMci`), output/spend-proof/attestation addresses expressed with non-canonical casing are accepted as valid, distinct strings by the rest of the validation and storage pipeline (which treats address strings by exact string equality: sorting checks, `arrOutputAddresses.indexOf`, `prev_address` comparisons, DB `address=?` lookups, balance/UTXO indexing, etc.) — see the sorted-output/double-spend logic immediately following the check: [3](#0-2) 

This is directly analogous to the Jetty bug: a security check (address well-formedness) is performed with the wrong case sensitivity for a particular code path, letting a value that should be normalized/rejected slip through as a syntactically "different" but semantically identical value.

### Impact Explanation
If two case-variant strings decode to the same c-hash (and thus the same underlying public-key-hash address), an attacker constructing units with `last_ball_mci < timestampUpgradeMci` (relevant for AA-response/private-payment code paths that still reference historical mci ranges, and for any private payment/spend-proof processing that revalidates old units) could produce outputs/spend proofs addressed to a case-variant string that:
- fails to match the canonical stored/expected address string used elsewhere in string-equality address bookkeeping (`arrOutputAddresses`, `prev_address`, wallet address matching, balance queries keyed by exact `address` string), potentially causing funds to be attributed to a "new" never-seen address string that is nonetheless spendable by the same private key, or
- causes divergent treatment between nodes/wallets that normalize case differently, leading to disagreement about which output belongs to which address/balance.

This falls into "unauthorized spending / node disagreement on validity" risk categories, though it is capped by the b) it only applies to units with `last_ball_mci` below `constants.timestampUpgradeMci` (an already-passed historical upgrade point), and c) full exploitation depends on base32's case-folding behavior in `thirty-two`, which was not independently verified against the code shown here.

### Likelihood Explanation
Likelihood is limited: the vulnerable branch (`isValidAddressAnyCase`) is only reachable for units whose `last_ball_mci` predates `constants.timestampUpgradeMci`, i.e., historical replay/backfill/catch-up scenarios rather than new unit posting on the live network today. An attacker would need to craft a unit that is accepted as validly timestamped in that old mci range (e.g., via catchup/hash-tree replay) — a scenario an ordinary unprivileged poster could still trigger by design if the network still processes/re-validates such old units for consistency (e.g. private-payment chain replays that only run against the poster's own address history). Because it's restricted to a legacy code path, likelihood is medium rather than high.

### Recommendation
- Confirm whether `thirty-two`'s `base32.decode()` performs case folding when decoding `isValidChash`'s input; if so, unify on a single case-sensitive check (`isValidAddress`) for every mci range, or explicitly canonicalize (uppercase) the address string before any checksum/storage operation regardless of `last_ball_mci`.
- Remove or gate `isValidAddressAnyCase` behind an explicit uppercase-normalization step so that no code path ever accepts a c-hash string in non-canonical case as distinct from its canonical form.
- Audit all other historical/legacy branches (`objValidationState.last_ball_mci >= constants.xxxUpgradeMci ? A : B` patterns) for similar loosened validation left over from protocol upgrades, since this is a repeatable footgun pattern.

### Proof of Concept
Conceptual (not independently executed against `thirty-two`):
1. Take a valid canonical address `ADDR` (uppercase base32, checksum-valid per `chash.isChashValid`).
2. Compute a lower/mixed-case variant `addr` of the same 32-character string.
3. If `base32.decode(addr)` in `chash.js` yields the same byte buffer as `base32.decode(ADDR)` (case-insensitive decoding), then `chash.isChashValid(addr) === true`, so `ValidationUtils.isValidAddressAnyCase(addr) === true` while `ValidationUtils.isValidAddress(addr) === false` (regex `/^[A-Z2-7]{32}$/` fails).
4. Construct a payment message with an output `{ address: addr, amount: N }` in a unit whose `objValidationState.last_ball_mci < constants.timestampUpgradeMci`; `validatePaymentInputsAndOutputs` will accept `addr` via `isValidAddressWithCase = isValidAddressAnyCase`, while downstream address bookkeeping treats `addr` as a distinct string from `ADDR`.

Note: I was not able to fully verify the exact case-folding behavior of the `thirty-two` base32 library from the indexed code; a Devin session with full repo/dependency access should confirm this before treating the finding as conclusively exploitable.

### Citations

**File:** validation.js (L2145-2145)
```javascript
	const isValidAddressWithCase = objValidationState.last_ball_mci >= constants.timestampUpgradeMci ? ValidationUtils.isValidAddress : ValidationUtils.isValidAddressAnyCase;
```

**File:** validation.js (L2184-2194)
```javascript
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
