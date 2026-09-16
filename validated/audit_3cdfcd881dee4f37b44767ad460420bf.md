### Title
Incomplete case blacklist in payment output address validation permits chash-valid but non-canonical addresses when an old `last_ball` is referenced - (File: validation.js)

### Summary
`validatePaymentInputsAndOutputs` selects between a strict, uppercase-only address check and a lenient, any-case check based on the `last_ball_mci` referenced by the unit being validated: [1](#0-0) 

```
const isValidAddressWithCase = objValidationState.last_ball_mci >= constants.timestampUpgradeMci ? ValidationUtils.isValidAddress : ValidationUtils.isValidAddressAnyCase;
```

`isValidAddress` enforces the canonical uppercase base32 alphabet, while `isValidAddressAnyCase` only checks the chash checksum, not the character case: [2](#0-1) 

This is used to validate the `address` field of payment outputs, both for public outputs (line 2184) and private/hidden-payment outputs (line 2174): [3](#0-2) 

### Finding Description
This mirrors the WildFly "incomplete blacklist" bug class: the blacklist/whitelist only recognizes one canonical representation (uppercase filenames in WildFly's case; uppercase base32 addresses here) and fails to account for alternative-but-equivalent representations (lowercase/mixed-case characters that still decode to a valid chash). `isChashValid` decodes with the `thirty-two` base32 library and only checks the checksum bits, so a lowercase or mixed-case rendering of a valid address string can pass `isValidAddressAnyCase` even though it is not the canonical `[A-Z2-7]{32}` string used everywhere else in the codebase (DB primary keys, wallet's own-address lists, `Array.indexOf`/string equality comparisons, JS string sort order used for the "outputs must be sorted by address" rule at line 2186-2189).

The strict/lenient choice is gated by the `last_ball_mci` of the *unit being validated*, not by the current network mci. Because `last_ball` only needs to be some valid stable ball that is an ancestor consistent with DAG ordering rules (it is not required to be the network's very latest stable ball), a unit author has some latitude in choosing which stable ball to reference as `last_ball`. If it is possible to reference a `last_ball` whose mci is below `constants.timestampUpgradeMci` (5,210,000 on mainnet / 909,000 on testnet), the lenient, case-insensitive path re-activates for a payment message in an otherwise modern unit.

### Impact Explanation
If an attacker can trigger the lenient path, they can construct payment outputs (public or private/hidden) whose `address` field is a case-mutated but chash-valid variant of a real address. Every other part of the system (wallet's known-address list, `addresses` table primary key lookups, balance queries, string-based sort/uniqueness checks such as `prev_address`/`arrOutputAddresses.indexOf`) treats addresses as exact-case strings. A payment can therefore be confirmed as valid by the validator while depositing funds to a string that no wallet recognizes as "its own" address, permanently freezing those funds (classic address-normalization fund-loss/freezing bug), or it can desynchronize case-sensitive uniqueness/sort checks (`arrOutputAddresses`, `prev_address` ordering) from case-insensitive equivalence, which is exactly the class of inconsistency that historically enables double-spend/inconsistent-validation bugs when different nodes or code paths disagree about which units are "the same" address.

### Likelihood Explanation
Exploitability hinges entirely on whether an attacker can freely choose an old, low-mci `last_ball` for a new unit while still satisfying all other DAG/stability constraints (non-retreating witnessed level, parent stability, etc.). I was not able to fully verify, within the available tooling, whether the protocol enforces that `last_ball` must be recent/monotonically advancing per author in a way that forecloses picking an ancient ball far below `timestampUpgradeMci`. This is the key open question that determines whether the bug is currently reachable by an ordinary unit poster today, or whether it is purely a dead, backward-compatibility code path for units that were already broadcast before the `timestampUpgradeMci` activation (in which case it has no exploitable impact on the current network).

### Recommendation
- Confirm whether `last_ball` selection permits referencing arbitrarily old stable balls; if so, drop the mci-gated branch entirely and always enforce `ValidationUtils.isValidAddress` (canonical-case only) for payment output addresses, regardless of `last_ball_mci`.
- Independently of the above, ensure all downstream consumers of addresses (DB schema, wallet's own-address matching, sort/uniqueness comparisons) either normalize to a single case before comparison or reject any address that isn't already in canonical form, so that case-based inconsistencies cannot occur even in latent/legacy code paths.

### Proof of Concept
Not fully constructible without confirming the `last_ball`-selection freedom described above (i.e., whether a new unit can reference an ancestor stable ball with `mci < constants.timestampUpgradeMci`). Conceptually:
1. Compose a payment unit whose `last_ball_unit` points to a stable ball with `mci < timestampUpgradeMci`.
2. In the payment message, set an output `address` to a case-mutated (e.g., lowercase) but chash-valid rendering of a target address.
3. If step 1 is achievable, `isValidAddressWithCase` resolves to `isValidAddressAnyCase`, the output passes validation, and the funds land on a string address that the target wallet's canonical uppercase address list will never match, resulting in frozen/lost funds.

### Citations

**File:** validation.js (L2145-2145)
```javascript
	const isValidAddressWithCase = objValidationState.last_ball_mci >= constants.timestampUpgradeMci ? ValidationUtils.isValidAddress : ValidationUtils.isValidAddressAnyCase;
```

**File:** validation.js (L2163-2185)
```javascript
		if (objAsset && objAsset.is_private){
			if (("output_hash" in output) !== !!objAsset.fixed_denominations)
				return callback("output_hash must be present with fixed denominations only");
			if ("output_hash" in output && !isStringOfLength(output.output_hash, constants.HASH_LENGTH))
				return callback("invalid output hash");
			if (!objAsset.fixed_denominations && !(("blinding" in output) && ("address" in output)))
				return callback("no blinding or address");
			if ("blinding" in output && !isStringOfLength(output.blinding, 16))
				return callback("bad blinding");
			if (("blinding" in output) !== ("address" in output))
				return callback("address and blinding must come together");
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
```

**File:** validation_utils.js (L56-62)
```javascript
function isValidAddressAnyCase(address){
	return isValidChash(address, 32);
}

function isValidAddress(address){
	return (typeof address === "string" && /^[A-Z2-7]{32}$/.test(address) && isValidChash(address, 32));
}
```
