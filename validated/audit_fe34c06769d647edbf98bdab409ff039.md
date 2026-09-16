### Title
Case-sensitivity parser differential in address validation (`isValidAddress` vs `isValidAddressAnyCase`) enables mismatched output/address matching in payment validation - ([File: validation.js], [File: validation_utils.js])

### Summary
`validation_utils.js` defines two different address-validity checks that mirror the "strict vs. lenient parser" pattern from the reported Angular SSRF bug: `isValidAddress()` requires the base32 alphabet `A-Z2-7` (case-sensitive, uppercase only) plus a valid chash checksum, while `isValidAddressAnyCase()` only checks the chash checksum and accepts any letter case. `validatePaymentInputsAndOutputs()` in `validation.js` deliberately selects between these two functions based on `last_ball_mci` relative to `constants.timestampUpgradeMci`, meaning payment-output address strings can be validated by either the strict or the lenient parser depending on chain height.

### Finding Description [1](#0-0) 
defines the strict (`isValidAddress`) and lenient (`isValidAddressAnyCase`) checks. The strict function enforces the canonical uppercase base32 alphabet in addition to the chash checksum, while the lenient one accepts any case as long as `base32.decode()` and the checksum validate — `chash.js`'s `isChashValid` calls `base32.decode(encoded)` [2](#0-1)  which (via the `thirty-two` package) is case-insensitive, so a mixed/lower-case address such as `mxmekgn37h5qo2awht7xrg6lhjvvtawu` decodes to the exact same bytes/checksum as its uppercase canonical form and is accepted by `isValidAddressAnyCase`.

`validatePaymentInputsAndOutputs()` picks the check to apply to payment outputs based on chain height: [3](#0-2) 
and then uses that same function for both string form-checks and public-output sort-order/uniqueness comparisons: [4](#0-3) 
Outside this one gated call site, essentially every other place in the codebase that must recognize the "same" 32-character address — `definition.js` address/authentifier ops, `formula/validation.js`/`formula/evaluation.js` `address`/`input`/`output`/`attestation` fields, `aa_validation.js`, `signed_message.js`, `wallet.js`, `data_feeds.js`, etc. — calls the strict, case-sensitive `isValidAddress` exclusively (per the grep results, 20+ call sites across the codebase use `isValidAddress`, and outside `validation.js` no other module conditionally substitutes `isValidAddressAnyCase`). Address *equality* everywhere else (in `input`/`output` matching in `formula/evaluation.js`, in `objAuthor.address === other_address` filters in `definition.js`, in balance bookkeeping in `aa_composer.js`/`balances.js`) is a plain JavaScript string `===` comparison, which is case-sensitive.

This creates the same class of bug as the Angular SSRF report: one code path (the pre-`timestampUpgradeMci` branch of payment validation) accepts an address string using the *lenient* parser (case-insensitive chash check), while all the surrounding logic that subsequently *keys off* that same string — output sorting/uniqueness checks in the very same function, and address matching used throughout `formula/evaluation.js` for `input[[...]]`/`output[[...]]` filters, `definition.js`'s "this address"/`sum`/`has definition change` filters, and AA state/balance bookkeeping in `aa_composer.js` — uses strict, case-sensitive string comparison. A lower/mixed-case address that is a byte-for-byte equivalent chash of a canonical address can therefore be treated as a *different* address by everything downstream of the lenient check, even though it decodes to the identical account.

### Impact Explanation
If an attacker crafts a payment output using a non-canonical-case rendering of a valid address (accepted only where the lenient `isValidAddressAnyCase` gate is in effect, i.e., for units whose `last_ball_mci < timestampUpgradeMci`), the output would pass validation.js's amount/asset checks, but:
- The "public outputs must be sorted by address" and "same address must have amounts sorted" invariants (lines 2186–2189) compare the address string with strict case sensitivity, so a lower-case variant of an address that should be treated as identical to an existing output address would not be recognized as the same address, silently defeating the anti-duplicate/sort-order invariant that other nodes may re-derive differently depending on how they treat case, producing a **node disagreement on unit validity** (a fork/consensus divergence) between nodes running before/after `timestampUpgradeMci` semantics are applied consistently.
- Any AA, oscript formula (`input[[address=...]]`, `output[[address=...]]`), or address-definition condition (`has definition change`, `sum` filters in `definition.js`) that filters payment inputs/outputs by address using strict `===` would fail to match a payment to/from the "same" address rendered in different case, causing **AA fund loss/freezing** (funds sent to a case-variant of the expected address are not recognized as satisfying a spending condition or a state transition) or unauthorized bypass of address-based spending filters.

### Likelihood Explanation
The vulnerable branch is explicitly gated by `last_ball_mci >= constants.timestampUpgradeMci`, i.e., it is dead code for all units above that historical upgrade point in the current chain, so it is not exploitable going forward under normal operation. Exploitability is limited to the narrow historical window/replay path guarded by the mci check, or to any other place that fails to apply the same upgrade gate consistently. This significantly limits real-world likelihood compared to the Angular case (which is exploitable on every request); I could not find a second, currently-reachable code path that applies `isValidAddressAnyCase` without the mci gate, so the concretely exploitable surface is narrow and largely historical/legacy-compatibility related rather than a live network-wide bypass.

### Recommendation
Not applicable in ask-only mode — this is an analysis only.

### Proof of Concept
Not fully constructable from static analysis alone: exploitation requires constructing a unit with `last_ball_mci < constants.timestampUpgradeMci` (i.e., only reproducible against historical chain state or in a modified test harness that lowers `timestampUpgradeMci`), containing a payment output whose address is a lower/mixed-case rendering of a valid chash (e.g. take any valid 32-char uppercase address and lowercase it), and then observe that: (1) `validatePaymentInputsAndOutputs` accepts it via `isValidAddressAnyCase`, while (2) an oscript `output[[address="<uppercase form>"]]` filter or `definition.js`'s address-equality filters fail to match it due to case-sensitive `===`. I was not able to execute this against a live node/test harness to confirm end-to-end impact; this should be verified with a Devin session that can run the existing test suite (e.g. `test/validation.test.js`, `formulas_in_contracts.test.js`) against a manually constructed pre-upgrade unit.

### Citations

**File:** validation_utils.js (L56-62)
```javascript
function isValidAddressAnyCase(address){
	return isValidChash(address, 32);
}

function isValidAddress(address){
	return (typeof address === "string" && /^[A-Z2-7]{32}$/.test(address) && isValidChash(address, 32));
}
```

**File:** chash.js (L152-171)
```javascript
function isChashValid(encoded){
	var encoded_len = encoded.length;
	if (encoded_len !== 32 && encoded_len !== 48) // 160/5 = 32, 288/6 = 48
		throw Error("wrong encoded length: "+encoded_len);
	try{
		var chash = (encoded_len === 32) ? base32.decode(encoded) : Buffer.from(encoded, 'base64');
	}
	catch(e){
		console.log(e);
		return false;
	}
	var binChash = buffer2bin(chash);
	var separated = separateIntoCleanDataAndChecksum(binChash);
	var clean_data = bin2buffer(separated.clean_data);
	//console.log("clean data", clean_data);
	var checksum = bin2buffer(separated.checksum);
	//console.log(checksum);
	//console.log(getChecksum(clean_data));
	return checksum.equals(getChecksum(clean_data));
}
```

**File:** validation.js (L2145-2145)
```javascript
	const isValidAddressWithCase = objValidationState.last_ball_mci >= constants.timestampUpgradeMci ? ValidationUtils.isValidAddress : ValidationUtils.isValidAddressAnyCase;
```

**File:** validation.js (L2174-2193)
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
```
