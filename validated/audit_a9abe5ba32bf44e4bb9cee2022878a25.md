### Title
Uncaught exception / crash in `chash.isChashValid` via malformed c-hash string reachable through `is_valid_address`/`is_aa` oscript in AAs and `isValidAddressAnyCase` - ([File: chash.js])

### Summary
The Pillow `ImagingPcdDecode` bug (CVE-2016-2533) is a crash-on-malformed-input caused by insufficient bounds/length validation before processing decoded data. The closest reachable analog in ocore is in `chash.js`, where `isChashValid()` decodes an attacker-supplied base32/base64 string and then unconditionally feeds the decoded buffer into length-sensitive helpers that `throw` on unexpected lengths outside of any `try/catch`.

### Finding Description
`isChashValid(encoded)` only guards the `base32.decode`/`Buffer.from` call in a `try/catch`: [1](#0-0) 

After that point, `buffer2bin(chash)` converts the decoded buffer to a bit-string of length `chash.length*8`, and this bit-string is passed to `separateIntoCleanDataAndChecksum`, which strictly requires the length to be exactly 160 or 288 bits, otherwise it `throw`s uncaught: [2](#0-1) 

For the primary caller `isValidAddress`, a regex `^[A-Z2-7]{32}$` is applied first, which guarantees the base32 alphabet and forces the decoded buffer to be exactly 20 bytes (160 bits), so the throwing path is unreachable there: [3](#0-2) 

However, `isValidAddressAnyCase` calls `isValidChash(address, 32)` **without** the charset regex check: [4](#0-3) 

This means a 32-character string that is not restricted to `[A-Z2-7]` can still reach `chash.isChashValid`. Depending on how the `thirty-two` decoder handles out-of-alphabet characters (it may silently skip/ignore invalid characters rather than throwing, which is a documented quirk of several base32 libraries), the resulting decoded buffer can end up with a length other than 20 bytes, causing `buffer2bin`/`separateIntoCleanDataAndChecksum` to throw an uncaught `Error` from inside `isChashValid`, propagating out of `isValidChash`/`isValidAddressAnyCase` to whatever unprivileged code path invoked it (e.g., `is_aa()` formula evaluation, definitions, AA trigger address checks) if that call site does not wrap the check in a `try/catch`.

### Impact Explanation
If any oscript/AA evaluation path (or other unit-validation path) calls `isValidAddressAnyCase` without a surrounding `try/catch`, a single crafted unit/AA trigger containing an attacker-chosen 32-character string can throw an uncaught exception during validation. In a Node.js process, an uncaught synchronous exception thrown deep in validation logic (not inside an `async` callback boundary that's caught) can propagate up and crash the node process handling that unit — a "network unable to confirm new units" condition if triggered against multiple/relied-upon nodes, matching the accepted DoS-crash impact class analogous to the Pillow bug.

### Likelihood Explanation
This requires: (1) an oscript path or other production code that calls `isValidAddressAnyCase` (or `chash.isChashValid` directly) on fully attacker-controlled 32-character strings without a `try/catch`, and (2) the `thirty-two` `base32.decode` implementation to not throw on invalid alphabet characters and instead return a buffer of an unexpected length. Both conditions were not fully confirmed within the tool budget available — the exact behavior of the `thirty-two` package's decoder for non-alphabet input, and a definitive unguarded call site for `isValidAddressAnyCase` outside `try/catch` blocks in oscript evaluation, could not be verified from the indexed code. This should be treated as **unconfirmed/uncertain** pending direct inspection of the `thirty-two` module source and every call site of `isValidAddressAnyCase`.

### Recommendation
- Wrap the entire body of `isChashValid` (not just the decode step) in a single `try/catch` returning `false` on any error, so malformed inputs of any decoded length fail validation gracefully instead of throwing.
- Add an explicit length check on the decoded buffer immediately after decoding (`chash.length !== 20 && chash.length !== 36` → return `false`) before calling `buffer2bin`.
- Audit all call sites of `isValidAddressAnyCase` (oscript `is_valid_address`, `is_aa`, definitions, AA composer, arbiters, data feeds, `wallet_defined_by_addresses.js`) to confirm they either apply the same charset restriction as `isValidAddress` or are wrapped in error handling that cannot crash the process.

### Proof of Concept
Given the unresolved uncertainty about the `thirty-two` decode behavior for invalid input, a concrete PoC could not be constructed and verified within this session. A verifying engineer should:
1. Call `require('thirty-two').decode('!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!')` (32 non-base32 characters) and inspect the returned buffer length.
2. If the length is not 20 bytes, call `chash.isChashValid('!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!')` directly and confirm it throws rather than returning `false`.
3. Trace whether any oscript function (`is_aa`, `is_valid_address` when evaluated against `isValidAddressAnyCase`-style checks) or other unauthenticated-input path calls this without a `try/catch`, to confirm end-to-end reachability and process-crash impact.

### Citations

**File:** chash.js (L45-53)
```javascript
function separateIntoCleanDataAndChecksum(bin){
	var len = bin.length;
	var arrOffsets;
	if (len === 160)
		arrOffsets = arrOffsets160;
	else if (len === 288)
		arrOffsets = arrOffsets288;
	else
		throw Error("bad length="+len+", bin = "+bin);
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
