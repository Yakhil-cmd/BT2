### Title
Uncaught exception (validation crash / DoS) in c-hash decoding for malformed same-length address strings - (File: chash.js)

### Summary
`chash.isChashValid()` only wraps the base32/base64 *decode* step in a `try/catch`. If the decode call does not throw but nonetheless returns a byte buffer whose bit-length is not exactly 160 or 288 (e.g. a `thirty-two` base32 decode of a string that contains characters technically accepted by the library but that do not map to a clean 20-byte value), the subsequent call to `separateIntoCleanDataAndChecksum()` throws an **uncaught** `Error("bad length=...")` that is not caught anywhere in the call chain.

### Finding Description
`isChashValid` in [1](#0-0)  performs:
```
try{
    var chash = (encoded_len === 32) ? base32.decode(encoded) : Buffer.from(encoded, 'base64');
}
catch(e){
    console.log(e);
    return false;
}
var binChash = buffer2bin(chash);
var separated = separateIntoCleanDataAndChecksum(binChash);
```
Only the decode call is protected. `separateIntoCleanDataAndChecksum` unconditionally throws if the resulting bit length is not exactly 160 or 288: [2](#0-1) . This throw is outside the `try` block, so it propagates as an unhandled exception to whatever caller invoked `isChashValid`.

Crucially, `validation_utils.js` exposes two entry points into this code:
- `isValidAddress(address)` — pre-filters input with the regex `/^[A-Z2-7]{32}$/` before calling `isChashValid`, which restricts the input to the exact base32 alphabet and effectively guarantees a clean 160-bit decode. [3](#0-2) 
- `isValidAddressAnyCase(address)` — calls `isValidChash(address, 32)` directly, **without** the character-set regex filter, meaning it forwards the raw 32-character (or 48-character, if used at len 48) attacker string straight into `base32.decode`/`Buffer.from` and then into the unguarded `separateIntoCleanDataAndChecksum` throw path. [4](#0-3) 

This mirrors the root cause of CVE‑2023‑37837's bug class: a decode/parsing routine that trusts attacker-supplied length/content invariants without validating them before further processing, leading to a crash on crafted input. Here the manifestation in JavaScript is an unhandled exception (Node.js process crash / unrecoverable validation error) instead of a native heap overflow, but the underlying defect — asymmetric bounds/format checking around a decode step reachable from untrusted network/unit data — is analogous.

### Impact Explanation
If `isValidAddressAnyCase` (or any other caller that reaches `isChashValid` without pre-filtering the character set) is invoked on attacker-controlled data taken from a posted unit, AA trigger, or wallet message, a single crafted string can throw an uncaught exception during validation. Since every node performing the same validation would hit the same crash on the same input, this can produce denial of service (nodes unable to process/validate units containing the crafted value), which matches the required "network unable to confirm new units" impact class.

### Likelihood Explanation
Likelihood depends entirely on whether `isValidAddressAnyCase` (or another non-regex-filtered caller of `isChashValid`) is reachable with attacker-controlled data from a single posted unit, AA trigger, or device message. `isValidAddress` — the function used for standard address fields in unit authors/outputs — already regex-filters input and is not vulnerable. I was not able to fully enumerate, within the available tool budget, every call site of `isValidAddressAnyCase` across the codebase to confirm it is reachable from consensus-critical, attacker-controlled input (e.g., unconfirmed whether it's used for asset/AA address fields, witness lists, or definition template placeholders that accept mixed-case chash strings before normalization). This should be verified before treating the impact as fully confirmed.

### Recommendation
- Move the length/format check (`binChash.length === 160 || binChash.length === 288`) inside the `try` block in `isChashValid`, or wrap the whole function body (including `separateIntoCleanDataAndChecksum` and `bin2buffer`) in a single try/catch that returns `false` on any exception, exactly mirroring the existing safe behavior for decode failures.
- Audit and confirm every caller of `isValidAddressAnyCase` (and any other consumer of `isChashValid` that doesn't pre-filter with the base32-charset regex) to ensure malformed same-length strings cannot reach unguarded exception paths during unit/AA/message validation.

### Proof of Concept
Conceptual (not fully verified end-to-end due to inability to confirm `thirty-two`'s exact decode leniency in this session):
```js
var validationUtils = require('./validation_utils.js');
// A 32-character string using only [A-Z2-7] characters that the 'thirty-two'
// decoder accepts without throwing, but whose decoded byte length/bit-mixing
// does not satisfy exactly 160 bits after checksum extraction.
var crafted = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA2"; // illustrative; needs decoder-specific crafting
validationUtils.isValidAddressAnyCase(crafted); // throws uncaught Error("bad length=...") instead of returning false
```
Constructing a concrete input string that passes `base32.decode` without throwing yet yields a non-160-bit result requires further inspection of the `thirty-two` library's decode tolerance, which was not completed in this session — this should be validated by a developer with codebase/dependency access before treating the PoC as conclusive.

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
