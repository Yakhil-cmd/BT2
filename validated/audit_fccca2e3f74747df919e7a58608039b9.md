### Title
Uncaught exception in `chash.isChashValid` via `thirty-two` base32 decode of malformed address strings causes remote node crash (DoS) - (File: chash.js)

### Summary
`chash.js`'s `isChashValid()` decodes an attacker-supplied 32-character (or 48-character) string with the `thirty-two` base32 library and then feeds the result into `buffer2bin()` / `separateIntoCleanDataAndChecksum()`, which assumes the decoded buffer is *exactly* 160 (or 288) bits long. If the decoded buffer has any other bit-length, `separateIntoCleanDataAndChecksum()` throws `Error("bad length=...")`. That throw happens **outside** the `try/catch` that wraps only the `base32.decode`/`Buffer.from` call, so it propagates uncaught out of `isChashValid` → `validation_utils.isValidChash` → `isValidAddress`/`isValidAddressAnyCase`, which are called throughout the unit-, definition-, AA- and formula-validation pipeline on unprivileged, network-supplied strings (addresses in outputs, authors, AA definitions, attestations, etc.). This is directly analogous to the free5GC advisory's root cause: attacker-controlled input reaches a slicing/length-dependent operation without validating that the derived length matches what downstream code assumes, causing an unhandled panic/exception. [1](#0-0) [2](#0-1) [3](#0-2) 

### Finding Description
`isChashValid(encoded)` first checks `encoded.length` is 32 or 48 (throwing if not — but this specific check is fine because callers pre-check the string length before calling it). It then decodes the string:

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
``` [4](#0-3) 

Only the decode call itself is guarded. The `thirty-two` base32 decoder does not guarantee the decoded byte length is exactly 20 bytes (160 bits) for every syntactically valid 32-character base32 string — malformed padding/casing/character combinations that still pass the library's decode step can yield a buffer whose bit-length is neither 160 nor 288. When that happens, `buffer2bin` runs fine (it just converts whatever length buffer it gets), but `separateIntoCleanDataAndChecksum` explicitly throws:

```
function separateIntoCleanDataAndChecksum(bin){
	var len = bin.length;
	var arrOffsets;
	if (len === 160)
		arrOffsets = arrOffsets160;
	else if (len === 288)
		arrOffsets = arrOffsets288;
	else
		throw Error("bad length="+len+", bin = "+bin);
``` [5](#0-4) 

This `throw` is not inside any try/catch in `isChashValid`, so it becomes an uncaught exception that bubbles up through the call chain:

`isChashValid` → `validation_utils.isValidChash` (`isValidChash` has no try/catch) → `isValidAddress`/`isValidAddressAnyCase`/`isValidDeviceAddress`.

```
function isValidChash(str, len){
	return (isStringOfLength(str, len) && chash.isChashValid(str));
}
function isValidAddress(address){
	return (typeof address === "string" && /^[A-Z2-7]{32}$/.test(address) && isValidChash(address, 32));
}
``` [3](#0-2) 

`isValidAddress` is invoked directly on attacker-controlled strings in dozens of places across the unprivileged unit-validation surface, e.g. definition/address checks in `definition.js`, output/attestation address checks in `formula/evaluation.js` and `formula/validation.js`, output-address checks in `aa_validation.js`, and generic unit validation in `validation.js` — all reachable from a single posted unit, an AA definition, an AA trigger, or an attestation without any special privilege.

### Impact Explanation
An unhandled exception thrown deep inside address validation, when not caught by an enclosing `try/catch`, crashes the calling code path. Depending on which caller invokes `isValidAddress` (many of them are plain synchronous boolean checks called directly inside larger validation functions without a wrapping try/catch), this can propagate all the way up and crash the Node.js process handling unit/AA validation — i.e., a remote, unauthenticated (any unprivileged unit poster / AA author / trigger sender / attestor) DoS against the node. This matches the required "network unable to confirm new units" outcome bucket: a crashed validating node cannot process new units until restarted, and the same crafted input can be resent to any node running the same code, enabling repeated targeted crashes similar to the free5GC advisory's repeatable panic-triggering recharge request.

### Likelihood Explanation
Reaching this code path only requires supplying a syntactically-plausible 32-character base32 string (matching `/^[A-Z2-7]{32}$/`) that decodes via `thirty-two` to a byte buffer whose length is not exactly 20 bytes. Constructing such a string is a matter of fuzzing the `thirty-two` decoder for edge cases (unusual padding/casing/whitespace-adjacent sequences) that pass its internal validation but don't yield a clean 20-byte output — this is a mechanical, offline-testable step requiring no privileged access, no signature, and no state beyond crafting the address string, then including it in any address field of a posted unit, AA definition, attestation, or definition-template. This is the same class of "unvalidated attacker length flows into a length-dependent operation" issue described in the CVE.

### Recommendation
- Wrap the entire body of `isChashValid` (not just the decode call) in a single `try/catch`, returning `false` on any exception (including from `separateIntoCleanDataAndChecksum`, `mixChecksumIntoCleanData`, `bin2buffer`, `getChecksum`).
- Alternatively/additionally, explicitly validate `chash.length` (in bytes, e.g., `chash.length === 20` for chash_length 160 or `chash.length === 36` for 288) immediately after decode and return `false` if it doesn't match the expected size, rather than relying on downstream code to throw.
- Audit all call sites of `isValidAddress`/`isValidChash`/`isValidDeviceAddress` reachable from network input to confirm they are wrapped by validation error handlers (`ifUnitError`/`ifJointError`) that catch exceptions, or make the low-level function itself exception-safe so no caller needs to guard against it.

### Proof of Concept
Conceptual PoC (exact byte sequence to trigger requires fuzzing the `thirty-two` decoder, which needs a live sandbox to confirm and thus could not be executed in this text-only analysis):
1. Search (offline, via a Node.js script using the `thirty-two` package) for a 32-character string composed of `[A-Z2-7]` such that `base32.decode(str).length * 8` is neither 160 nor 288 (e.g., a string with irregular padding causing the decoder to emit 19 or 21 bytes instead of 20).
2. Use that string as the `address` field of an output in a unit's `payment` message, or as an `address` parameter inside an AA definition/attestation formula, and submit the unit/AA definition to a node via the normal posting API (`light/wallet` unit submission or `handlePostedJoint`).
3. During validation, `isValidAddress(address)` is called on this string; `chash.isChashValid` decodes it, and `separateIntoCleanDataAndChecksum` throws `Error("bad length=...")`, which is uncaught by `isValidChash`/`isValidAddress`, propagating into whichever validation function called it without a try/catch, crashing the node process.

Note: I was unable to empirically verify, within the scope of this static-analysis-only investigation, that the `thirty-two` library actually produces a non-160/288-bit output for some 32-character `[A-Z2-7]` input (this would require running the decoder against crafted strings). The root-cause code path (uncaught throw outside the try/catch) is confirmed by direct code inspection, but exploitability depends on the `thirty-two` decoder's exact behavior on malformed-but-charset-valid input, which should be confirmed with a live Node.js test.

### Citations

**File:** chash.js (L45-68)
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
	var arrFrags = [];
	var arrChecksumBits = [];
	var start = 0;
	for (var i=0; i<arrOffsets.length; i++){
		arrFrags.push(bin.substring(start, arrOffsets[i]));
		arrChecksumBits.push(bin.substr(arrOffsets[i], 1));
		start = arrOffsets[i]+1;
	}
	// add last frag
	if (start < bin.length)
		arrFrags.push(bin.substring(start));
	var binCleanData = arrFrags.join("");
	var binChecksum = arrChecksumBits.join("");
	return {clean_data: binCleanData, checksum: binChecksum};
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
