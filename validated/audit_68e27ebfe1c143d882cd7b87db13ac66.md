### Title
Uncaught exception (process crash / DoS) from malformed c-hash input in address validation - (File: chash.js)

### Summary
`chash.js`'s `isChashValid()` decodes an attacker-supplied encoded hash string and only wraps the *decode* step (`base32.decode`/`Buffer.from(..., 'base64')`) in a `try/catch`. The subsequent processing — `buffer2bin()` and `separateIntoCleanDataAndChecksum()` — is **not** protected, even though `separateIntoCleanDataAndChecksum()` explicitly `throw`s an `Error` when the decoded bit-length is not exactly 160 or 288. This is analogous to the libsixel bug class in the report: insufficient bounds/length validation of attacker-controlled encoded data leads to an unhandled fault (there, a buffer overflow; here, an uncaught JS exception) that can crash the process — a Denial of Service. [1](#0-0) [2](#0-1) 

### Finding Description
`isChashValid(encoded)` validates the string length (32 or 48), then decodes it: [3](#0-2) 

Only the decode call is inside `try/catch`. It then calls `buffer2bin(chash)` and `separateIntoCleanDataAndChecksum(binChash)`, which is where the real length assertion lives: [4](#0-3) 
```
function separateIntoCleanDataAndChecksum(bin){
	var len = bin.length;
	...
	else
		throw Error("bad length="+len+", bin = "+bin);
```
If the decoded buffer's bit-length is not exactly 160 or 288, this `throw` happens *outside* the `try/catch` in `isChashValid`, propagating as an uncaught exception to the caller.

The critical entry point is `isValidAddressAnyCase()`, which — unlike `isValidAddress()` — does **not** first constrain the input to the base32 alphabet `[A-Z2-7]` via regex before calling into c-hash validation: [5](#0-4) 
```
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
Any 32-character string reaches `chash.isChashValid()` through `isValidAddressAnyCase`. If it contains characters outside the RFC4648 base32 alphabet (e.g. lowercase letters, `0`, `1`, `8`, `9`), the `thirty-two` decoder may not throw but instead silently produce a decoded buffer whose byte length differs from the expected 20 bytes (160 bits). This mismatched length is caught in `separateIntoCleanDataAndChecksum` only via an unguarded `throw`, which is not caught anywhere in the `isChashValid` call chain.

`isValidAddressAnyCase` is used pervasively across attacker-reachable input paths (units, addresses in messages, AA triggers, wallet/device messages), per its wide usage in `wallet.js`, `network.js`, `definition.js`, `formula/evaluation.js`, `light.js`, `aa_validation.js`, `uri.js`, etc.

### Impact Explanation
An uncaught exception thrown deep inside a validation utility used across unit/message/AA/wallet processing paths can crash the Node.js process handling that input (unhandled exception → process termination unless a top-level domain/handler exists). If reachable from a posted unit, an AA trigger, or a device/private-payment message field that is validated with `isValidAddressAnyCase` before other safety nets, a single crafted 32-character string can crash a full node or wallet process — a network-availability impact ("a network unable to confirm new units" if it crashes hub/node processes broadly) rather than a memory-safety issue (JS has no real buffer overflow), but the same class of "insufficiently bounds-checked attacker input crashes the parser" as CVE-2020-36120.

### Likelihood Explanation
The precondition (a 32-character string containing non-base32-alphabet characters reaching `isValidAddressAnyCase` without prior regex filtering) is plausible but not confirmed end-to-end in this pass: I was not able to fully verify (a) that `thirty-two`'s `base32.decode` actually returns a non-20-byte buffer instead of throwing for out-of-alphabet input (rather than throwing, which would be caught), and (b) a concrete call site where `isValidAddressAnyCase` is invoked directly on unsanitized, attacker-controlled 32-character strings without an equivalent regex/alphabet check beforehand or without an enclosing `try/catch`/domain that would absorb the exception. These would need to be confirmed by tracing each of the many `isValidAddressAnyCase` call sites and by inspecting the `thirty-two` library's decode behavior on invalid characters.

### Recommendation
- Wrap the entire body of `isChashValid()` (including `buffer2bin` and `separateIntoCleanDataAndChecksum`) in `try/catch`, returning `false` on any exception, matching the defensive pattern already used for the decode step.
- Alternatively/additionally, validate the input alphabet before decoding in `isValidChash`/`isValidAddressAnyCase` (as `isValidAddress` already does), so malformed characters are rejected before reaching low-level decoding.

### Proof of Concept
Conceptual (not fully verified against the `thirty-two` decoder in this pass):
```js
var chash = require('./chash.js');
// A 32-char string with characters outside the base32 alphabet [A-Z2-7]
// e.g. containing lowercase letters or digits 0/1/8/9
var malformed = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"; // 32 chars, invalid base32 alphabet
chash.isChashValid(malformed); // if base32.decode() doesn't throw but yields a
                                // buffer whose bit-length != 160, this throws
                                // an uncaught Error from separateIntoCleanDataAndChecksum
```
This would need to be validated against the actual `thirty-two` module behavior and against a concrete unauthenticated call path (e.g., a unit author/address field validated via `isValidAddressAnyCase`) to confirm full exploitability. Due to the uncertainty noted in the Likelihood section, this should be verified by a follow-up code-level review/test before treating it as fully confirmed.

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
