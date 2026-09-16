## Finding [1](#0-0) 

### Title
Uncaught exception (DoS) in `isChashValid` on malformed-length decoded hash - (File: chash.js)

### Summary
`chash.js`'s `isChashValid` wraps only the base32/base64 *decode* step in a `try/catch`, but the subsequent call to `separateIntoCleanDataAndChecksum` — which `throw`s a bare `Error` whenever the decoded bit-length isn't exactly 160 or 288 — is left unprotected. This is structurally the same bug class as CVE-2017-9204 (`iw_get_ui16le`): a length assumption baked into a fixed-format parser is not actually enforced against the real length of attacker-controlled decoded data, so a crafted input reaches a code path that was never designed to handle it, causing an unhandled fault (there, a native SEGV; here, an uncaught JS exception that can crash/kill the Node.js process handling unit validation).

### Finding Description
`isChashValid(encoded)` [1](#0-0)  only guards the decode call:
```
try{ var chash = (encoded_len === 32) ? base32.decode(encoded) : Buffer.from(encoded, 'base64'); }
catch(e){ return false; }
var binChash = buffer2bin(chash);
var separated = separateIntoCleanDataAndChecksum(binChash);   // <-- NOT in try/catch
```
`separateIntoCleanDataAndChecksum` [2](#0-1)  throws `Error("bad length=...")` whenever `bin.length` (i.e. `chash.length * 8`) is not exactly 160 or 288 bits. The function assumes that a 32-character input always decodes to exactly 20 bytes and a 48-character input always decodes to exactly 36 bytes — mirroring the ImageWorsener bug of trusting a fixed-size field read without verifying the actual buffer bounds/length before use.

This assumption holds for `isValidAddress`, which pre-filters input with a strict regex `/^[A-Z2-7]{32}$/` before calling into chash validation [3](#0-2) . However, `isValidChash`/`isValidAddressAnyCase` do **not** apply that alphabet restriction — they only check string length before calling `chash.isChashValid` directly [4](#0-3) :
```
function isValidChash(str, len){
	return (isStringOfLength(str, len) && chash.isChashValid(str));
}
function isValidAddressAnyCase(address){
	return isValidChash(address, 32);
}
```
If the underlying `thirty-two` base32 decoder (or Node's inherently lenient `Buffer.from(x, 'base64')`, which silently skips characters outside the base64 alphabet rather than throwing) is fed a 32- or 48-character string containing out-of-alphabet characters and produces a decoded buffer whose byte length differs from the expected 20/36 bytes, the decode step itself does not throw. Execution then falls through into `separateIntoCleanDataAndChecksum`, hits the `else throw Error("bad length=...")` branch, and this exception is not caught anywhere in `isChashValid`. It propagates up through `isValidChash` → `isValidAddressAnyCase` (or any other `isValidChash` caller) into whatever unit/message validation flow called it.

### Impact Explanation
An uncaught exception thrown deep inside address/hash validation logic that is reachable from attacker-supplied unit content (any code path that validates an address or hash in "any case" mode, without pre-filtering via the strict `isValidAddress` regex) can propagate past the calling validation logic. Depending on how far up the call chain the exception is caught, this can crash the Node.js process performing unit validation for all nodes that process the malicious unit/message — a network-wide denial-of-service condition matching the "network unable to confirm new units" impact category, directly analogous to the DoS impact of CVE-2017-9204.

### Likelihood Explanation
Medium. Exploitability hinges on confirming (a) that `isValidChash`/`isValidAddressAnyCase` (or another caller that skips the alphabet regex) is actually invoked on unfiltered, attacker-controlled 32/48-character strings during unit/message validation, and (b) that the specific base32 library (`thirty-two`) and/or Node's base64 decoder actually produce a mis-sized buffer instead of throwing for out-of-alphabet input. I was not able to fully trace the single call site of `isValidAddressAnyCase` in `validation.js` within the available tool budget (only one match was found there), so the exact reachability from an unprivileged unit poster is not fully confirmed and should be verified against the actual validation flow before treating this as conclusively exploitable.

### Recommendation
Wrap the entire body of `isChashValid` (not just the decode call) in a single `try/catch`, and/or make `separateIntoCleanDataAndChecksum`/`mixChecksumIntoCleanData` return an error value instead of throwing, so any malformed-length input is turned into `false` rather than an uncaught exception. Additionally, audit every caller of `isValidChash`/`isValidAddressAnyCase` to confirm whether attacker-controlled strings reach it without prior alphabet filtering, and consider enforcing the same charset restriction used by `isValidAddress` before calling `isChashValid`.

### Proof of Concept
Conceptual (pending confirmation of the exact reachable call site):
1. Identify a validation path that calls `ValidationUtils.isValidAddressAnyCase(x)` or `isValidChash(x, 32/48)` directly on a unit-supplied string, without first checking `/^[A-Z2-7]{32}$/`.
2. Craft a 32-character (or 48-character) string containing characters outside the base32 (or base64) alphabet such that the underlying decoder silently drops/mis-decodes characters, yielding a buffer whose length isn't 20 (or 36) bytes.
3. Submit a unit/message containing this string in the field validated by that path.
4. Observe that `chash.isChashValid` throws `Error("bad length=...")` uncaught, propagating out of `isValidChash`, potentially crashing the validating node's process.

Because full confirmation of the exact vulnerable call site in `validation.js` requires deeper tracing than was possible in this session, I recommend a Devin session with codebase access to verify the call graph of `isValidAddressAnyCase`/`isValidChash` and the exact lenient-decode behavior of the `thirty-two` package before treating this as a confirmed, weaponizable DoS.

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
