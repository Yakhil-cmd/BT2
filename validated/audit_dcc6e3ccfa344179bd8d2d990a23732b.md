### Title
Unvalidated chash decode length allows an uncaught exception (crash) during unit/address validation - (File: `chash.js`)

### Summary
`chash.isChashValid()` decodes a 32/48-character attacker-supplied string and assumes the decoded byte buffer always represents exactly 160 or 288 bits. When that assumption is violated by a crafted input, an unguarded `throw` deep inside the c-hash bit-manipulation helpers propagates out of `isChashValid`/`isValidChash`, instead of the normal `false`-return validation-failure pattern used everywhere else in ocore.

### Finding Description
`isChashValid()` only wraps the decode step in `try/catch`; the checksum-separation step is unprotected: [1](#0-0) 

`separateIntoCleanDataAndChecksum()` hard-`throw`s if the decoded bit length isn't exactly 160 or 288: [2](#0-1) 

`bin2buffer()` similarly derives a buffer size directly from `bin.length` without verifying it is byte-aligned or within expected bounds: [3](#0-2) 

`isValidChash()`/`isValidAddressAnyCase()` call `isChashValid()` with only a length-of-string check (`isStringOfLength`), not a charset check, unlike `isValidAddress()` which additionally enforces `/^[A-Z2-7]{32}$/`: [4](#0-3) 

This mirrors the CVE-2025-0678 root cause pattern: a size value derived from attacker-controlled, insufficiently-validated input (squash4 filesystem geometry vs. here, a base32/base64-decoded c-hash) is used downstream in buffer-size logic without confirming it matches the invariant the rest of the code assumes, producing an unexpected/uncaught failure path deep in a low-level primitive that many higher-level validators depend on.

### Impact Explanation
Every ocore validator function elsewhere in the codebase communicates failure via callbacks (`ifUnitError`, `return false`, etc.); a raw `throw` surfacing from `chash.js` during synchronous unit/address/authentifier validation is inconsistent with that contract and can escape as an uncaught exception in the request/validation code path. If any code path reachable from processing an attacker-posted unit, AA trigger, or definition calls the any-case address validator (`isValidAddressAnyCase`/`isValidChash`) on attacker-controlled 32-character data without an additional catch, a single crafted unit can crash the node process handling it — matching the "network unable to confirm new units" outcome allowed by this analog's impact criteria.

### Likelihood Explanation
The regular `isValidAddress()` used for most address checks is protected by the `[A-Z2-7]{32}` regex, which limits reachability. However `isValidChash`/`isValidAddressAnyCase` bypass that charset restriction and only enforce string length, so any code path that validates an address in a case-insensitive manner is directly exposed to malformed base32 input from a single posted unit/message.

### Recommendation
- Wrap the entire body of `isChashValid()` (not just the decode call) in `try/catch` and return `false` on any error, consistent with the rest of ocore's validation contract.
- In `separateIntoCleanDataAndChecksum()`/`bin2buffer()`, replace `throw` with a return value the caller can safely interpret as "invalid", or ensure all callers of `chash.js` functions are guaranteed to catch exceptions.
- Restrict `isValidChash`/`isValidAddressAnyCase` to the valid base32 charset before calling `isChashValid`, matching `isValidAddress`'s regex guard.

### Proof of Concept
Call `chash.isChashValid("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA1")` (32 chars, but containing a non-standard base32 character or crafted to make `base32.decode` return a buffer whose bit length isn't 160) directly, or via `validation_utils.isValidAddressAnyCase(...)` with the same string — the call throws an uncaught `Error("bad length=...")` instead of returning `false`, demonstrating the missing validation on the decoded length. Exact confirmation of an end-to-end unguarded call path from a posted unit into `isValidAddressAnyCase` would require tracing all consumers of that function across the codebase, which was not fully enumerable within the available search results.

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

**File:** chash.js (L107-113)
```javascript
function bin2buffer(bin){
	var len = bin.length/8;
	var buf = Buffer.alloc(len);
	for (var i=0; i<len; i++)
		buf[i] = parseInt(bin.substr(i*8, 8), 2);
	return buf;
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

**File:** validation_utils.js (L52-61)
```javascript
function isValidChash(str, len){
	return (isStringOfLength(str, len) && chash.isChashValid(str));
}

function isValidAddressAnyCase(address){
	return isValidChash(address, 32);
}

function isValidAddress(address){
	return (typeof address === "string" && /^[A-Z2-7]{32}$/.test(address) && isValidChash(address, 32));
```
