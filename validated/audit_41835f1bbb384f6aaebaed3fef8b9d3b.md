Based on my research, I found a valid analog in the codebase.

### Title
Uncaught Exception (Node.js Crash) via Malformed C-Hash Input in `isChashValid` — reachable through `isValidAddressAnyCase` — ([File: chash.js])

### Summary
The Sequoia bug class is: a length-derived subtraction/indexing operation that assumes a fixed decoded-input size, and panics (crashes the process) when that assumption is violated by attacker-supplied, too-short/malformed data. `ocore`'s c-hash validator has the same root-cause shape: `isChashValid()` decodes an attacker-controlled string and then unconditionally assumes the decoded buffer has an exact bit-length (160 or 288), throwing an *uncaught* `Error` when that assumption fails.

### Finding Description
`chash.isChashValid()` [1](#0-0)  decodes the `encoded` string with `base32.decode()` or `Buffer.from(encoded,'base64')` inside a `try/catch` that only guards the decode step:
```
try{
    var chash = (encoded_len === 32) ? base32.decode(encoded) : Buffer.from(encoded, 'base64');
}
catch(e){ return false; }
var binChash = buffer2bin(chash);
var separated = separateIntoCleanDataAndChecksum(binChash);
``` [2](#0-1) 

`separateIntoCleanDataAndChecksum()` then requires the decoded bit-length to be *exactly* 160 or 288, otherwise it `throw`s outside of any try/catch:
```
function separateIntoCleanDataAndChecksum(bin){
	var len = bin.length;
	...
	else
		throw Error("bad length="+len+", bin = "+bin);
``` [3](#0-2) 

Both `base32.decode` (thirty-two library) and `Buffer.from(str,'base64')` are lenient decoders: neither is guaranteed to throw on malformed/short/irregularly-padded input — they can silently produce a buffer whose length does not correspond to a "clean" 20-byte or 36-byte payload, especially when characters outside the expected alphabet are present. The function `isValidAddress()` mitigates this specific risk with a strict regex pre-check (`/^[A-Z2-7]{32}$/`) before ever reaching `isChashValid` [4](#0-3) , but `isValidAddressAnyCase()` calls `isValidChash(address, 32)` — and thus `isChashValid` — **directly, with no charset/regex filter**:
```
function isValidAddressAnyCase(address){
	return isValidChash(address, 32);
}
``` [5](#0-4) 

This is the exact bug-class match to the report: an internal parsing routine assumes fixed decoded-length input and unconditionally subtracts/indexes based on that assumption, throwing/panicking instead of gracefully rejecting malformed attacker input when validation upstream is incomplete.

### Impact Explanation
An uncaught `Error` thrown deep inside address validation, if not caught by a surrounding handler, propagates as an unhandled exception. In a Node.js process this can crash the entire `ocore` node process (denial of service), matching the CVSS "A:H" impact of the source advisory (availability impact via crash). A node crash on a full node halts processing/relay of new units for that node, directly impacting the "network unable to confirm new units" acceptance criterion if reachable on a widely-used code path.

### Likelihood Explanation
Reachability depends on finding a call site that reaches `isValidAddressAnyCase` (or another `isValidChash`/`isChashValid` call lacking upstream charset filtering) with attacker-supplied address/asset-like strings from a posted unit, AA trigger, or private-payment message. This is a real code smell (missing input hardening compared to the more careful `isValidAddress`), but I was not able to fully enumerate every call site of `isValidAddressAnyCase` and confirm end-to-end reachability from a single unprivileged unit/trigger without deeper tracing that ran out of iterations — this is a plausible but not fully proven analog given available search results.

### Recommendation
Harden `isChashValid()` by wrapping the entire post-decode logic (`buffer2bin` + `separateIntoCleanDataAndChecksum` + `mixChecksumIntoCleanData` calls) in a single `try/catch` that returns `false` on any thrown error, rather than only guarding the decode call. Additionally, apply the same strict base32/base64 charset regex used in `isValidAddress()` to any other consumer of `isValidChash`, including `isValidAddressAnyCase()`, before decoding.

### Proof of Concept
Not fully constructible without further tracing of which validated network/unit fields route through `isValidAddressAnyCase` — I could not confirm within the available tool budget that this path is reachable from a single posted unit/trigger/private-payment/device message without an intervening full node code change; flagging this uncertainty explicitly rather than asserting an unverified PoC.

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
