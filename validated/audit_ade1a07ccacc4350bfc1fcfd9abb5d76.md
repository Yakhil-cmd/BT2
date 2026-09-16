## Analog Found

### Title
Uncaught exception in chash validation causes node crash on malformed 288-bit (48-char) chash input - (File: chash.js)

### Summary
CVE-2021-27478 describes a crafted-packet parser bug in OpENer's EtherNet/IP stack that throws an unhandled fault and crashes the device (DoS) because a decode routine doesn't validate its own output before it is consumed by downstream length-dependent logic. `ocore`'s chash-verification routine has the same structural flaw: `isChashValid()` in [1](#0-0)  wraps only the *decode* step in `try/catch`, but the subsequent length-dependent processing of the decoded bytes is left unprotected and can throw.

### Finding Description
`isChashValid(encoded)` accepts externally-supplied strings of length 32 (base32, chash160) or 48 (base64, chash288): [1](#0-0) 

For the 48-character case it calls `Buffer.from(encoded, 'base64')`. Unlike `base32.decode`, Node's base64 `Buffer.from` does **not** throw on malformed/invalid-alphabet input — it silently skips invalid characters and can return a buffer whose length differs from the expected 36 bytes (288 bits) depending on the crafted content of `encoded`. Because that decode step is the only thing guarded by the `try/catch`, a malformed-but-not-throwing base64 string escapes the catch block entirely.

Execution then continues to:
```
var binChash = buffer2bin(chash);
var separated = separateIntoCleanDataAndChecksum(binChash);
```
`separateIntoCleanDataAndChecksum()` explicitly throws when the bit length isn't exactly 160 or 288: [2](#0-1) 

This `throw` occurs **outside** the `try/catch` in `isChashValid`, so it propagates as an unhandled exception to whatever code called the chash-validation helpers (`isValidChash` → `isValidAddressAnyCase`/`isValidAddress` and related exports in `validation_utils.js`): [3](#0-2) 

If nothing further up the stack catches this synchronous throw, it becomes an uncaught exception in the Node.js process, crashing/terminating the node — precisely the "specifically crafted input causes a denial-of-service" pattern of CVE-2021-27478, but here triggered by a crafted string field instead of a crafted network packet.

### Impact Explanation
Chash/address validation is invoked throughout core validation paths reachable from unprivileged input: unit authors/addresses, payment outputs, AA definitions, and other address-bearing fields ultimately funnel through `isValidAddress`/`isValidChash`. An uncaught exception thrown mid-validation, rather than being converted into an `ifUnitError`/`ifJointError` callback, terminates the validating process — a full node-availability DoS, not merely rejection of one bad unit. This satisfies the "network unable to confirm new units" bar since a crashed hub/full node stops processing/relaying at all.

### Likelihood Explanation
The trigger requires only posting a unit/message containing a 48-character string in a field validated as a chash288-style value, where the string decodes via `Buffer.from(str,'base64')` to a byte length other than 36 bytes while still passing the earlier `isStringOfLength(str, 48)` gate. Because `Buffer.from` tolerates arbitrary junk characters in base64 without throwing, crafting such an input is straightforward for any unprivileged unit poster who can reach a code path calling `isValidChash(str, 48)`.

### Recommendation
Wrap the entirety of the post-decode processing in `isChashValid` (the `buffer2bin`, `separateIntoCleanDataAndChecksum`, and `bin2buffer` calls) in the same `try/catch` that currently only covers the decode step, and return `false` on any thrown error instead of letting it propagate. Additionally, validate the decoded buffer's byte length immediately after `Buffer.from(encoded, 'base64')` (must equal 36 for 48-char input) before doing any further bit-level processing.

### Proof of Concept
Conceptual (Node REPL) reproduction using the exported function:
```js
var chash = require('./chash.js');
// 48-char base64-ish string with characters that Buffer.from('base64') will
// silently drop, changing the decoded byte-length away from 36:
chash.isChashValid("AAAA????????????????????????????????????????AA");
// -> throws Error("bad length=...") instead of returning false,
//    escaping the try/catch in isChashValid and crashing the caller.
```
Exact byte sequences needed to make `Buffer.from(str,'base64')` yield a non-36-byte result while `str.length === 48` would need to be brute-forced/verified in a running Node instance (not available in this analysis environment), since Node's base64 decoder behavior for invalid characters is implementation-specific per Node version.

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
