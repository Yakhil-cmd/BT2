Line 354 confirms it directly: `validate()` calls `!arrAuthorAddresses.every(isValidAddress)` synchronously, with no surrounding try/catch, before the `mutex.lock` call in `validation.js`. If `isValidAddress` throws, the exception propagates uncaught out of `validate()`.

### Title
Uncaught exception / node crash via malformed address checksum decoding in `isChashValid` - (File: chash.js)

### Summary
`chash.isChashValid()` only wraps the *decoding* step in `try/catch`, but not the subsequent bit-manipulation steps that assume a fixed-length buffer. A crafted 48-character base64-like address string can decode to a buffer whose length is not exactly 36 bytes, causing an uncaught `Error` to propagate out of unit validation, analogous to the Info-Zip `zi_short` crash from an out-of-range field value in a header.

### Finding Description
`isChashValid` in [1](#0-0)  validates only the encoded-string length (32 or 48 chars) before decoding, then wraps only the `base32.decode`/`Buffer.from(encoded, 'base64')` call in `try/catch`:
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
`separateIntoCleanDataAndChecksum` ( [2](#0-1) ) throws `Error("bad length="+len...)` if the resulting bit-string length isn't exactly 160 or 288. Node's `Buffer.from(str, 'base64')` is lenient about non-alphabet characters and padding, so a 48-character string containing characters outside the strict base64 alphabet (but still 48 chars long) can decode to a buffer whose length is not exactly 36 bytes (288 bits). That mismatch throws inside `separateIntoCleanDataAndChecksum`, **outside** the `try/catch`, so the exception is not caught by `isChashValid`.

`isValidChash`/`isValidAddress` in [3](#0-2)  call `chash.isChashValid(str)` directly with no try/catch either. In `validation.js`, author addresses from an attacker-supplied unit are checked synchronously and unconditionally: [4](#0-3) 
This call happens before the `mutex.lock(...)` wrapper and before any of the async `async.series` steps that have structured error handling — there is no surrounding try/catch at this call site or in its caller `network.js:handleJoint` ( [5](#0-4) ). An uncaught synchronous exception thrown here is a standard Node.js fatal error that terminates the process.

`isValidAddress` (32-char check) itself cannot trigger this via the base32 path since valid-length base32-decoded output is fixed at 20 bytes, but the 288-bit/48-char path is reachable via `isValidChash(str, 48)`/`isValidAddressAnyCase`-style HASH_LENGTH=44 checks and other 48-length asset/definition-chash paths elsewhere in the codebase (e.g., asset IDs, definition c-hashes) that reuse `chash.isChashValid`.

### Impact Explanation
A successful trigger crashes the full node process handling the unit (denial of service), matching the CVE's "buffer overflow ... allows ... denial of service (crash)" class for a value in an untrusted header/field that isn't validated before use in downstream length-dependent logic. This can be sent by any unprivileged peer that posts a unit whose author address (or another chash-validated field) is a 48-character string engineered to decode via Node's lenient base64 decoder into a buffer whose bit-length isn't 288.

### Likelihood Explanation
Reaching this requires that `Buffer.from(str, 'base64')` actually produces a non-36-byte buffer for some 48-character input containing non-base64-alphabet characters, and that this occurs before the length check inside `separateIntoCleanDataAndChecksum` — both of which depend on Node's Buffer/base64 decoding lenience, which I could not fully verify from static code alone (I don't have a live Node.js environment to test the exact decode behavior for adversarial inputs). This should be verified with a runtime test of `Buffer.from(<crafted-48-char-string>, 'base64').length` to confirm a mismatch is achievable.

### Recommendation
Wrap the full body of `isChashValid` (from decode through checksum comparison) in try/catch and return `false` on any exception, rather than only guarding the decode call:
```js
function isChashValid(encoded){
    var encoded_len = encoded.length;
    if (encoded_len !== 32 && encoded_len !== 48)
        throw Error("wrong encoded length: "+encoded_len);
    try {
        var chash = (encoded_len === 32) ? base32.decode(encoded) : Buffer.from(encoded, 'base64');
        var binChash = buffer2bin(chash);
        var separated = separateIntoCleanDataAndChecksum(binChash);
        var clean_data = bin2buffer(separated.clean_data);
        var checksum = bin2buffer(separated.checksum);
        return checksum.equals(getChecksum(clean_data));
    }
    catch(e){
        console.log(e);
        return false;
    }
}
```
Additionally, validate that the decoded buffer length exactly matches the expected byte count (20 or 36 bytes) before proceeding, since `Buffer.from` silently truncates/pads on malformed base64 rather than throwing.

### Proof of Concept
1. Craft a unit with an author address (or other 48-char chash field) consisting of 48 characters where some characters are outside the base64 alphabet (e.g. containing `!`, `@`, or similar), keeping total string length at 48.
2. Submit the unit to a node via `handleJoint` (posted unit path).
3. `validation.js` line 354 calls `isValidAddress` → `isValidChash` → `chash.isChashValid`.
4. `Buffer.from(encoded, 'base64')` returns without throwing but produces a buffer whose length in bits is not 288.
5. `separateIntoCleanDataAndChecksum` throws `Error("bad length=...")` outside of any try/catch in the call chain, crashing the node process.

*Note: step 4's exact triggering input needs to be confirmed empirically against Node's `Buffer` base64 decoder, which I was unable to execute in this environment.*

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

**File:** validation.js (L354-355)
```javascript
	if (!arrAuthorAddresses.every(isValidAddress))
		return callbacks.ifUnitError("invalid author address");
```

**File:** network.js (L1149-1174)
```javascript
function handleJoint(ws, objJoint, bSaved, bPosted, callbacks){
	if ('aa' in objJoint)
		return callbacks.ifJointError("AA unit cannot be broadcast");
	var unit = objJoint.unit.unit;
	if (typeof unit !== 'string')
		return callbacks.ifJointError("invalid unit");
	const version = objJoint.unit.version;
	if (typeof version !== 'string')
		return callbacks.ifJointError("invalid version");
	const fVersion = parseFloat(version);
	if (!(fVersion >= constants.fVersion4 || objJoint.ball)) // covers NaN too
		return callbacks.ifTransientError("version is too old");
	if (assocUnitsInWork[unit])
		return callbacks.ifUnitInWork();
	assocUnitsInWork[unit] = true;
	
	var validate = function(){
		mutex.lock(['handleJoint'], function(unlock){
			if (ws && !conf.bLight)
				currentJointHost = ws.host;
			// clear host only if validation completed with any result, otherwise it crashed and we keep it for a while to avoid DoS from the same peer
			const clearHost = () => {
				if (ws && !conf.bLight)
					currentJointHost = null;
			};
			validation.validate(objJoint, {
```
