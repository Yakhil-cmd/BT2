### Title
Unhandled exception in `isChashValid` on malformed c-hash length causes validation crash - (File: chash.js)

### Summary
`chash.js`'s `isChashValid()` decodes an attacker-supplied address/definition-chash string and assumes the decoded buffer always has the expected bit length (160 or 288 bits), but only wraps the *decode* call in a `try/catch`, not the subsequent length-dependent processing. This mirrors the CVE-2017-17782 root cause: a length value derived from untrusted input is used to index/allocate downstream structures without validating that the actual decoded data matches the expected size, causing an out-of-bounds condition (there, a heap over-read; here, an uncaught exception from a hard length assertion).

### Finding Description
`isChashValid(encoded)` enforces only the *string* length of the input (32 or 48 characters) before decoding: [1](#0-0) 

For the 48-character path it calls `Buffer.from(encoded, 'base64')`. Node's base64 decoder silently skips characters that are not valid base64 alphabet members (and stops early on premature `=` padding), so a 48-character string can decode to a buffer shorter than the expected 36 bytes (288 bits) without throwing. The `try/catch` only covers this decode call, not what follows.

The decoded buffer is then passed to `buffer2bin()` and `separateIntoCleanDataAndChecksum()`, the latter of which throws an uncaught `Error("bad length=...")` if the resulting bit-string length isn't exactly 160 or 288: [2](#0-1) [3](#0-2) 

This throw occurs *outside* the local `try/catch` block in `isChashValid`: [4](#0-3) 

`isChashValid` is invoked from address/definition-chash validation logic in `validation_utils.js`, which is reachable from ordinary unit validation whenever an address, definition hash, or similar chash-encoded field is checked (e.g., author/output addresses, definition chashes for multi-sig/AA addresses). Because it can be triggered by any field an unprivileged unit poster controls, a maliciously crafted 48-character chash string that decodes to a truncated buffer will cause the length-assertion `throw` to propagate up through the validation call chain instead of being reported as a normal “invalid address” error.

### Impact Explanation
If this exception is not caught by every caller in the validation pipeline (validation.js and downstream consumers of `isValidAddress`/definition-chash checks), it results in an unhandled exception that can crash the validating process for any unit referencing the crafted string, rather than cleanly rejecting the unit as invalid. This is a denial-of-service on unit/definition validation reachable from a single posted unit, which can cause nodes to disagree on validity/stability of the DAG or become unable to process new units containing the crafted field, matching the accepted impact categories (node disagreement on validity/stability, network unable to confirm new units).

### Likelihood Explanation
The trigger requires only crafting a 48-character c-hash string with a small number of invalid base64 characters or misplaced padding, something any unit poster, AA trigger author, or address/asset definition author can embed in a unit. No special privileges, race conditions, or additional gadgets are required beyond controlling the chash-encoded field value.

### Recommendation
In `isChashValid` (chash.js), verify `chash.length` immediately after decoding matches the expected byte length for the given `encoded_len` (20 bytes for 160-bit / 36 bytes for 288-bit) and return `false` if it does not, instead of relying on the deeper length assertion inside `separateIntoCleanDataAndChecksum`. Wrap the entire body of `isChashValid` (not just the decode call) in the existing `try/catch` so any unexpected length or format anomaly degrades to a clean “invalid” result rather than an uncaught exception.

### Proof of Concept
1. Construct a 48-character string intended for the 288-bit chash path where several characters are outside the base64 alphabet (e.g., replace a few characters with `!`, `@`, or insert a stray `=` mid-string) so that `Buffer.from(encoded, 'base64')` silently returns a buffer shorter than 36 bytes.
2. Embed this string in a field that is validated via the chash/definition-hash check reachable from ordinary unit posting (e.g., as an address or definition chash referenced by a unit's author/output/definition).
3. Submit the unit for validation; `isChashValid` decodes the string without error, then `buffer2bin`/`separateIntoCleanDataAndChecksum` computes a bit-length that is neither 160 nor 288 and throws `Error("bad length=...")` outside the local `try/catch`, propagating an unhandled exception through the validation call path instead of a normal validation failure.

Note: I was not able to fully trace every caller of `isChashValid`/`isValidAddress` in `validation_utils.js` and `validation.js` in the available context to confirm whether an outer `try/catch` in the broader validation pipeline ultimately intercepts this specific throw before it reaches process level. This should be verified against the full call chain before treating the DoS impact as fully confirmed.

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

**File:** chash.js (L96-105)
```javascript
function buffer2bin(buf){
	var bytes = [];
	for (var i=0; i<buf.length; i++){
		var bin = buf[i].toString(2);
		if (bin.length < 8) // pad with zeros
			bin = zeroString.substring(bin.length, 8) + bin;
		bytes.push(bin);
	}
	return bytes.join("");
}
```

**File:** chash.js (L152-170)
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
```
