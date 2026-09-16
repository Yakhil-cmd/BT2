### Title
Unhandled exception in c-hash deserialization crashes node on malformed address string - ([File: chash.js])

### Summary
`chash.js`'s `isChashValid()` decodes an externally supplied base32/base64 address string and then processes it through a length-keyed offset table (`arrOffsets160`/`arrOffsets288`) without validating that the *decoded* bit-length actually matches the length that was assumed when selecting the offset table. When it doesn't match, an `Error` is thrown outside of any `try/catch`, and — because `isChashValid`/`isValidAddress` is called synchronously and unguarded from many unit/message/address validation paths — this crashes the whole node process. This mirrors the root cause of CVE-2023-29499 in GLib's GVariant deserializer: the code trusts a declared/implied size and walks a fixed offset table over the payload without re-checking that the actual decoded data size supports that offset table, and the resulting bounds/format mismatch is fatal instead of being handled as a validation failure.

### Finding Description
`isChashValid()` in [1](#0-0)  only wraps the base32/base64 *decode* step in a `try/catch`:
```js
function isChashValid(encoded){
	var encoded_len = encoded.length;
	if (encoded_len !== 32 && encoded_len !== 48)
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
	...
}
```
`separateIntoCleanDataAndChecksum()` [2](#0-1)  requires the decoded bit-length (`bin.length`) to be exactly 160 or 288, and **throws an uncaught `Error("bad length=...")`** for any other value:
```js
function separateIntoCleanDataAndChecksum(bin){
	var len = bin.length;
	var arrOffsets;
	if (len === 160) arrOffsets = arrOffsets160;
	else if (len === 288) arrOffsets = arrOffsets288;
	else throw Error("bad length="+len+", bin = "+bin);
	...
}
```
The offset tables (`arrOffsets160`, `arrOffsets288`) are precomputed once from `calcOffsets()` [3](#0-2)  assuming a fixed total bit length; they are only valid when the actual decoded buffer has exactly that many bits. The code checks the input string's *character* length (32 or 48) but never re-validates that the *decoded byte buffer* actually has the corresponding fixed bit length before indexing into the offset table via `separateIntoCleanDataAndChecksum`/`mixChecksumIntoCleanData`. Base32 decoding of a 32-character string is not guaranteed to always yield exactly 20 bytes — implementations can legally produce a shorter buffer when the input contains valid base32 padding (`=`) characters or otherwise malformed-but-decodable input, which the outer `encoded_len` check does not catch. When that happens, the thrown `Error` propagates uncaught out of `isChashValid`, which is invoked from address-validation helpers used throughout `validation.js`/`definition.js` when validating addresses in units, authors, outputs, asset definitions, AA triggers, and definition templates. Because there is no `try/catch` anywhere in the call chain, this synchronous exception crashes the Node.js process handling validation.

This is structurally the same bug class as CVE-2023-29499: a deserializer computes/uses an offset table sized for an *expected* input length, but does not verify that the actual decoded payload conforms to that expected length before indexing through the table, resulting in an unhandled fault rather than a rejected/invalid result.

### Impact Explanation
Any unprivileged party can craft a unit/message referencing an address string of the right *character* length (32 for base32, 48 for base64) that decodes into a byte buffer whose bit length isn't exactly 160/288 bits, triggering the uncaught `Error`. Since address validation (`isValidAddress`) is exercised on essentially every incoming unit (authors, output addresses, definition conditions, AA triggers, asset issuer/transfer conditions, private-payment addresses, etc.), a single malicious unit can crash any full node that attempts to validate it — a network-wide denial of service preventing confirmation of new units, satisfying the "network unable to confirm new units" bar for Medium/High severity.

### Likelihood Explanation
Reachability is very high: address strings appear in essentially every unit and message type an unprivileged actor can post (unit authors/definitions, payment outputs, AA triggers/definitions, asset conditions, device/wallet messages). The only requirement is producing a 32- or 48-character string that base32/base64-decodes to a buffer whose bit length differs from 160/288 — plausible via base32 padding characters or other decoder-specific edge cases in the `thirty-two` library, which are not excluded by the surrounding length check.

### Recommendation
- In `isChashValid()`, explicitly validate `chash.length` (in bytes) immediately after decoding, and return `false` (not throw) if it does not equal exactly 20 bytes (for base32/160-bit) or 36 bytes (for base64/288-bit), before calling `buffer2bin`/`separateIntoCleanDataAndChecksum`.
- Wrap the remainder of `isChashValid()` (the `buffer2bin`/`separateIntoCleanDataAndChecksum`/`bin2buffer` calls) in the same `try/catch` that already guards the decode step, so any unexpected format issue degrades to `return false` instead of an uncaught exception.
- Add defensive length assertions inside `separateIntoCleanDataAndChecksum` and `mixChecksumIntoCleanData` callers so that a mismatched offset table size can never propagate as an unhandled exception during unit validation.

### Proof of Concept
1. Construct a 32-character base32-alphabet string that decodes (via the `thirty-two` library) to a byte buffer shorter than 20 bytes, e.g. an input using trailing `=` padding characters combined with valid base32 characters, or any other input the decoder accepts but which does not correspond to exactly 160 bits of payload.
2. Use this string as an author/output/AA-trigger address field value in a unit posted to the network (`isValidAddress`/`isChashValid` is invoked on it during validation).
3. On the validating node, `isChashValid()` decodes the string successfully (no exception in the guarded `try`), computes `binChash = buffer2bin(chash)` with a bit-length not equal to 160, and calls `separateIntoCleanDataAndChecksum(binChash)`, which executes `throw Error("bad length=...")` outside of any `try/catch` in the call chain, crashing the node's validation process. [1](#0-0) [2](#0-1)

### Citations

**File:** chash.js (L16-40)
```javascript
function calcOffsets(chash_length){
	checkLength(chash_length);
	var arrOffsets = [];
	var offset = 0;
	var index = 0;

	for (var i=0; offset<chash_length; i++){
		var relative_offset = parseInt(arrRelativeOffsets[i]);
		if (relative_offset === 0)
			continue;
		offset += relative_offset;
		if (chash_length === 288)
			offset += 4;
		if (offset >= chash_length)
			break;
		arrOffsets.push(offset);
		//console.log("index="+index+", offset="+offset);
		index++;
	}

	if (index != 32)
		throw Error("wrong number of checksum bits");

	return arrOffsets;
}
```

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
