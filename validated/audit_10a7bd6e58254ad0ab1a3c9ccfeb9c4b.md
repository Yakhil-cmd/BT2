### Title
Uncaught exception in `isChashValid()` on malformed base64 c-hash crashes the validating node - (File: chash.js)

### Summary
`chash.js`'s `isChashValid()` only wraps the *decoding* step in `try/catch`, but not the subsequent length-dependent parsing (`separateIntoCleanDataAndChecksum`). Node's lenient base64 decoder (`Buffer.from(str, 'base64')`) can silently produce a buffer whose byte length does not match the expected 288-bit (36-byte) c-hash size when the input string contains invalid/extra characters, instead of throwing. That malformed-length buffer then reaches unguarded code that throws an uncaught `Error`, which is the same bug class as CVE-2015-8957 (crafted/malformed structured input reaching a parser that does not fully validate lengths before further processing, causing a crash instead of a graceful error).

### Finding Description
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
	var separated = separateIntoCleanDataAndChecksum(binChash);   // <-- NOT protected by the try/catch above
	...
}
``` [1](#0-0) 

`separateIntoCleanDataAndChecksum()` explicitly throws whenever the input length is anything other than exactly 160 or 288 bits:
```js
function separateIntoCleanDataAndChecksum(bin){
	var len = bin.length;
	var arrOffsets;
	if (len === 160) arrOffsets = arrOffsets160;
	else if (len === 288) arrOffsets = arrOffsets288;
	else throw Error("bad length="+len+", bin = "+bin);
	...
}
``` [2](#0-1) 

The length check that gates which decode branch is used only validates the *string* length (`encoded.length === 48`), not the *decoded byte length*. Node's `Buffer.from(str, 'base64')` is a lenient decoder: it silently skips characters that are not part of the base64 alphabet rather than throwing, so a 48-character string containing a few invalid characters can decode to a buffer shorter than 36 bytes. That shorter buffer flows straight into `buffer2bin()` and then into `separateIntoCleanDataAndChecksum()`, which throws because the resulting bit-length is neither 160 nor 288 — and this throw is outside the `try/catch` that only covers the decode call.

This mirrors the CVE's bug class: a length/structure assumption made about attacker-controlled encoded data is not actually enforced before the data is passed into strict downstream parsing logic, and the failure mode is an unhandled crash rather than a validation error.

### Impact Explanation
`isChashValid` (and `getChash288`/`getChash160`, which share the vulnerable `separateIntoCleanDataAndChecksum`/`bin2buffer` machinery) is exercised anywhere the codebase needs to sanity-check a c-hash-style identifier before treating it as a valid address/definition hash (referenced from `validation_utils.js`). Any code path that calls this validator on attacker-supplied strings without its own surrounding `try/catch` will throw an uncaught exception. In a Node.js process, an uncaught exception in a synchronous call stack typically terminates the process unless a global handler is installed. If this is reachable during unit or AA-trigger validation, a single crafted unit/trigger posted by an unprivileged user could crash validating full nodes, preventing the network from processing and confirming new units — a network-availability impact analogous to the "denial of service (application crash)" impact of the original CVE.

### Likelihood Explanation
Likelihood is Medium: the defect itself (unguarded throw reachable via a decoder quirk) is concretely demonstrable in the code shown above, but I was not able to fully trace, within the available tool budget, every external call path that supplies attacker-controlled 48-character strings into `isChashValid` without an enclosing `try/catch` elsewhere in the validation pipeline (only the reference from `validation_utils.js` and `chash.js`'s own two internal call sites were confirmed). Confirming or ruling out an unguarded external caller (e.g., in address/definition validation invoked directly from `validation.js`/`definition.js` on unit data) needs further verification with full repository access.

### Recommendation
- Move the call to `separateIntoCleanDataAndChecksum()` (and any other post-decode processing) inside the same `try/catch` block that guards the decode step in `isChashValid()`, returning `false` on any thrown error instead of propagating it.
- Additionally validate that the decoded buffer's byte length exactly matches the expected size (20 bytes for 160-bit, 36 bytes for 288-bit) before calling `buffer2bin`/`separateIntoCleanDataAndChecksum`, rather than relying solely on the pre-decode string length.
- Audit all callers of `isChashValid`/`getChash160`/`getChash288` to ensure none of them can propagate an uncaught exception from attacker-controlled input into the unit/AA validation pipeline.

### Proof of Concept
```js
const chash = require('./chash.js');
// 48-char string of the right length but containing bytes that Node's
// base64 decoder silently drops, yielding a decoded buffer shorter than 36 bytes.
const malformed = "!!!!" + "A".repeat(44); // 48 chars, "!!!!" is invalid base64 and gets skipped by Buffer.from
try {
    chash.isChashValid(malformed); // wraps only the decode step; separateIntoCleanDataAndChecksum() throws uncaught
} catch (e) {
    console.log("uncaught exception escapes isChashValid:", e.message);
}
``` [3](#0-2)

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
