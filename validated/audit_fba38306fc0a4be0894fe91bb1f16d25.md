## Analog Found

### Title
Denial of Service via uncaught exception in 288-bit c-hash validation caused by silent truncation of malformed base64 input - ([File: chash.js])

### Summary
The CVE describes a buffer-overflow/crash in FreeImage's `processMakerNote()`, which trusts an internally-derived length field while decoding untrusted metadata and reads/writes past the real buffer bounds, crashing the process. The ocore analog is in `isChashValid()` in `chash.js`: it decodes an attacker-supplied 48-character string with `Buffer.from(encoded, 'base64')`, but Node's base64 decoder silently drops invalid characters instead of throwing, so the resulting buffer can be shorter than the 36 bytes (288 bits) the rest of the function assumes. That length assumption is never re-checked, so the same class of "unvalidated length used for buffer processing" bug from the CVE is present here, and it results in an uncaught `Error` being thrown deep inside address/definition-hash validation.

### Finding Description
`isChashValid()` only wraps the *decode* step in a `try/catch`: [1](#0-0) 

For the 288-bit (48-character) branch, it calls `Buffer.from(encoded, 'base64')`. Node.js's base64 decoder does not validate/reject unrecognized characters — it simply skips them — so a 48-character string containing invalid base64 characters decodes to a buffer with fewer than 36 bytes, with no error raised at this call site.

The function then proceeds unconditionally to: [2](#0-1) 

`buffer2bin(chash)` produces a bit string whose length is `chash.length*8`, which will not be 288 if the decoded buffer is short. That bit string is passed into `separateIntoCleanDataAndChecksum()`: [3](#0-2) 

which explicitly `throw`s an `Error` for any length other than 160 or 288. This throw happens **outside** the `try/catch` in `isChashValid()` (that catch only covers the decode line), so the exception propagates uncaught out of `isChashValid()`.

This is functionally the same root-cause pattern as the CVE: a length value is derived from untrusted data during a decode/parse step, and the routine keeps operating on that value without re-validating it against the buffer that was actually produced, eventually causing an out-of-bounds/invalid-length operation that a well-formed input would never trigger.

`isChashValid` is the low-level primitive behind `isValidAddress`/288-bit chash checks (`validation_utils.js`), which are invoked while validating **every unit an unprivileged user can post**: author addresses, output/definition-chash addresses (including 288-bit chashes used for shared/multisig address definitions), and AA/definition validation paths in `definition.js` and `aa_validation.js`.

### Impact Explanation
If the uncaught exception is not intercepted by a `try/catch` at every call site along the validation chain (unit/joint validation, definition validation, AA definition validation), it becomes an unhandled exception in the middle of processing a unit supplied by any peer/wallet user. In a Node.js process this can crash the node (or the specific worker handling the unit), which — if triggered broadly — can prevent the network from confirming new units or cause inconsistent behavior between nodes that happen to catch the exception at different call depths versus nodes that do not, directly mapping to the "network unable to confirm new units" / "node disagreement" impact categories.

### Likelihood Explanation
The trigger requires only crafting a 48-character string containing byte(s) outside the base64 alphabet and placing it wherever a 288-bit address/chash is validated (e.g., as an author address, an inner address reference in a definition, or a shared-address chash) inside an otherwise well-formed unit — something any unprivileged unit poster can construct and broadcast. No special privileges, node compromise, or peer trust relationship is required.

### Recommendation
- In `isChashValid()` (chash.js), validate the decoded buffer length immediately after decoding (`chash.length !== chash_length/8`) and return `false` rather than letting `separateIntoCleanDataAndChecksum()` throw.
- Wrap the full body of `isChashValid()` (not just the decode call) in `try/catch`, returning `false` on any exception, consistent with how the function is documented/used as a boolean validity check.
- Audit all call sites of `isValidAddress`/`isChashValid` in `validation_utils.js`, `validation.js`, `definition.js`, and `aa_validation.js` to confirm they don't assume this function can never throw.

### Proof of Concept
```js
var chash = require('./chash.js');
// 48 chars, but with an invalid base64 character '!' so Buffer.from(..., 'base64')
// silently decodes to fewer than 36 bytes instead of throwing.
var malformed_288bit_chash = '!'.repeat(48);
chash.isChashValid(malformed_288bit_chash);
// -> throws "bad length=..." from separateIntoCleanDataAndChecksum,
//    uncaught because it's outside isChashValid's try/catch.
```
Embedding `malformed_288bit_chash` as an address/definition-chash field inside a unit's `authors`/`definition`/output structure and submitting it for validation reaches this same code path.

**Note on uncertainty:** I could not fully trace every call site of `isValidAddress`/`isChashValid` to confirm whether an outer `try/catch` in `validation.js`/`network.js` intercepts this specific throw before it reaches an uncaught-exception handler (which would downgrade the crash to a handled validation error). This should be verified in a live session, since the ocore codebase index used here does not always expose complete call-chain context for every function. [4](#0-3)

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

**File:** chash.js (L152-164)
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
```

**File:** validation_utils.js (L64-66)
```javascript
function isValidDeviceAddress(address){
	return ( isStringOfLength(address, 33) && address[0] === '0' && isValidAddress(address.substr(1)) );
}
```
