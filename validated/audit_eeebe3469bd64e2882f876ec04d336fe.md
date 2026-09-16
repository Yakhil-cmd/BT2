### Title
Unhandled exception in `chash.isChashValid()` on malformed 288-bit (base64) chash input causes a crash during unit/address validation - (File: chash.js)

### Summary
`chash.isChashValid()` decodes an address's checksum-hash encoding and then feeds the decoded buffer into `separateIntoCleanDataAndChecksum()`, which asserts an exact bit-length (`160` or `288`) and `throw`s otherwise. The `try/catch` in `isChashValid()` only wraps the *decode* step, not the length-assertion step that follows, so a crafted 48-character value that base64-decodes leniently to a buffer whose bit-length is not exactly `288` produces an **uncaught exception** that propagates out of address validation. This mirrors the FreeRTOS-Plus-TCP DNS parser bug class: a length value derived from attacker-controlled encoded data is trusted to match an expected size without validation, and the mismatch is only discovered deep inside the parser, past the point where errors are safely handled.

### Finding Description
`isChashValid()` explicitly wraps only the decoding step in `try/catch`: [1](#0-0) 

The subsequent call, `separateIntoCleanDataAndChecksum(binChash)`, unconditionally throws when the bit-length of the decoded buffer is not `160` or `288`: [2](#0-1) 

For 32-character (base32) addresses, a full 32-character base32 string always decodes to exactly 20 bytes (160 bits), so this path is effectively safe. However, for 48-character values, `isChashValid()` uses `Buffer.from(encoded, 'base64')`: [3](#0-2) 

Node.js's base64 decoder is lenient: it silently skips characters that are not part of the base64 alphabet and stops decoding at the first `=` padding sequence, rather than throwing. This means a 48-character string that is not "clean" base64 (e.g. contains stray symbols, extra `=`, or is malformed in specific ways) can decode without throwing to a `Buffer` whose length is not the expected 36 bytes. `buffer2bin()` then produces a bit-string whose length is neither 160 nor 288, and `separateIntoCleanDataAndChecksum()` throws `Error("bad length=...")` **outside** the `try/catch` block in `isChashValid()`, propagating as an uncaught exception to whichever caller invoked address validation (`validation_utils.js`'s address-validity checks, which are used pervasively for unit inputs/outputs, author addresses, AA definitions/addresses, and asset issuer/definer addresses).

### Impact Explanation
Address strings of this exact 32/48-character shape are validated synchronously on essentially every path that touches a posted unit: author addresses, payment input/output addresses, AA/asset definitions, and address-definition authentifiers. If the throw is not caught somewhere further up the synchronous call stack (validation code in `validation.js`/`definition.js` largely relies on `ValidationUtils.isValidAddress`/`isChashValid` returning a boolean, not throwing), a single malicious unit or joint containing a specially crafted 48-character "address-like" string can trigger an uncaught exception during validation. In a Node.js process, an uncaught synchronous exception of this kind can crash the validating process, which for a hub or full node means the network's ability to receive/relay/confirm units through that node is disrupted — analogous to "network unable to confirm new units" from a single attacker-crafted input, mirroring the DoS-via-malformed-length-field character of CVE-2024-38373.

### Likelihood Explanation
Reachable directly from unprivileged input: any unit author, AA trigger author, or asset issuer can include an address-shaped string of length 48 in fields that undergo chash/address validation. No special privileges, peer/hub trust, or timing conditions are required — only crafting a string of the right length with base64-invalid characters positioned so that Node's lenient base64 decoder consumes a different number of bytes than 36.

### Recommendation
Wrap the entire body of `isChashValid()` (not just the decode calls) in `try/catch`, or add an explicit post-decode length check (`chash.length === 20` for 160-bit / `36` for 288-bit) that returns `false` instead of allowing `separateIntoCleanDataAndChecksum()`'s internal `throw` to escape uncaught. Additionally, validate the 48-character input against a strict/canonical base64 alphabet (rejecting stray characters) before calling `Buffer.from(..., 'base64')`, so malformed encodings are rejected early rather than silently truncated/misinterpreted.

### Proof of Concept
1. Construct a 48-character string `s` that is not valid canonical base64 (e.g. insert a non-base64 character such as `!` or extra `=` mid-string) but still satisfies `isStringOfLength(address, 48)`-style pre-checks used by address validators.
2. Call `chash.isChashValid(s)` directly, or embed `s` as an author/output/AA address in a unit/trigger and run it through unit validation.
3. `Buffer.from(s, 'base64')` decodes leniently to a buffer whose length is not 36 bytes.
4. `buffer2bin()` yields a bit string whose length is not `288`.
5. `separateIntoCleanDataAndChecksum()` throws `Error("bad length=...")` from a code path not covered by `isChashValid()`'s `try/catch`, propagating uncaught to the caller and, if unguarded up the stack, crashing the process handling that unit/joint.

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

**File:** chash.js (L152-163)
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
```
