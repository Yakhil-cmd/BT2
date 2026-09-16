## Analog Analysis: Uncaught length-mismatch exception in `chash.js` c-hash/address validation

### Title
Unhandled exception on malformed address/c-hash causes node crash during unit validation - (File: `chash.js`)

### Summary
CVE-2020-21827 is a heap buffer overflow in LibreDWG's `read_2004_compressed_section` caused by insufficient bounds/length validation while decoding attacker-controlled compressed binary data, allowing out-of-bounds memory access from external input. The closest reachable analog in `ocore--008` is in the c-hash decode/validation path (`chash.js`), where an attacker-controlled, externally supplied string (e.g. an `address` field inside a posted unit's authors/definitions or any oscript value checked via `isValidAddress`) is decoded and its resulting byte length is *assumed* rather than strictly validated, leading to an uncaught `Error` thrown deep in the decode pipeline instead of a graceful `false` return.

### Finding Description
`isChashValid()` first checks the string length of the *encoded* form (32 or 48 chars) [1](#0-0) , then decodes it with `base32.decode()` or `Buffer.from(..., 'base64')` inside a `try/catch` that only guards the decode call itself [2](#0-1) . Immediately after, the decoded buffer is converted to a bit string via `buffer2bin()` and passed to `separateIntoCleanDataAndChecksum()`, which throws an uncaught `Error("bad length=...")` if the resulting bit length is not exactly 160 or 288 [3](#0-2) [4](#0-3) .

The problem is that a fixed *encoded string length* (32 base32 chars / 48 base64 chars) does not guarantee a fixed *decoded byte length* for arbitrary attacker-supplied input, since base32/base64 alphabets and padding are permissive. A crafted 32-character or 48-character string can decode to a buffer whose bit-length is not 160/288, triggering the `throw` on line 53, which is entirely outside the `try/catch` block in `isChashValid` (lines 156-162 only wrap the decode call, not the subsequent processing). This mirrors the CVE's root cause: a length assumption made about decoded/decompressed attacker-supplied data is not actually enforced before further processing, producing an out-of-bounds condition (buffer overflow in C; unhandled exception/crash in JS, since Node.js `Buffer` operations are bounds-checked at the VM level and fail fast with a thrown exception instead of silent memory corruption).

`isValidChash()` / `isValidAddressAnyCase()` / `isValidAddress()` call `chash.isChashValid()` directly without any additional exception handling [5](#0-4) , and these validators are used pervasively throughout `validation.js` (address definitions, authors, payment addresses, AA definitions, data feed attestor addresses, etc. — 11 call sites) to validate untrusted fields inside a posted unit. If any of those call sites is not itself wrapped by a surrounding `try/catch` (e.g., invoked synchronously outside of the joint-validation `try` scaffolding, or invoked from a code path added later that assumes a boolean return), the thrown error is unhandled and will propagate up the call stack.

### Impact Explanation
An uncaught exception thrown while validating a single incoming unit/joint can crash the Node.js process (default behavior for uncaught exceptions unless wrapped by a process-level handler that simply logs and continues). If this occurs on hub/full nodes processing gossip/incoming joints, this results in denial of service against consensus-critical infrastructure — the network becomes unable to validate/confirm new units while affected nodes are down or repeatedly crashing, satisfying the "network unable to confirm new units" impact bucket. Because the trigger data (a malformed address string) can be embedded in ordinary unit fields (author address, definition, payment address, AA trigger data, attestor list, etc.), it is reachable by any unprivileged unit poster.

### Likelihood Explanation
Exploitation requires crafting a base32/base64 string of the exact required character length (32 or 48) that nonetheless decodes to a byte count whose bit-length is not 160 or 288. This is plausible because base32 alphabets tolerate certain non-canonical encodings and base64 length does not uniquely determine decoded byte count when padding is manipulated (e.g. `=` characters count toward the 48-char total but reduce actual decoded bytes). Constructing such an input is a lightweight, offline exercise requiring no network access or privileged position — only the ability to place the crafted string into a unit field that flows into `isValidAddress`/`isChashValid`.

### Recommendation
- Wrap the entire body of `isChashValid()` (not just the decode call) in a single `try/catch` that returns `false` on any error, matching the function's documented contract of returning a boolean.
- After decoding, explicitly assert `chash.length === 20` (160 bits) or `chash.length === 36` (288 bits) before calling `buffer2bin`/`separateIntoCleanDataAndChecksum`, and return `false` immediately if the assertion fails, rather than relying on later functions to throw.
- Audit all call sites of `isValidAddress`, `isValidAddressAnyCase`, and `isValidChash` in `validation.js` and elsewhere to confirm each is inside a `try/catch` or otherwise cannot allow an exception to escape unit-validation flow and crash the process.

### Proof of Concept
Conceptual (not executed against the live repo, since no code execution is available in this session):
1. Construct a 32-character base32 string that base32-decodes to a byte buffer whose length is not 20 bytes — for example, a string using padding/casing that the `thirty-two` library decodes leniently to 19 or 21 bytes rather than the expected 20.
2. Place this string as the `address` value of an author or payment output in an otherwise well-formed unit, or as an oscript/AA trigger `address` field.
3. Post the unit / send the trigger; when `validation_utils.isValidAddress()` → `chash.isChashValid()` is invoked, `separateIntoCleanDataAndChecksum()` throws `Error("bad length=...")` outside of any enclosing `try/catch` at that call site, propagating as an uncaught exception.
4. If the invoking code path lacks a `try/catch` (needs to be confirmed per call site in `validation.js`), the node process crashes, disrupting unit validation for that node.

Note: I was not able to fully verify, within the available search budget, whether every one of the 11 call sites of `isValidAddress` in `validation.js` is guarded by a try/catch that would absorb this exception before it becomes a process-crashing unhandled exception — this would need to be confirmed by tracing each call site (e.g., inside `validateAuthors`, `validateInputsAndOutputs`, `validateDefinition`) to determine the actual reachable severity.

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

**File:** chash.js (L152-155)
```javascript
function isChashValid(encoded){
	var encoded_len = encoded.length;
	if (encoded_len !== 32 && encoded_len !== 48) // 160/5 = 32, 288/6 = 48
		throw Error("wrong encoded length: "+encoded_len);
```

**File:** chash.js (L156-162)
```javascript
	try{
		var chash = (encoded_len === 32) ? base32.decode(encoded) : Buffer.from(encoded, 'base64');
	}
	catch(e){
		console.log(e);
		return false;
	}
```

**File:** chash.js (L163-164)
```javascript
	var binChash = buffer2bin(chash);
	var separated = separateIntoCleanDataAndChecksum(binChash);
```

**File:** validation_utils.js (L52-58)
```javascript
function isValidChash(str, len){
	return (isStringOfLength(str, len) && chash.isChashValid(str));
}

function isValidAddressAnyCase(address){
	return isValidChash(address, 32);
}
```
