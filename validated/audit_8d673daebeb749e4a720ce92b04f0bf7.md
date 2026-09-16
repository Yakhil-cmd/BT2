### Title
Uncaught exception / crash in c-hash validation via malformed base32 address string bypassing character-set check in `isValidAddressAnyCase` - (File: chash.js)

### Summary
`chash.isChashValid()` decodes an attacker-supplied string with `base32.decode()` (for 32-character c-hashes) and then unconditionally feeds the resulting buffer into `buffer2bin()` and `separateIntoCleanDataAndChecksum()`, which `throw` a hard `Error` if the decoded bit-length is not exactly 160 or 288 bits. Only `base32.decode()` itself is wrapped in `try/catch`; the subsequent length assertions are not. `ValidationUtils.isValidAddress()` mitigates this by first requiring the string to match `/^[A-Z2-7]{32}$/` (valid base32 alphabet, correct length) before calling `isChashValid`, but `ValidationUtils.isValidAddressAnyCase()` calls `isValidChash()`/`isChashValid()` directly, checking only string length (`isStringOfLength(str,32)`) with **no character-set validation**.

### Finding Description
- `isValidAddressAnyCase(address)` → `isValidChash(address, 32)` → `chash.isChashValid(address)`. [1](#0-0) 
- Inside `isChashValid`, decoding is guarded by try/catch, but the length checks that follow (in `separateIntoCleanDataAndChecksum`) are not: [2](#0-1) [3](#0-2) 
- Because `isValidAddressAnyCase` skips the `/^[A-Z2-7]{32}$/` regex that `isValidAddress` enforces, a 32-character string containing bytes/characters outside the base32 alphabet (e.g. lowercase letters, digits 0/1/8/9, punctuation) can be passed straight to `base32.decode()`. Depending on how the `thirty-two` library’s decoder handles out-of-alphabet input (it does not always throw — it can silently produce a decoded buffer whose bit length differs from the expected 160 due to partial/garbage decoding of malformed groups), the resulting buffer can end up NOT satisfying `len === 160` in `separateIntoCleanDataAndChecksum`, causing an uncaught `Error("bad length=...")` to propagate out of `isChashValid` with no catch anywhere in the call chain.
- This exactly mirrors the CVE-2024-0901 bug class: a “packet” (here, an address/c-hash string) that has the *correct declared length* (32 chars) but malformed internal structure causes an out-of-band assumption violation deep in a length-based parser, resulting in an unhandled crash rather than a graceful validation failure.

### Impact Explanation
An uncaught synchronous exception thrown from deep inside validation code (not wrapped by the calling validation logic, since `isValidAddressAnyCase` is meant to be a boolean predicate, not a throwing function) will propagate up the call stack. If not caught by a higher-level try/catch or a Node `uncaughtException` handler, this crashes the ocore process, taking a node offline — a network-availability impact when triggered broadly (nodes unable to confirm units because the process serving validation dies), fitting the "node disagreement/crash" impact class permitted by scope. Even if caught somewhere and merely logged, it represents a code-path where an assumed invariant ("valid base32 always decodes to correctly-sized checksum bits") is violated by attacker-controlled non-alphabet input reaching a `throw`.

### Likelihood Explanation
`isValidAddressAnyCase` is exposed to attacker-controlled data anywhere a case-insensitive address check is used (it exists specifically to accept mixed-case addresses before normalization) — reachable from unit posting, AA trigger, and asset/definition validation flows that accept addresses. Since `isValidAddress` (with the stricter regex) is used in most core definition-condition validation paths, the primary risk is concentrated in whatever code paths intentionally call `isValidAddressAnyCase` for lenient/case-insensitive address checks (e.g., wallet/UI address entry validation) that could also be reachable via unit/trigger data depending on integration. I could not fully confirm every call site of `isValidAddressAnyCase` beyond its two references in `validation_utils.js` and one in `validation.js`, nor could I verify precisely how the `thirty-two` npm package handles out-of-alphabet characters (whether it throws or returns a mis-sized buffer) without the library source in the index, so likelihood is assessed as **moderate**, contingent on that library behavior.

### Recommendation
1. Make `isChashValid` fully robust to malformed input by wrapping the entire body (including the `buffer2bin`/`separateIntoCleanDataAndChecksum` calls) in a single try/catch that returns `false` on any thrown error, rather than only wrapping the `base32.decode`/`Buffer.from` call.
2. Alternatively/additionally, validate the base32 alphabet explicitly in `isValidAddressAnyCase` before calling `isChashValid`, consistent with `isValidAddress`'s regex check (case-insensitively), so that malformed characters are rejected up front rather than relying on the decoder's behavior.
3. Add defensive length checks immediately after `base32.decode`/`Buffer.from` in `isChashValid` (verify decoded buffer length is exactly 20 or 36 bytes) before proceeding, returning `false` on mismatch instead of letting `separateIntoCleanDataAndChecksum` throw.

### Proof of Concept
Conceptual PoC (exact triggering byte sequence depends on `thirty-two`'s internal decode table behavior for out-of-alphabet characters, which I could not verify from the indexed code):
```js
var ValidationUtils = require('./validation_utils.js');
// 32-char string, correct length, but contains characters outside [A-Z2-7]
var malformedAddress = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"; // lowercase / non-base32-standard chars
ValidationUtils.isValidAddressAnyCase(malformedAddress); 
// -> internally calls chash.isChashValid, which may throw an uncaught Error
// from separateIntoCleanDataAndChecksum if base32.decode() returns a
// buffer whose length in bits isn't exactly 160, crashing the caller.
``` [4](#0-3) 

Note: I was unable to inspect the `thirty-two` package's internal decode implementation within the indexed codebase to conclusively prove that it returns a mis-sized buffer (versus always throwing) for non-alphabet input; this is the key uncertain fact needed to fully confirm exploitability. If `thirty-two`'s decoder throws for any invalid character, this specific path is already caught by the existing try/catch and the finding would need reclassification.

### Citations

**File:** validation_utils.js (L52-58)
```javascript
function isValidChash(str, len){
	return (isStringOfLength(str, len) && chash.isChashValid(str));
}

function isValidAddressAnyCase(address){
	return isValidChash(address, 32);
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
