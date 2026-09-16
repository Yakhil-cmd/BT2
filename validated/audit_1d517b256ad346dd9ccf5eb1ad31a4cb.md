### Title
Uncaught exception via malformed chash input crashes node validation before full address-format checks - ([File: chash.js])

### Summary
`chash.js` validates c-hashes (used for addresses/assets) with a two-stage design: a fast length check followed by decoding and bit-level checksum extraction. The checksum-extraction path (`separateIntoCleanDataAndChecksum`) can `throw` an uncaught `Error` when the decoded byte length isn't exactly 160 or 288 bits, and this throw is *not* wrapped in the `try/catch` that only covers the `base32.decode`/`Buffer.from` call. This mirrors the CVE-2019-18676 pattern: a value that passes a coarse, early length check reaches a deeper code path with insufficient validation, causing a crash before the "real" security checks (the base32-alphabet enforcing regex used by `isValidAddress`) are applied.

### Finding Description
`isChashValid(encoded)` only validates the *string length* (32 or 48) before decoding: [1](#0-0) 

The decode step is wrapped in try/catch, but the subsequent calls are not: [2](#0-1) 

`separateIntoCleanDataAndChecksum` explicitly `throw`s a plain `Error` (not routed through any callback/error-handling convention) if the bit length of the decoded buffer isn't exactly 160 or 288: [3](#0-2) 

The strict, well-formed entry point `isValidAddress` additionally enforces a base32-alphabet regex before calling into `chash.isChashValid`: [4](#0-3) 

However, `isValidChash`/`isValidAddressAnyCase` perform **only the length check**, without the alphabet regex, before calling `chash.isChashValid`: [5](#0-4) 

If the `thirty-two` base32 decoder is lenient toward characters outside the strict RFC4648 alphabet used by ocore’s regex (`[A-Z2-7]`) — e.g. lowercase letters, `0`, `1`, `8`, `9`, or padding artifacts — it can silently return a buffer whose byte length does not correspond to 160/288 bits. That buffer then propagates through `buffer2bin` → `separateIntoCleanDataAndChecksum`, hitting the unguarded `throw Error("bad length=...")`. Because this is a synchronous exception raised deep inside a call chain built entirely around callback-passing style (`ifError`/`ifOk`/`callback`), the throw is not caught by any of the calling validation functions, and surfaces as an unhandled exception at the point where the enclosing validation logic (`validation.js`, `definition.js`, asset/attestation/AA validation) invoked it.

### Impact Explanation
An unhandled synchronous exception thrown mid-way through unit/AA/asset validation on a full node (which has no blanket `try/catch` around these deep helper calls) can crash the Node.js process handling that connection/request. Since this is invoked while validating units broadcast by any unprivileged poster (addresses appear in `authors`, definition/asset conditions, attestation payloads, AA triggers, etc.), a single crafted unit or private/AA payload containing a chash-length string that decodes to the wrong bit-length can potentially crash the validating process — a node-wide denial of service preventing confirmation of new units, directly analogous to the "any client can trivially DoS the whole service via a single crafted input, before normal checks run" nature of CVE-2019-18676.

### Likelihood Explanation
Likelihood depends on whether the underlying `thirty-two` base32 library can be coerced into returning an unusual-length buffer for a 32-character string that is not restricted to the strict `[A-Z2-7]` alphabet, and on confirming a concrete callable path reaching `isValidChash`/`isValidAddressAnyCase` (rather than the more strictly regex-guarded `isValidAddress`) with attacker-controlled data (e.g., during any case-insensitive address comparison performed on unit/AA/asset fields). I was not able to fully trace every call site of `isValidChash`/`isValidAddressAnyCase` within the indexed portion of `validation.js` (only one match was found and its exact context could not be retrieved in the available iterations), so exploitability through a fully in-scope path (unit poster / AA trigger / asset issuer, not a hub/peer-only interaction) remains **unconfirmed**. This uncertainty should be resolved with a full codebase check (e.g., a Devin session) before treating this as fully validated.

### Recommendation
- Wrap `separateIntoCleanDataAndChecksum` (and `mixChecksumIntoCleanData`) calls in `chash.js`'s `isChashValid` in the same `try/catch` that already guards the decode step, converting the thrown `Error` into a `return false` instead of letting it propagate.
- Apply the same base32-alphabet regex validation that `isValidAddress` uses inside `isValidChash`/`isChashValid` itself, rather than relying on each caller to separately enforce it.
- Audit all call sites of `isValidChash` / `isValidAddressAnyCase` to ensure none of them process attacker-controlled input without equivalent protection.

### Proof of Concept
Conceptual (pending confirmation of an in-scope caller of `isValidChash`/`isValidAddressAnyCase` with attacker data, and of `thirty-two`'s decoding leniency):
```js
var chash = require('./chash.js');
// 32-char string, passes length check, but uses characters outside [A-Z2-7]
// if thirty-two's base32.decode does not strictly reject/normalize these,
// the resulting buffer's bit-length may not equal 160, hitting the
// unguarded `throw Error("bad length=...")` in separateIntoCleanDataAndChecksum.
chash.isChashValid("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1"); // illustrative, not verified
```
This PoC illustrates the code-path defect (unguarded throw reachable via `isValidChash`) but I could not execute/verify actual base32-decoder behavior or fully confirm an unauthenticated, in-scope caller path within the available search iterations.

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

**File:** validation_utils.js (L52-58)
```javascript
function isValidChash(str, len){
	return (isStringOfLength(str, len) && chash.isChashValid(str));
}

function isValidAddressAnyCase(address){
	return isValidChash(address, 32);
}
```

**File:** validation_utils.js (L60-62)
```javascript
function isValidAddress(address){
	return (typeof address === "string" && /^[A-Z2-7]{32}$/.test(address) && isValidChash(address, 32));
}
```
