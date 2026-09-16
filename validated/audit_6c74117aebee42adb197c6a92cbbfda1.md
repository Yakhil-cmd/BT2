### Title
Uncaught exception (panic) in chash address-checksum decoding on malformed input - ([File: chash.js])

### Summary
`chash.js` exposes `isChashValid(encoded)`, used by `validation_utils.js` to validate any 32- or 48-character c-hash string (addresses, asset/definition chashes). The decode path assumes the decoded buffer always has an exact bit-length of 160 or 288, but this assumption is not enforced for every caller, and the length check that does exist is not guarded by a `try/catch`, so malformed input throws an uncaught `Error` instead of returning `false`.

### Finding Description
`isChashValid` only wraps the initial `base32.decode`/`Buffer.from(…,'base64')` call in a `try/catch`: [1](#0-0) 

Everything after the decode (`buffer2bin`, `separateIntoCleanDataAndChecksum`, `bin2buffer`) runs unprotected. `separateIntoCleanDataAndChecksum` explicitly `throw`s a plain `Error` if the decoded bit-length is not exactly 160 or 288: [2](#0-1) 

Node's base64 decoder is lenient: `Buffer.from(str, 'base64')` silently skips characters that are not part of the base64 alphabet instead of throwing, so a 48-character string containing a mix of valid and invalid characters can decode to a buffer shorter than the expected 36 bytes (288 bits). Likewise, `thirty-two`'s base32 decoder can produce an unexpected byte count for a 32-character string containing characters outside the `A-Z2-7` alphabet.

The length check performed by `isChashValid` only checks the *encoded string* length (32 or 48 characters), not that every character belongs to the expected alphabet: [3](#0-2) 

The strict caller `isValidAddress` mitigates this for one specific case by first requiring the string to match `/^[A-Z2-7]{32}$/` before calling `isValidChash`: [4](#0-3) 

However, `isValidChash` and `isValidAddressAnyCase` do **not** perform this alphabet check: [5](#0-4) 

Any code path that calls `isValidChash(str, len)` or `isValidAddressAnyCase` directly — bypassing the regex guard used by `isValidAddress` — can pass a crafted string containing disallowed characters at the exact required length (32 for 160-bit / 48 for 288-bit c-hashes). This reaches `isChashValid`, decodes to a shorter-than-expected buffer, and throws an uncaught `Error` from `separateIntoCleanDataAndChecksum`, which is not caught anywhere in the call stack. This is directly analogous to the reported Go bug class: a too-short/malformed decoded payload causes a decode routine to panic instead of gracefully rejecting the input.

### Impact Explanation
An uncaught synchronous exception thrown deep inside address/definition validation crashes the Node.js process handling unit/message validation (denial of service). Because address- and chash-validation utilities are invoked while validating externally supplied units, definitions, asset issuance fields, and AA-related data, an attacker who can reach any caller of `isValidChash`/`isValidAddressAnyCase` (bypassing the `isValidAddress` regex guard) can remotely crash a node, preventing it from confirming new units — a network availability impact matching the required "node unable to confirm new units" criterion.

### Likelihood Explanation
This requires identifying a concrete caller that uses `isValidChash`/`isValidAddressAnyCase` (rather than `isValidAddress`) on attacker-supplied data of the exact expected length. Grep found exactly one usage of `isValidChash`/`isValidAddressAnyCase` outside `validation_utils.js`, in `validation.js`, but its exact call site and the field it validates could not be retrieved before the tool budget was exhausted. Without confirming that specific call site accepts attacker-controlled, case-sensitive-only-checked address strings from a posted unit/message, the exact reachability of this crash from an unprivileged unit poster cannot be fully verified — this is the main uncertainty in this finding.

### Recommendation
- Wrap the entire body of `isChashValid` (not just the initial decode) in `try/catch`, returning `false` on any exception instead of propagating it.
- Additionally validate that decoded buffers have exactly the expected byte length (20 or 36 bytes) before calling `buffer2bin`/`separateIntoCleanDataAndChecksum`.
- Enforce the base32/base64 alphabet check (as already done in `isValidAddress`) inside `isValidChash` itself so all callers, including `isValidAddressAnyCase`, are protected uniformly.

### Proof of Concept
Conceptual PoC (pending confirmation of the exact `validation.js` call site that uses `isValidChash`/`isValidAddressAnyCase` with attacker data):
```js
var chash = require('./chash.js');
// 48-char string, length matches expected base64 chash length,
// but contains characters outside the base64 alphabet (e.g. spaces/symbols)
// causing Buffer.from(str,'base64') to silently drop them and yield <36 bytes.
var malformed = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA!!!!"; // 48 chars, some invalid
chash.isChashValid(malformed); // throws Error("bad length=...") uncaught if not caught by caller
```
If any validation path (e.g. in `validation.js`, confirmed to call `isValidChash`/`isValidAddressAnyCase`) passes such a string derived from a unit/definition field without pre-filtering via the `isValidAddress` regex, posting a unit containing that field crashes the validating node.

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
