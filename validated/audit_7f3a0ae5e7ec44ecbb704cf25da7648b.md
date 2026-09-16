### Title
Missing validation of decoded c-hash length lets a malformed address string crash the node - (File: chash.js)

### Summary
`chash.isChashValid()` only checks the length of the *encoded* string before decoding it, but never validates the length of the *decoded* buffer before it is fed into `separateIntoCleanDataAndChecksum()`. If decoding yields a buffer whose bit-length is neither 160 nor 288, that function throws an uncaught `Error("bad length=...")` outside of any `try/catch`, which is the same bug class as CVE-2020-3810: an input-length invariant that is assumed rather than validated, causing an unhandled exception/crash when processing attacker-supplied data.

### Finding Description
`isChashValid()` validates only `encoded.length` (32 or 48 chars) and wraps the decode call itself in `try/catch`: [1](#0-0) 

But the result of decoding (`chash`, then `binChash = buffer2bin(chash)`) is passed straight into `separateIntoCleanDataAndChecksum(binChash)` **outside** that try block: [2](#0-1) 

`separateIntoCleanDataAndChecksum()` throws a plain `Error` if `bin.length` (i.e., decoded-buffer bit length) is not exactly 160 or 288: [3](#0-2) 

For 48-character inputs, decoding uses `Buffer.from(encoded, 'base64')`, whose output length is not fixed by the input length rule assumed by the code (48 base64 chars normally yields 36 bytes = 288 bits, but Node's base64 decoder is lenient about padding/invalid characters and can silently produce a shorter buffer for malformed but non-throwing input, e.g. strings with embedded whitespace, `=` padding placed early, or otherwise decodable-but-irregular character runs). When that happens, `chash.length*8 !== 288`, and the unguarded `throw` propagates out of `isChashValid()`.

`isChashValid()` is reached via `isValidChash()` → `isValidAddressAnyCase()` / `isValidAddress()` in `validation_utils.js`: [4](#0-3) 

`isValidAddress` is called pervasively throughout unit/AA/definition validation (payment outputs, author addresses, oracle addresses in `definition.js`'s `in merkle`/`address` operators, data feed conditions, attestation payloads, AA triggers, etc.), all of which are reachable from a single posted unit or AA trigger authored by an unprivileged party, e.g.: [5](#0-4) [6](#0-5) 

None of these call sites wrap `isValidAddress`/`isChashValid` in a `try/catch`; the codebase relies on the (false) assumption that `separateIntoCleanDataAndChecksum` always receives a 160- or 288-bit buffer.

### Impact Explanation
If reachable, an unhandled exception thrown from deep inside address validation (invoked while validating a maliciously crafted unit, AA definition/trigger address field, or oracle/data-feed address) is not guarded by the callers, and in Node.js an exception escaping the synchronous validation call stack that isn't caught by a domain/try-catch at the top level crashes the process. Because `validate()` in `validation.js` is invoked for every incoming unit and AA trigger, an attacker who can construct a single malformed unit (or AA trigger causing an AA to validate an address supplied in its own definition/oscript path) could crash a node processing it — a "network unable to confirm new units" condition if this is exploitable broadly across nodes running the same code.

### Likelihood Explanation
The exact reachability depends on whether `Buffer.from(str, 'base64')` in current Node.js versions can be made to return a buffer whose length in bytes is not exactly `48 * 6 / 8 = 36` for a 48-character string — this needs further reproduction/testing against the specific Node runtime in use, since strict/lenient base64 parsing behavior varies by version and by exact bytes supplied. I could not fully verify a concrete 48-character base64 string that triggers a decoded length other than 36 bytes without runtime experimentation, which limits certainty that this path is exploitable versus a defense-in-depth gap only.

### Recommendation
- In `chash.js`, validate the decoded buffer's bit-length immediately after decoding and before calling `separateIntoCleanDataAndChecksum`, returning `false` (not throwing) for any length other than 160/288, mirroring the existing `catch` block's `return false` behavior.
- Move the `separateIntoCleanDataAndChecksum` call (and everything downstream) inside the existing `try/catch` in `isChashValid()`, or add an explicit early length check on `chash.length * 8` right after decode.

### Proof of Concept
Conceptual PoC (needs runtime confirmation of a qualifying base64 input):
1. Find/construct a 48-character string `s` such that `Buffer.from(s, 'base64').length !== 36` but `Buffer.from` does not throw (e.g., by exploiting lenient handling of embedded `=` or invalid characters in Node's base64 decoder).
2. Call `chash.isChashValid(s)` directly, or post a unit/AA trigger with an address field set to `s` so that `validation_utils.isValidAddress(s)` is invoked during normal unit/AA validation.
3. Observe the uncaught `Error("bad length=...")` thrown from `separateIntoCleanDataAndChecksum`, propagating out of `isChashValid` and crashing the validating process if not caught by an outer handler.

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

**File:** validation_utils.js (L52-60)
```javascript
function isValidChash(str, len){
	return (isStringOfLength(str, len) && chash.isChashValid(str));
}

function isValidAddressAnyCase(address){
	return isValidChash(address, 32);
}

function isValidAddress(address){
```

**File:** validation.js (L245-255)
```javascript
		if (!objUnit.messages.every(m => {
			if (m.app === "payment" && m.payload)
				return isNonemptyArray(m.payload.outputs) &&
					(!("asset" in m.payload) || isStringOfLength(m.payload.asset, constants.HASH_LENGTH)) &&
					m.payload.outputs.every(o => isNonemptyObject(o) && isValidAddress(o.address) && isPositiveInteger(o.amount) && o.amount <= constants.MAX_CAP) &&
					isNonemptyArray(m.payload.inputs) &&
					m.payload.inputs.every(i => isNonemptyObject(i) && (!("type" in i) || ["issue", "headers_commission", "witnessing"].includes(i.type)));
			else
				return true;
		}))
			return callbacks.ifUnitError("invalid payment message");
```

**File:** definition.js (L269-278)
```javascript
			case 'address':
				if (objValidationState.bNoReferences)
					return cb("no references allowed in address definition");
				if (bInNegation)
					return cb(op+" cannot be negated");
				if (bAssetCondition)
					return cb("asset condition cannot have "+op);
				var other_address = args;
				if (!isValidAddress(other_address))
					return cb("invalid address");
```
