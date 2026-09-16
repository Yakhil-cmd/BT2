### Title
Insufficient length validation before c-hash checksum parsing causes an uncaught exception (DoS) in address/chash validation - (File: chash.js)

### Summary
`isChashValid()` in `chash.js` decodes an attacker-controlled 32/48-character c-hash string (a unit's address, asset id, definition-chash, etc.) with `base32.decode()`/`Buffer.from(..., 'base64')` and then hands the resulting bytes to `separateIntoCleanDataAndChecksum()` without first confirming the decoded byte length actually matches the expected 160/288-bit size. Analogous to CVE-2017-16533, where the Linux HID subsystem parsed an externally supplied report descriptor without validating that its length matched what the fixed-format parser expected (leading to a read past the buffer and a crash), `ocore` here parses a fixed-bit-length structure (`arrOffsets160`/`arrOffsets288`) against a buffer whose actual size is not re-validated after decoding, so a short/malformed decode throws an uncaught `Error` outside of the surrounding `try/catch`.

### Finding Description
`isChashValid(encoded)` only checks the string length of the encoded input (32 or 48 characters): [1](#0-0) 

Decoding is wrapped in `try/catch`, but that catch only covers `base32.decode`/`Buffer.from` throwing. It does **not** validate that the decoded buffer is exactly 20 bytes (160 bits) or 36 bytes (288 bits). The `thirty-two` base32 library can, for certain malformed-but-not-throwing inputs (e.g. strings with padding/invalid characters that decode into a shorter byte array than expected), return a buffer whose length is not what `checkLength`/`calcOffsets` assumes.

That decoded buffer is passed to `buffer2bin()` (safe, works on any length) and then to `separateIntoCleanDataAndChecksum(bin)`: [2](#0-1) 

This function explicitly `throw`s a plain `Error` (not caught anywhere) if `bin.length` is neither 160 nor 288 — i.e., exactly the "wrong-length input reaches a fixed-format parser" bug class from the reference CVE. Because this throw happens *after* the `try/catch` block in `isChashValid` has already exited, it propagates as an uncaught exception.

`isChashValid` is the sole implementation backing address/chash validation used throughout unit and definition validation: [3](#0-2) 

`isValidAddress`/`isValidChash` are called pervasively while validating a freshly posted unit — on unit authors' addresses, output addresses, `address_definition_change` payloads, "address"/"cosigned by" definition operators, data-feed oracle addresses, etc. (e.g. `definition.js`): [4](#0-3) 

Any unprivileged unit poster can put such a string in an address field. If validation code calling `isValidAddress`/`isValidChash` does not wrap the call in its own `try/catch` (validation.js/definition.js call these as plain boolean predicates, not expecting them to throw), the uncaught exception surfaces up the async call chain during joint/unit validation, crashing (or leaving in an inconsistent state) the Node.js process performing validation — i.e., the same "crafted input causes crash during parsing due to missing length validation" root cause as CVE-2017-16533, translated to this codebase's own binary-parsing routine.

### Impact Explanation
Because address/chash validation happens on every incoming unit, and it is invoked as if it were a pure boolean function without exception handling at most call sites, a single crafted unit whose address (or referenced asset id / cosigner address / oracle address) is a syntactically-length-correct but semantically malformed base32/base64 string can throw an uncaught error mid-validation. This aborts validation for that unit/joint on any node processing it and, depending on whether an outer handler catches generic exceptions, can crash the node process validating units, causing a denial of service for validation/witnessing and preventing the network from confirming new units — matching the "network unable to confirm new units" acceptance criterion.

### Likelihood Explanation
Likelihood is Medium: the length precondition (32 or 48 chars) is trivial for an attacker to satisfy, and constructing a base32/base64 string that decodes without throwing but to an unexpected byte count is feasible (e.g., certain malformed padding accepted by the `thirty-two` decoder, or `Buffer.from(..., 'base64')`'s lenient handling of non-canonical base64 that silently truncates/pads). The exact byte counts the underlying libraries produce for adversarial inputs were not exhaustively verified in this review (no sandbox/test execution available), so exploitability should be confirmed by fuzzing `base32.decode`/`Buffer.from(_, 'base64')` with 32/48-character strings to find one whose decoded length differs from 20/36 bytes.

### Recommendation
In `chash.js`, after decoding, explicitly validate the decoded buffer's byte length (20 for chash160, 36 for chash288) before calling `buffer2bin`/`separateIntoCleanDataAndChecksum`, returning `false` (not throwing) on mismatch. Additionally, wrap the whole body of `isChashValid` in `try/catch` and return `false` on any exception, so a parsing anomaly can never propagate as an uncaught error into unit/definition validation.

### Proof of Concept
Conceptual PoC (exact byte-length-mismatching encodings depend on the `thirty-two` library's decoding leniency and were not verified against a running environment):
```js
var chash = require('./chash.js');
// Craft a 32-character base32 string that thirty-two decodes without throwing
// into a buffer whose length !== 20 bytes (e.g. via non-canonical padding characters).
var malformed = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="; // illustrative; needs library-specific crafting
console.log(chash.isChashValid ? chash.isChashValid(malformed) : "isChashValid not exported directly");
// Expected (buggy) behavior: throws "bad length=...` from separateIntoCleanDataAndChecksum,
// uncaught by any surrounding try/catch in validation_utils.isValidChash/isValidAddress.
```
A background Devin agent with code execution should verify concretely whether `base32.decode()` or `Buffer.from(str, 'base64')` can return a byte array whose length is neither 20 nor 36 for a 32/48-character input string without throwing, then confirm that `isValidAddress`/`isValidChash` propagate this as an uncaught exception during `validation.js`/`definition.js` unit validation.

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

**File:** validation_utils.js (L52-61)
```javascript
function isValidChash(str, len){
	return (isStringOfLength(str, len) && chash.isChashValid(str));
}

function isValidAddressAnyCase(address){
	return isValidChash(address, 32);
}

function isValidAddress(address){
	return (typeof address === "string" && /^[A-Z2-7]{32}$/.test(address) && isValidChash(address, 32));
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
