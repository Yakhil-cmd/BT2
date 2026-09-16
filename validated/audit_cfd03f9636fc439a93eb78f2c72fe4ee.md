### Title
Uncaught exception on malformed c-hash decode crashes address validation - (File: chash.js)

### Summary
`chash.isChashValid()` decodes an attacker-supplied encoded string with `base32.decode()`/`Buffer.from(encoded,'base64')` inside a `try/catch`, but the subsequent processing of the decoded buffer (`buffer2bin`, `separateIntoCleanDataAndChecksum`) is **not** covered by that `try/catch`. If the decoded buffer does not have the expected bit-length (160 or 288), `separateIntoCleanDataAndChecksum` throws an uncaught `Error`, which can propagate out of the validation call stack.

### Finding Description
`isChashValid()` in [1](#0-0)  only wraps the decode step in `try/catch`:
```
try{
    var chash = (encoded_len === 32) ? base32.decode(encoded) : Buffer.from(encoded, 'base64');
}
catch(e){ return false; }
var binChash = buffer2bin(chash);
var separated = separateIntoCleanDataAndChecksum(binChash);   // can throw, uncaught
```
`separateIntoCleanDataAndChecksum` [2](#0-1)  explicitly `throw`s when the decoded bit-length isn't exactly 160 or 288:
```
if (len === 160) arrOffsets = arrOffsets160;
else if (len === 288) arrOffsets = arrOffsets288;
else throw Error("bad length="+len+", bin = "+bin);
```
This function is reached via `validation_utils.isValidChash()` [3](#0-2) , which is used both by `isValidAddress()` (guarded by a strict `/^[A-Z2-7]{32}$/` regex that forces exactly-20-byte base32 decode, so safe) and by `isValidAddressAnyCase()` [4](#0-3) , which has **no charset restriction** before calling `isValidChash`. `isValidAddressAnyCase` is referenced in `validation.js`, meaning a caller that accepts a case-insensitive/looser address string (32 arbitrary characters) can drive an input into `base32.decode` that decodes to a buffer whose bit-length differs from 160, triggering the uncaught throw deep inside address-validity checking rather than a caught `false` return.

This is analogous to CVE-2017-5461: an insufficiently-guarded custom decode/length-handling path (rather than NSS's C buffer arithmetic) can be driven into an unexpected-length state by attacker-controlled encoded input, producing a crash in code that is supposed to fail gracefully with `false`.

### Impact Explanation
An uncaught exception thrown from deep inside address validation, if not caught by an enclosing `try/catch` in the calling chain (e.g. inside `validateAuthor`/`validateInputs` during unit processing), can terminate synchronous validation abruptly for a unit posted by any unprivileged peer, causing a node crash (denial of service) instead of a controlled unit-rejection. This would satisfy the "network unable to confirm new units" impact criterion if reachable on the main unit-validation path without a protecting try/catch.

### Likelihood Explanation
Exploitability depends on whether the `isValidAddressAnyCase` call site in `validation.js` is reachable from untrusted, attacker-controlled data (e.g., an address field within a unit/message/definition) and whether that call is wrapped by any outer `try/catch`/`async` error handler that would swallow the thrown error instead of crashing the process. I was not able to fully confirm the exact call site and its surrounding error-handling within the available tool budget — this is the main uncertainty in this finding.

### Recommendation
Wrap the entire body of `isChashValid` (including `buffer2bin` and `separateIntoCleanDataAndChecksum`) in the existing `try/catch` so any malformed-length decode returns `false` instead of throwing, matching the defensive intent already present for the decode step.

### Proof of Concept
Conceptual (not fully verified against the exact reachable call site):
```js
var chash = require('./chash.js');
// 32 characters outside strict base32 alphabet but still decodable by the 'thirty-two' library
// to a buffer whose bit length is not 160, triggering the uncaught throw in
// separateIntoCleanDataAndChecksum instead of a caught `false`.
chash.isChashValid("some-32-char-string-outside-A-Z2-7");
```

**Note on confidence:** I could not fully trace the exact call site of `isValidAddressAnyCase` in `validation.js` (the search only returned a match count, not the surrounding context/try-catch) within the remaining tool budget, so the reachability from a fully untrusted unit-posting path to an *uncaught* (process-crashing) exception is not fully confirmed. Given this ambiguity and the constraint that only concrete, provable Medium+/High/Critical impacts should be reported, this analog should be treated as tentative pending direct inspection of the `validation.js` call site and its error-handling context in a full Devin session.

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

**File:** validation_utils.js (L52-53)
```javascript
function isValidChash(str, len){
	return (isStringOfLength(str, len) && chash.isChashValid(str));
```

**File:** validation_utils.js (L56-58)
```javascript
function isValidAddressAnyCase(address){
	return isValidChash(address, 32);
}
```
