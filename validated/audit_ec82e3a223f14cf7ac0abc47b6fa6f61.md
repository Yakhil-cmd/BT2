Given the reachable attack surface constraints, the closest defensible analog to CVE‑2021‑4214 (an unvalidated length/offset used to walk a buffer, causing a crash on malformed input) is an **unhandled exception in the c‑hash validation routine** used to validate addresses supplied inside network‑visible objects (private‑payment outputs, unit authors, etc.).

### Title
Unhandled exception in c-hash validation on malformed address input causes a crash (DoS) - (File: chash.js)

### Summary
`chash.isChashValid()` only wraps the base32/base64 *decode* step in a `try/catch`; every subsequent step that processes the decoded buffer (`buffer2bin`, `separateIntoCleanDataAndChecksum`, `bin2buffer`) is unprotected and can `throw` on attacker-controlled input, propagating an uncaught exception up to the caller.

### Finding Description
`isChashValid(encoded)` in [1](#0-0)  only checks `encoded.length` (32 or 48) and wraps `base32.decode`/`Buffer.from` in `try/catch`. It does **not** validate that the decoded buffer actually contains exactly 160 or 288 bits, nor does it guard the following calls:
- `buffer2bin(chash)` [2](#0-1) 
- `separateIntoCleanDataAndChecksum(binChash)`, which explicitly `throw`s `Error("bad length=...")` for any bit-length other than 160/288 [3](#0-2) 

The 32‑character (base32) path is normally protected because the only caller that reaches `isChashValid` for addresses, `isValidAddress()`, first enforces a strict regex `^[A-Z2-7]{32}$` before calling `isValidChash` [4](#0-3) . However, `isValidAddressAnyCase()` calls `isValidChash(address, 32)` **without** that character-class restriction — only the length is checked [5](#0-4) . This lets any 32‑character string (including characters outside the base32 alphabet, mixed case, punctuation, etc.) reach `base32.decode()`, whose output length/format is not guaranteed to correspond to the expected 160‑bit payload, tripping the unguarded `throw` inside `separateIntoCleanDataAndChecksum`.

`isValidAddressAnyCase` is used as the "any case" address validator in `validatePaymentInputsAndOutputs` via `isValidAddressWithCase`, selected when `objValidationState.last_ball_mci < constants.timestampUpgradeMci` [6](#0-5)  for private-asset payment output addresses [7](#0-6) . It is thus reachable by a private-payment counterparty / asset issuer constructing a payment message with a specially crafted, malformed 32-character output address string in units whose `last_ball_mci` still falls below the timestamp-upgrade threshold (relevant on testnets/devnets and historical unit re-validation paths).

### Impact Explanation
If `separateIntoCleanDataAndChecksum` throws inside a synchronous call chain that is not wrapped by the caller (validation code generally expects `isValidAddress`-style functions to return booleans, not throw), the exception surfaces as an unhandled exception in Node.js. Depending on where it fires (inside unit/joint validation, network message handling, or wallet processing of a private payment chain) this can crash the process handling the malformed unit — a denial-of-service on any node/wallet that validates the crafted object, which can prevent a node from confirming otherwise-valid units while it is down or looping on the same poisoned data.

### Likelihood Explanation
Likelihood is constrained by the fact that the vulnerable code path (`isValidAddressAnyCase`) is guarded by the `timestampUpgradeMci` condition and is not the default validator on networks past that upgrade. It also depends on the exact (unverified from the index) behavior of the `thirty-two` package's `base32.decode()` on invalid input — whether it silently produces a buffer of unexpected length (triggering the throw) or itself throws (which *is* caught). I could not confirm the `thirty-two` decode implementation from the indexed files, so exploitability cannot be fully confirmed without further testing.

### Recommendation
- Wrap the entire body of `isChashValid()` (not just the decode call) in `try/catch` and return `false` on any exception, matching the defensive pattern already used for `base32.decode`/`Buffer.from`.
- Harden `isValidAddressAnyCase()` to also constrain the character set (or at minimum validate the decoded buffer length before proceeding) so malformed strings cannot reach unguarded downstream logic.

### Proof of Concept
Conceptual (not fully verified against the `thirty-two` package internals):
```js
var chash = require('./chash.js');
// 32-character string using characters outside the standard base32 alphabet [A-Z2-7]
// but still passing isStringOfLength(str, 32) used by isValidAddressAnyCase
chash.isChashValid('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'); // lower-case, may decode to unexpected byte length
// -> if base32.decode produces a buffer whose bit length isn't 160/288,
//    separateIntoCleanDataAndChecksum throws an uncaught Error("bad length=...")
```

**Caveat:** I was not able to fully verify the exact byte-length behavior of `base32.decode()` (from the `thirty-two` npm package) for non-standard input within the indexed codebase, so the exploitability of this specific throw path should be validated with direct testing/tracing before treating it as fully confirmed. If that verification fails to reproduce a crash, no other Medium/High/Critical analog matching the CVE's bug class (heap overflow due to unchecked length while parsing untrusted data) was found within the allowed reachable surfaces.

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

**File:** chash.js (L96-105)
```javascript
function buffer2bin(buf){
	var bytes = [];
	for (var i=0; i<buf.length; i++){
		var bin = buf[i].toString(2);
		if (bin.length < 8) // pad with zeros
			bin = zeroString.substring(bin.length, 8) + bin;
		bytes.push(bin);
	}
	return bytes.join("");
}
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

**File:** validation_utils.js (L48-62)
```javascript
function isStringOfLength(str, len){
	return (typeof str === "string" && str.length === len);
}

function isValidChash(str, len){
	return (isStringOfLength(str, len) && chash.isChashValid(str));
}

function isValidAddressAnyCase(address){
	return isValidChash(address, 32);
}

function isValidAddress(address){
	return (typeof address === "string" && /^[A-Z2-7]{32}$/.test(address) && isValidChash(address, 32));
}
```

**File:** validation.js (L2145-2145)
```javascript
	const isValidAddressWithCase = objValidationState.last_ball_mci >= constants.timestampUpgradeMci ? ValidationUtils.isValidAddress : ValidationUtils.isValidAddressAnyCase;
```

**File:** validation.js (L2174-2175)
```javascript
			if ("address" in output && !isValidAddressWithCase(output.address))
				return callback("output address " + JSON.stringify(output.address) + " invalid");
```
