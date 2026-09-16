Based on my research, I found a structurally similar bug-class in `ocore--008`: an **unchecked length assumption causing an uncaught exception**, analogous to the Stellar `strkey` panic (where a length-derived value is used in downstream arithmetic without validating it stays within expected bounds).

### Title
Uncaught exception (panic) in `chash.isChashValid` via `isValidAddressAnyCase` bypassing base32-alphabet validation - (File: `chash.js`)

### Summary
`chash.isChashValid()` assumes that once an encoded string's *length* passes a coarse check (32 or 48 characters), the *decoded byte length* will always be exactly 20 or 36 bytes (160/288 bits). This assumption is only true when the input is restricted to the strict base32 alphabet, which is enforced by `isValidAddress()`'s regex `/^[A-Z2-7]{32}$/` [1](#0-0) , but is **not** enforced by the sibling function `isValidAddressAnyCase()`, which only checks string length via `isValidChash()` [2](#0-1) .

### Finding Description
`isChashValid()` only wraps the `base32.decode()`/`Buffer.from()` call in a `try/catch` block: [3](#0-2) 
If the decoded buffer's bit-length isn't exactly 160 or 288, `buffer2bin()`+`separateIntoCleanDataAndChecksum()` throws `Error("bad length="+len+...)` — and that throw happens **outside** the `try/catch`, so it propagates uncaught: [4](#0-3) 
The `thirty-two` `base32.decode()` library does not throw for characters outside the strict `[A-Z2-7]` alphabet (e.g., lowercase letters, `0`, `1`, `8`, `9`); it typically decodes them permissively or produces a buffer of unexpected length, which is exactly the kind of "did not validate the length-derived assumption" root cause seen in the strkey CVE (there, an inner length field was trusted to be small enough for arithmetic that assumed no overflow; here, an inner encoded length is trusted to always map to exactly 160/288 bits without verifying the alphabet that guarantees it).

`isValidAddress()` prevents this by pre-filtering with a strict regex before calling `isChashValid()` [1](#0-0) , but `isValidAddressAnyCase()` calls `isValidChash()` directly, skipping that regex: [2](#0-1) 

### Impact Explanation
If any validation code path that accepts case-insensitive/any-case addresses (via `isValidAddressAnyCase`) processes a unit/message field containing a crafted 32-character string using out-of-alphabet characters, the resulting uncaught `Error("bad length=...")` will propagate up the call stack. If that call site is not wrapped by validation's outer error handlers (`ifUnitError`/`ifJointError` try/catch), it becomes an uncaught exception that can crash the node process while validating an incoming, attacker-supplied unit — a availability/DoS condition consistent with "a network unable to confirm new units."

### Likelihood Explanation
I could not fully confirm, within the available tool budget, that the sole call site of `isValidAddressAnyCase` in `validation.js` lies outside a protective `try/catch`/`ifJointError` guard — the grep only located a single reference and I was unable to inspect its surrounding function context before the session ended. This is a material gap: if that call site is already wrapped in a try/catch (as most payload/hash validations in `validation.js` are, e.g. `validation.js:259-266` for payload commission), the exception would be caught and turned into a normal `ifJointError`, meaning the practical exploitability is low or nonexistent. Without confirming this, I cannot assert with confidence that this is a *reachable, unguarded* uncaught-exception path.

### Recommendation
- Harden `chash.isChashValid()` to wrap the entire body (including `separateIntoCleanDataAndChecksum`/`buffer2bin`) in the `try/catch`, returning `false` instead of throwing on any malformed decoded length.
- Alternatively/additionally, enforce the same strict base32 alphabet check in `isValidChash`/`isValidAddressAnyCase` as is already done in `isValidAddress`, so that length-only checks can never let malformed-alphabet strings reach the bit-length-dependent code.

### Proof of Concept
Not executed (no filesystem/runtime access in this session). Conceptually: call `ValidationUtils.isValidAddressAnyCase("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")` (32 lowercase `a`s, invalid case/alphabet for the intended base32 encoding) and observe whether `chash.isChashValid` throws instead of returning `false`. This should be verified in a live environment before treating it as confirmed-exploitable, given the uncertainty noted above about the caller's exception handling in `validation.js`.

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

**File:** validation_utils.js (L60-62)
```javascript
function isValidAddress(address){
	return (typeof address === "string" && /^[A-Z2-7]{32}$/.test(address) && isValidChash(address, 32));
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
