### Title
Uncaught exception in address/c-hash validation causes node crash via malformed base64 address string - (File: chash.js)

### Summary
`chash.isChashValid()` only wraps the base32/base64 decode step in a `try/catch`. The subsequent processing of the decoded bytes (`buffer2bin` → `separateIntoCleanDataAndChecksum`) is unprotected and can throw an uncaught `Error` when a 48-character "address"-shaped string decodes (via Node's lenient `Buffer.from(str,'base64')`) to a byte length other than 288 bits. Because `isValidAddress`/`isValidAddressAnyCase` (which call `isChashValid`) are used pervasively as plain boolean predicates throughout unit, definition, and AA validation, this uncaught exception propagates out of what callers assume is a safe synchronous check, crashing the process that is validating an attacker-supplied unit — the same "malformed length field causes unchecked out-of-range parsing that crashes the process" bug class described in CVE-2025-63649 for monkey's chunked-encoding parser.

### Finding Description
`isChashValid` in [1](#0-0)  is:

```js
function isChashValid(encoded){
	var encoded_len = encoded.length;
	if (encoded_len !== 32 && encoded_len !== 48)
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
	...
}
```

Only the decode call is inside the `try` block. `Buffer.from(str, 'base64')` in Node.js is lenient — invalid/non-base64 characters interspersed in the string are silently skipped rather than throwing, so a 48-character string containing a mix of valid and invalid base64 characters can decode to a `Buffer` whose length is not exactly 36 bytes (288 bits).

That malformed-length buffer is passed unguarded to `buffer2bin` and then to `separateIntoCleanDataAndChecksum` ( [2](#0-1) ), which explicitly throws when the bit length is anything other than 160 or 288:
```js
function separateIntoCleanDataAndChecksum(bin){
	var len = bin.length;
	var arrOffsets;
	if (len === 160)
		arrOffsets = arrOffsets160;
	else if (len === 288)
		arrOffsets = arrOffsets288;
	else
		throw Error("bad length="+len+", bin = "+bin);
	...
```
This `throw` occurs outside the `try/catch` in `isChashValid`, so it is an unhandled exception.

`isChashValid` is reached through `isValidChash` → `isValidAddress`/`isValidAddressAnyCase` in [3](#0-2) , which are called as plain synchronous boolean predicates dozens of times across unit validation, address-definition validation, and AA trigger/definition validation (e.g. `definition.js`, `aa_validation.js`, `validation.js`). None of these call sites expect `isValidAddress()` to throw — they use it as `if (!isValidAddress(x)) return cb("...")`. An attacker can place a crafted 48-character address-like string in any of these validated fields (unit author address, output address, definition-embedded address, AA trigger data referencing an address, private-payment address, etc.) from a normal, unprivileged unit/trigger post.

### Impact Explanation
When the exception is thrown mid-validation of an incoming unit/trigger and is not caught by an enclosing handler, it becomes an unhandled exception in Node.js, which by default terminates the process. Since unit/AA validation happens on every node processing new units (light and full), a single crafted unit containing this malformed pseudo-address string can crash any node that attempts to validate it — a network-wide denial-of-service that prevents confirmation of new units, matching the "network unable to confirm new units" impact class for this analog category.

### Likelihood Explanation
The bug is reachable by an ordinary, unprivileged actor: any address-typed field parsed during standard unit/AA-trigger/definition validation flows through `isValidAddress`. Constructing a 48-character string that base64-decodes (with silently-dropped invalid characters) to a length other than 36 bytes requires no special privileges and is a simple, repeatable string-crafting exercise, making exploitation straightforward once triggered against a target field.

### Recommendation
Move the entire body of `isChashValid` (including `buffer2bin` and `separateIntoCleanDataAndChecksum`) inside the `try/catch`, or add an explicit length check (`chash.length === 20` / `chash.length === 36`) immediately after decoding and return `false` rather than throwing when the decoded buffer's length does not match the expected 160/288-bit c-hash size.

### Proof of Concept
Conceptually:
1. Build a 48-character string using otherwise-valid base64 alphabet characters but interleave a small number of invalid characters (e.g., punctuation not in the base64 alphabet) such that Node's `Buffer.from(str, 'base64')` silently skips them, yielding a decoded buffer whose length is not exactly 36 bytes.
2. Place that string in any unit field validated via `isValidAddress`/`isValidAddressAnyCase` (e.g., an output `address`, an address-definition reference, or AA trigger `data` field consumed by `is_valid_address`/definition validation) and post the unit to the network.
3. When a node validates the unit, `chash.isChashValid()` decodes the string successfully (no exception in the `try` block), then calls `separateIntoCleanDataAndChecksum` with a bit-length other than 160/288, throwing an uncaught `Error` that is not caught anywhere up the synchronous call chain from `isValidAddress`, crashing the validating node process.

Note: I was not able to execute this against a live node to directly confirm process termination (only static code-path analysis was performed here); a Devin session with runtime access would be needed to confirm whether any outer wrapper (e.g., a global `uncaughtException` handler) currently mitigates the crash in this deployment.

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
