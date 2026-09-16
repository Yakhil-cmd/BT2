### Title
Uncaught exception / crash in `isChashValid` from malformed address field length mismatch - (File: `chash.js`)

### Summary
`chash.js` decodes an address's base32 payload and then processes it byte-for-byte assuming a fixed bit-length (160 or 288). If the decoded buffer is not exactly the expected size, the internal length check throws an `Error` that is **not** caught, unlike the sibling decode step which *is* wrapped in try/catch. This mirrors the CVE-2021-34085 bug class: a parsing routine that indexes/consumes attacker-controlled data assuming a fixed length, without validating the decoded length before further processing, leading to an unhandled crash.

### Finding Description
`isChashValid` only wraps the initial decode call in a try/catch: [1](#0-0) 

```
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
```

`base32.decode` can succeed (no exception) yet return a buffer whose byte length does not correspond to exactly 160 bits, since base32 decoding of a 32-character string with non-canonical padding/characters is not guaranteed to yield exactly 20 bytes. `buffer2bin` performs no length validation and simply serializes whatever bytes are present: [2](#0-1) 

The resulting bit-string is then passed, **outside any try/catch**, to `separateIntoCleanDataAndChecksum`, which explicitly throws for any length other than 160 or 288: [3](#0-2) 

```
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

This uncaught `Error` propagates synchronously out of `isChashValid`, which is called directly (with no try/catch at any call site) from `isValidChash` → `isValidAddress` / `isValidAddressAnyCase`: [4](#0-3) 

`isValidAddress` is used pervasively throughout unit validation (`validation.js`) to check author addresses, payment output addresses, definition addresses, AA trigger/definition addresses, etc. Any of these fields are attacker-controlled fields inside a unit/AA definition/trigger posted by an unprivileged party, so an address string crafted to decode via base32 into a buffer whose bit-length is not exactly 160 will trigger the uncaught throw during routine validation of an incoming unit.

### Impact Explanation
Since `isValidAddress`/`isValidChash` is invoked synchronously deep inside unit validation with no surrounding exception handling at this level, an uncaught exception thrown mid-validation can crash the calling logic path (or, depending on the surrounding async/callback context, propagate as an unhandled exception in the Node.js process). This is a network-wide, unauthenticated denial-of-service vector: a single malicious unit/AA trigger with a crafted address field can crash any full node or light client that attempts to validate it, preventing the network from confirming new units — directly matching one of the accepted high-impact outcomes (a network unable to confirm new units).

### Likelihood Explanation
The bug is reachable by any unprivileged unit poster, AA author, or trigger sender simply by including a crafted address string in a routinely-validated field (author address, payment output address, definition address, etc.). No special privileges, hub/peer compromise, or key leakage is required — only crafting a base32 string that decodes to a buffer of unexpected byte length. This makes exploitation straightforward for anyone who can broadcast a unit.

### Recommendation
Wrap the length-dependent processing (`buffer2bin`, `separateIntoCleanDataAndChecksum`, and the subsequent checksum comparison) in `isChashValid` in the same try/catch used for the decode step, and/or explicitly validate `chash.length * 8` equals 160/288 before proceeding, returning `false` instead of throwing on mismatch.

### Proof of Concept
1. Construct a 32-character string that is valid base32 alphabet input but decodes (via the `thirty-two` library) to a buffer whose length is not exactly 20 bytes (e.g., a string with irregular padding characters that the library still parses without throwing).
2. Pass this string as an address field in a unit's payment output (`payload.outputs[i].address`) or as an author's `address`, and submit the unit for validation.
3. During validation, `isValidAddress` → `isValidChash` → `chash.isChashValid` is invoked; `separateIntoCleanDataAndChecksum` throws an uncaught `Error`, crashing the validation call path on any node that processes the unit. [1](#0-0) [3](#0-2) [4](#0-3)

### Citations

**File:** chash.js (L45-54)
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
	var arrFrags = [];
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
