## Analysis

The CVE-2019-7150 bug class is: **code reads a length-prefixed/structured value from untrusted input and does not verify that the decoded data actually has the expected size before further binary processing, causing a crash when it turns out to be truncated/malformed.**

The closest reachable analog in ocore is in the chash validation pipeline, which every address string in every unit (author addresses, `address_definition_change.definition_chash`, asset `definer_address`, AA definition addresses, etc.) passes through.

### Root cause

`chash.isChashValid()` decodes an attacker-supplied encoded string and only wraps the **decode** call in a `try/catch`. The subsequent processing of the decoded buffer — `buffer2bin()` and `separateIntoCleanDataAndChecksum()` — is **not** protected: [1](#0-0) 

`separateIntoCleanDataAndChecksum()` explicitly assumes the decoded bit-length is exactly 160 or 288 and `throw`s an uncaught `Error` otherwise: [2](#0-1) 

`isValidChash()`/`isValidAddress()` call straight into `isChashValid()` with no additional guard: [3](#0-2) 

The decode functions used here — `thirty-two`'s `base32.decode()` for 32‑char strings and `Buffer.from(str, 'base64')` for 48‑char strings — are known to be lenient decoders in Node.js: `Buffer.from(x, 'base64')` silently stops/ignores at invalid characters instead of throwing, and can return a buffer shorter than the nominal length implied by the string length. If such a "successfully decoded but wrong-length" buffer is produced, `buffer2bin()` returns a bit-string whose length is neither 160 nor 288, and `separateIntoCleanDataAndChecksum()` throws an **uncaught** exception, propagating all the way up through `isValidAddress` → `validateAuthor`/`validateInlinePayload` in `validation.js`, crashing the Node.js process that is validating the unit.

Because chash/address validation is purely deterministic on the bytes of the posted unit, **every full node** that processes the same malicious unit hits the identical uncaught exception and crashes — this is a network-wide denial of validation/confirmation, not merely a single-node bug.

### Caveat

I was not able to execute the `thirty-two` package or Node's base64 decoder in this environment to conclusively prove that a 32-character (or 48-character) string restricted to the legal alphabet can actually decode to a buffer whose length differs from 20/36 bytes. This is the crux of whether the analog is exploitable, and it needs to be verified by actually testing `base32.decode()`/`Buffer.from(str,'base64')` with crafted strings, and by checking whether `isValidAddress`'s regex (`/^[A-Z2-7]{32}$/`) fully constrains `thirty-two`'s decoder to fixed-length output, before this can be treated as a confirmed, exploitable crash.

### Title
Uncaught exception on malformed chash length in `isChashValid` due to unchecked truncated decode - (File: chash.js)

### Summary
`isChashValid()` in `chash.js` only catches exceptions from the initial base32/base64 decode step, but assumes without verification that the decoded buffer has exactly 160 or 288 bits before calling `separateIntoCleanDataAndChecksum()`, which throws an uncaught `Error` for any other length — mirroring the CVE-2019-7150 pattern of not checking whether decoded/read data was truncated before further fixed-size processing.

### Finding Description
`isChashValid()` decodes an attacker-controlled encoded chash string inside a `try/catch` [4](#0-3) , but the subsequent `buffer2bin(chash)` and `separateIntoCleanDataAndChecksum(binChash)` calls are outside that protection [5](#0-4) . `separateIntoCleanDataAndChecksum` throws a plain `Error` whenever `bin.length` is not exactly 160 or 288 [2](#0-1) . This function is reached from every `isValidAddress`/`isValidChash` call across the validation code path [6](#0-5) , which is used to validate author addresses, `address_definition_change.definition_chash`, and other address fields inside any posted unit [7](#0-6) .

### Impact Explanation
If the decode step (`base32.decode` / `Buffer.from(..,'base64')`) can, for any input matching the length/charset pre-checks, yield a buffer whose bit-length is not 160/288 (Node's base64 decoder is known to be lenient about invalid characters rather than throwing), then every node validating a unit containing such an address string throws an uncaught exception, crashing the node process. Since this is fully deterministic on unit bytes, it would crash all full nodes processing the same unit simultaneously, halting network-wide validation/confirmation of new units.

### Likelihood Explanation
Reachable by any unprivileged unit poster: any address field in a unit (author address, `address_definition_change`, asset definer, AA address, etc.) flows through `isValidAddress`/`isChashValid`. The likelihood hinges entirely on whether the underlying decoders can be made to return an off-length buffer for a string that otherwise passes the existing length/charset checks — this is the part flagged above as unverified.

### Recommendation
Wrap `buffer2bin`/`separateIntoCleanDataAndChecksum` inside the same `try/catch` as the decode step in `isChashValid`, and have `isChashValid` return `false` (rather than throw) on any unexpected decoded length, so malformed input can never produce an uncaught exception in unit validation.

### Proof of Concept
Not fully constructed — requires confirming that either `require('thirty-two').decode()` on a 32-character string restricted to `[A-Z2-7]` or `Buffer.from(str,'base64')` on a 48-character string can produce a buffer whose byte length is not exactly 20/36 bytes, respectively. This should be tested directly (e.g., `node -e "console.log(Buffer.from('....','base64').length)"` with crafted strings) to determine feasibility before treating this as confirmed.

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

**File:** validation_utils.js (L52-66)
```javascript
function isValidChash(str, len){
	return (isStringOfLength(str, len) && chash.isChashValid(str));
}

function isValidAddressAnyCase(address){
	return isValidChash(address, 32);
}

function isValidAddress(address){
	return (typeof address === "string" && /^[A-Z2-7]{32}$/.test(address) && isValidChash(address, 32));
}

function isValidDeviceAddress(address){
	return ( isStringOfLength(address, 33) && address[0] === '0' && isValidAddress(address.substr(1)) );
}
```

**File:** validation.js (L1719-1744)
```javascript
		case "address_definition_change":
			if (!isNonemptyObject(payload))
				return callback("payload must be a non empty object");
			if (hasFieldsExcept(payload, ["definition_chash", "address"]))
				return callback("unknown fields in address_definition_change");
			var arrAuthorAddresses = objUnit.authors.map(function(author) { return author.address; } );
			var address;
			if (objUnit.authors.length > 1){
				if (!isValidAddress(payload.address))
					return callback("when multi-authored, must indicate address");
				if (arrAuthorAddresses.indexOf(payload.address) === -1)
					return callback("foreign address");
				address = payload.address;
			}
			else{
				if ('address' in payload)
					return callback("when single-authored, must not indicate address");
				address = arrAuthorAddresses[0];
			}
			if (!objValidationState.arrDefinitionChangeFlags)
				objValidationState.arrDefinitionChangeFlags = {};
			if (objValidationState.arrDefinitionChangeFlags[address])
				return callback("can be only one definition change per address");
			objValidationState.arrDefinitionChangeFlags[address] = true;
			if (!isValidAddress(payload.definition_chash))
				return callback("bad new definition_chash");
```
