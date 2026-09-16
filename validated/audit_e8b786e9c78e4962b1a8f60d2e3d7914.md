Based on my research, I found a plausible analog to the PyPXE buffer-overflow-induced-crash bug class in `chash.js`, in the address checksum/decoding path that every unprivileged unit poster's address strings pass through. [1](#0-0) [2](#0-1) [3](#0-2) 

### Title
Unhandled exception from malformed-length chash decoding causes node crash / DoS - (File: chash.js)

### Summary
`chash.isChashValid()` decodes an attacker-supplied address string (`base32.decode` for 32-char addresses or `Buffer.from(encoded,'base64')` for 48-char chashes) and assumes the decoded buffer is exactly 20 or 36 bytes (160/288 bits). Only the decode call itself is wrapped in try/catch; the subsequent bit-length assumptions in `separateIntoCleanDataAndChecksum()` are not, so a crafted string whose decoded byte length differs from the expected size throws an uncaught `Error`.

### Finding Description
`isChashValid(encoded)` first checks `encoded.length` is 32 or 48 characters, then decodes it into a `Buffer` inside a `try/catch`: [4](#0-3) 
It then calls `buffer2bin(chash)` and `separateIntoCleanDataAndChecksum(binChash)` **outside** that try/catch: [5](#0-4) 
`separateIntoCleanDataAndChecksum` explicitly throws if the bit length isn't exactly 160 or 288: [6](#0-5) 
Node's base64/base32 decoders are lenient about malformed input (skipping invalid characters or padding) rather than always failing, so a 48-character string with a mix of valid/invalid base64 characters can decode to a buffer whose length is not exactly 36 bytes, without the decode call itself throwing. The `bin.length` check then throws synchronously and uncaught from within `isChashValid`, which is called from `isValidChash`/`isValidAddress` in `validation_utils.js`: [3](#0-2) 
`isValidAddress()` is invoked directly, unguarded by try/catch, from many unprivileged-input validation paths, e.g. inside `.every()` checks on payment output addresses in `validation.js`: [7](#0-6) 
Any of these call sites can propagate the thrown error up through the synchronous validation call chain.

### Impact Explanation
If the exception is not caught by an outer handler (a scenario I could not fully verify given the tool-call limit — I did not confirm whether `network.js`'s `handleJoint`/`validate()` entry points wrap the whole synchronous validation call in try/catch), an attacker-crafted unit, AA trigger, or asset definition containing a malformed 48-character chash string (e.g., in an output address, asset issuer address, or AA address field) could throw an uncaught exception during validation on any full node processing that unit. This causes a Node.js process crash — a network-wide denial of service preventing confirmation of new units, matching the "network unable to confirm new units" impact bar and analogous to the PyPXE advisory's DoS-via-malformed-length-handling.

### Likelihood Explanation
The `isValidAddress`/`isChashValid` path is reached by any unprivileged actor who can post a unit, AA trigger, or asset definition containing address-like strings (payment outputs, authors, asset issuers, AA addresses). Constructing a 48-character string that decodes via Node's `Buffer.from(str,'base64')` to a byte length other than 36 (e.g., by embedding invalid characters or unusual padding) is a low-effort, deterministic manipulation, not requiring any privileged position.

### Recommendation
Wrap the entirety of `isChashValid()`'s body (not just the decode step) in a try/catch, and additionally explicitly verify `chash.length` equals the expected byte length (20 or 36 bytes) immediately after decoding, returning `false` rather than throwing when it doesn't match.

### Proof of Concept
Conceptually (unverified end-to-end due to tool limits): call `chash.isChashValid()` with a 48-character string such as `"AAAA" + "!".repeat(44)` (invalid non-base64 characters interspersed) so that `Buffer.from(str, 'base64')` returns a buffer whose length isn't 36 bytes; this causes `separateIntoCleanDataAndChecksum` to throw `"bad length=..."` uncaught. Embedding such a string as an output address in a payment message and posting the unit to a full node would trigger this code path via `validation.js`'s `isValidAddress` check during unit validation.

**Note on confidence**: I was unable to confirm within the available tool budget whether `network.js`'s top-level unit-validation entry point (`handleJoint`/`validate`) has an outer try/catch that would prevent an actual process crash — this is the key uncertainty determining whether the impact is a full DoS crash or merely a rejected/errored unit. A Devin session with fuller codebase access could trace `network.js`'s `handleJoint()` call chain to confirm this.

### Citations

**File:** chash.js (L45-68)
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
	var arrChecksumBits = [];
	var start = 0;
	for (var i=0; i<arrOffsets.length; i++){
		arrFrags.push(bin.substring(start, arrOffsets[i]));
		arrChecksumBits.push(bin.substr(arrOffsets[i], 1));
		start = arrOffsets[i]+1;
	}
	// add last frag
	if (start < bin.length)
		arrFrags.push(bin.substring(start));
	var binCleanData = arrFrags.join("");
	var binChecksum = arrChecksumBits.join("");
	return {clean_data: binCleanData, checksum: binChecksum};
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
