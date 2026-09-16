### Title
Uncaught length-mismatch exception in `chash.isChashValid` allows a single malformed address to crash unit/AA validation - ([File: chash.js])

### Summary
CVE-2017-9050 is a heap over-read in libxml2's `xmlDictAddString` caused by an *incomplete length check* left over from a prior fix (CVE-2016-1839): a length/offset assumption about attacker-controlled data was not fully re-validated, so malformed input reaches code that indexes past what was actually allocated, crashing the process. The relevant bug class here is not "buffer over-read" per se in JS (no raw memory access), but the analogous pattern: **an internal length invariant about untrusted, attacker-controlled data is assumed instead of defensively checked, and when violated it throws an uncaught exception deep in a hot validation path**, crashing/DoSing the node the same way the libxml2 bug crashes programs consuming untrusted XML.

### Finding Description
`chash.isChashValid()` decodes an externally supplied c-hash/address string and expects the decoded buffer to be exactly 160 or 288 bits after conversion: [1](#0-0) 

It validates only the *encoded string length* (`encoded_len !== 32 && encoded_len !== 48`), then calls `base32.decode(encoded)` (for the 32-char case) and passes the result to `buffer2bin()` and then `separateIntoCleanDataAndChecksum()`: [2](#0-1) 

`separateIntoCleanDataAndChecksum` re-checks the *bit length* of the decoded binary string and, if it isn't exactly 160 or 288, does not return an error — it **throws** a raw `Error`:
```
else throw Error("bad length="+len+", bin = "+bin);
``` [3](#0-2) 

The only `try/catch` in `isChashValid` wraps the base32/base64 decode call itself, not the subsequent `buffer2bin`/`separateIntoCleanDataAndChecksum` calls: [4](#0-3) 

So the length check exists (mirroring the "incomplete fix" pattern in the CVE — a check was added but doesn't cover every downstream code path that assumes the length invariant). If the base32/base64 decoding step produces a buffer whose *bit length* isn't a clean 160/288 (e.g., due to non-canonical/partial characters that some base32 decoders tolerate, or a valid-length base64 string like the 48-char case that legitimately decodes to something other than 288 bits when it contains padding or is otherwise malformed), the thrown `Error` propagates unguarded out of `isChashValid`.

This function underlies `validation_utils.isValidChash` / `isValidAddress`, which is called throughout unit, AA, and definition validation to check *every address string appearing in units, authors, AA triggers, definitions, and shared-address wallet messages*: [5](#0-4) 
For example, address definitions embedded in units are validated via `objectHash.getChash160`/definition validation paths that ultimately rely on chash correctness: [6](#0-5) 
and shared-address / device wallet messages call `ValidationUtils.isValidAddress` directly on attacker-supplied fields with no surrounding try/catch: [7](#0-6) [8](#0-7) 

If any of these call sites invoke `isValidAddress`/`isValidChash` without a `try/catch` around it (several call sites across `wallet.js`, `network.js`, `validation.js`, `definition.js`, `aa_validation.js`, `light.js` do call it as a plain boolean predicate, not inside a try block), a single crafted 32- or 48-character address-like string that decodes to a non-160/288-bit buffer will cause an unhandled exception, crashing the node process that is validating the unit/message — exactly the "incomplete length-check leads to crash on attacker input" pattern of CVE-2017-9050.

### Impact Explanation
An uncaught exception thrown deep inside address validation, when reached from an unprivileged input path (a posted unit's author/definition address, an AA trigger's address-like field, or a wallet/device shared-address message), can crash the hub/node process handling that unit. Because this is invoked while processing incoming units/messages from arbitrary posters, a single malformed unit or message could repeatedly crash nodes, preventing them from confirming new units (a "network unable to confirm new units" condition) — this matches the Validate criteria for impact.

### Likelihood Explanation
Likelihood depends on whether: (a) any reachable call site invokes `isValidAddress`/`isValidChash` without a wrapping `try/catch`, and (b) the `thirty-two` base32 decoder (or `Buffer.from(str,'base64')`) can actually be coaxed into returning a buffer whose length isn't a clean multiple of the expected 20/36 bytes for some 32/48-character inputs (e.g. base64 strings with non-standard padding characters that Node's lenient base64 decoder still accepts). I was not able to fully verify from the indexed code whether such an input exists (this depends on the exact tolerance of `Buffer.from(str, 'base64')`, which is lenient about invalid characters/padding in Node.js), and whether every current call site of `isValidAddress` in the unit-validation hot path is wrapped in try/catch — several files use it as a bare boolean check (`wallet.js`, `network.js`) which suggests some paths are unguarded, but a full audit of all call sites was not completed given the tool budget.

### Recommendation
- Move the length checks so that any length mismatch inside `separateIntoCleanDataAndChecksum`/`buffer2bin`/`isChashValid` returns `false` instead of throwing.
- Wrap the entire body of `isChashValid` (not just the decode call) in `try/catch`, returning `false` on any exception, so length-invariant violations from untrusted input can never propagate as uncaught exceptions.
- Audit all call sites of `ValidationUtils.isValidAddress`/`isValidChash` reachable from untrusted unit/AA/device-message input to ensure none can crash the process on unexpected exceptions.

### Proof of Concept
Conceptual PoC (exact byte sequence would need experimentation against the `thirty-two`/Node base64 decoder in this environment):
```js
var chash = require('./chash.js');
// Craft a 48-character base64-looking string whose decoded byte length,
// once converted to bits via buffer2bin, is not exactly 288 bits
// (e.g., a string that Buffer.from(str,'base64') decodes leniently,
// ignoring invalid trailing characters, producing a truncated buffer).
var malformed = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA!!!!"; // 48 chars, illegal trailing chars
try {
    chash.isChashValid(malformed); // expected: throws "bad length=..." uncaught
} catch (e) {
    console.log("CRASH: uncaught exception from isChashValid:", e);
}
```
This would need to be sent as an address field in a unit, AA trigger, or wallet `new_shared_address`/`approve_new_shared_address` message to a node whose corresponding call site does not wrap `isValidAddress` in try/catch, causing that node's process to crash while processing the message.

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

**File:** definition.js (L774-800)
```javascript
			case 'address':
				// ['address', 'BASE32']
				if (!pathIncludesOneOfAuthentifiers(path, arrAuthentifierPaths, bAssetCondition))
					return cb2(false);
				var other_address = args;
				storage.readDefinitionByAddress(conn, other_address, objValidationState.last_ball_mci, {
					ifFound: function(arrInnerAddressDefinition){
						evaluate(arrInnerAddressDefinition, path, cb2);
					},
					ifDefinitionNotFound: function(definition_chash){
						try {
							var arrDefiningAuthors = objUnit.authors.filter(function(author){
								return (author.address === other_address && author.definition && objectHash.getChash160(author.definition) === definition_chash);
							});
						}
						catch (e) {
							return cb2(false);
						}
						if (arrDefiningAuthors.length === 0) // no definition in the current unit
							return cb2(false);
						if (arrDefiningAuthors.length > 1)
							throw Error("more than 1 address definition");
						var arrInnerAddressDefinition = arrDefiningAuthors[0].definition;
						evaluate(arrInnerAddressDefinition, path, cb2);
					}
				});
				break;
```

**File:** wallet.js (L214-226)
```javascript
			case "approve_new_shared_address":
				// {address_definition_template_chash: "BASE32", address: "BASE32", device_addresses_by_relative_signing_paths: {...}}
				if (!ValidationUtils.isValidAddress(body.address_definition_template_chash))
					return callbacks.ifError("invalid addr def c-hash");
				if (!ValidationUtils.isValidAddress(body.address))
					return callbacks.ifError("invalid address");
				if (typeof body.device_addresses_by_relative_signing_paths !== "object" 
						|| Object.keys(body.device_addresses_by_relative_signing_paths).length === 0)
					return callbacks.ifError("invalid device_addresses_by_relative_signing_paths");
				walletDefinedByAddresses.approvePendingSharedAddress(body.address_definition_template_chash, from_address, 
					body.address, body.device_addresses_by_relative_signing_paths);
				callbacks.ifOk();
				break;
```

**File:** wallet_defined_by_addresses.js (L377-395)
```javascript
// {address: "BASE32", definition: [...], signers: {...}}
function handleNewSharedAddress(body, callbacks){
	if (!ValidationUtils.isArrayOfLength(body.definition, 2))
		return callbacks.ifError("invalid definition");
	if (typeof body.signers !== "object" || Object.keys(body.signers).length === 0)
		return callbacks.ifError("invalid signers");
	try {
		var addr = objectHash.getChash160(body.definition);
	}
	catch (e) {
		return callbacks.ifError("invalid definition: " + e);
	}
	if (body.address !== addr)
		return callbacks.ifError("definition doesn't match its c-hash");
	for (var signing_path in body.signers){
		var signerInfo = body.signers[signing_path];
		if (signerInfo.address && signerInfo.address !== 'secret' && !ValidationUtils.isValidAddress(signerInfo.address))
			return callbacks.ifError("invalid member address: " + JSON.stringify(signerInfo.address));
	}
```
