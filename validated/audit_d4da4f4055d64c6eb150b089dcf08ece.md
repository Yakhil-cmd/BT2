### Title
Heap Buffer Over-Read via Unbounded DER Length Fields in PEM Public Key Parsing - (File: signature.js)

### Summary
`validateAndFormatPemPubKey` in `signature.js` parses attacker-controlled base64 PEM key data supplied through the `is_valid_sig` oscript function, reading DER length/tag bytes at fixed offsets without first verifying that the decoded buffer is long enough to contain them, analogous to the ImageMagick XCF decoder's integer-overflow-driven out-of-bounds read on crafted image headers (CVE-2026-53466).

### Finding Description
`validateAndFormatPemPubKey(pem_key, algo, handle, bPostPemCurvesFix)` strips PEM headers/footers and whitespace, checks only that the resulting base64 string is non-empty and no longer than 736 characters, and decodes it into `contentAloneBuffer`: [1](#0-0) 

It then reads `contentAloneBuffer[0]`, `[1]`, `[2]`/`[3]`/`[4]`, and derives `identifiersStart`/`identifiersLength` from these byte values, and slices `contentAloneHex` using `identifiersStart` and `identifiersLength` before any check that the buffer actually contains that many bytes: [2](#0-1) 

Because there is only an upper bound on the base64 *string* length (736 chars) but no lower bound and no validation that `contentAloneBuffer.length` is large enough for the indices being accessed (e.g. `contentAloneBuffer[4]` in the `0x82` length-tag branch, or the `.slice(identifiersStart*2, identifiersStart*2+identifiersLength*2)` computed from attacker-controlled `identifiersLength`), a short or crafted buffer can cause the code to read past the buffer end. In Node.js this typically yields `undefined` for out-of-range indexed reads (soft failure) rather than a native crash, but the subsequent hex slicing math (`identifiersStart*2 + identifiersLength*2`) is entirely attacker-derived from a single length byte (0–255) with no upper bound check against the actual `contentAloneHex.length`, so `.slice()` can silently return truncated/garbage data feeding into `objSupportedPemTypes` lookups, exactly the "integer used to compute a read range without bounds validation" root cause seen in the XCF advisory (CWE-190/CWE-681 — value from crafted input used unchecked as an array/offset size).

A related sibling function, `verifyMessageWithSecp256k1PemPubKey`, has the same unguarded-length pattern using fixed offsets (`bitStringIdx+3`, `bitStringIdx+68`) against a `der` buffer whose size is not checked beforehand: [3](#0-2) 

This whole code path is reachable from `is_valid_sig(...)` in the oscript formula evaluator, which any AA author (via AA definition/trigger) or unit poster embedding a `sig` message can invoke with an attacker-controlled PEM key and signature string, calling into `verifyMessageWithPemPubKey` → `validateAndFormatPemPubKey`: [4](#0-3) 

### Impact Explanation
If a malformed/undersized PEM public key causes `validateAndFormatPemPubKey` or `verifyMessageWithSecp256k1PemPubKey` to produce inconsistent results between two independently-executing full nodes (e.g., one node throws/returns false while another, due to JS engine or Buffer-implementation differences in out-of-range indexing, accepts the definition/signature), it can lead to a **consensus split (node disagreement on unit/AA validity)**, which is one of the accepted high-impact outcomes for this campaign. Even absent a consensus split, uncontrolled length-derived slicing feeding into address/authentifier or AA signature verification logic increases risk of signature-check bypass, potentially enabling unauthorized spending from an address whose definition relies on `is_valid_sig` with a PEM key.

### Likelihood Explanation
`is_valid_sig` with PEM keys is a documented, reachable oscript primitive usable by any address definition author or AA author; the attacker fully controls the `pem_key` and `algo` string in the triggering unit/AA trigger data, requiring no special privilege, matching the "unprivileged unit poster / AA author" reachability bar. The bug requires crafting a base64 payload that decodes to a buffer shorter than the offsets accessed by the branch selected by `contentAloneBuffer[1]`.

### Recommendation
Add explicit length checks in `validateAndFormatPemPubKey` before indexing `contentAloneBuffer` (verify `contentAloneBuffer.length` is sufficient for the selected branch's fixed offsets before reading `[3]`/`[4]`/`[5]`), and validate that `identifiersStart*2 + identifiersLength*2 <= contentAloneHex.length` before slicing. Apply the same length check to `verifyMessageWithSecp256k1PemPubKey` before slicing `der` at `bitStringIdx+3`/`bitStringIdx+68`.

### Proof of Concept
Construct an AA trigger or unit `sig` message invoking `is_valid_sig(message, signature, pem_key)` where `pem_key` decodes (after header/footer/whitespace stripping) to a very short buffer, e.g. only 2 bytes: `0x30 0x81` (satisfies `contentAloneBuffer[0] === 0x30` and `contentAloneBuffer[1] === 0x81`), then the code proceeds to read `contentAloneBuffer[3]` and `contentAloneBuffer[4]` which are out of bounds (`undefined`), driving `identifiersStart`/`identifiersLength` to `NaN`/`undefined`-derived values that propagate into the subsequent hex slice and type lookup with unchecked bounds.

### Citations

**File:** signature.js (L27-36)
```javascript
function verifyMessageWithPemPubKey(message, signature, pem_key, bPostPemCurvesFix) {
	var contentB64 = pem_key
		.replace("-----BEGIN PUBLIC KEY-----", "")
		.replace("-----END PUBLIC KEY-----", "")
		.replace(/\s/g, "");
	var der = Buffer.from(contentB64, 'base64');
	var algIdStart = der[1] <= 0x7F ? 4 : der[1] === 0x81 ? 5 : der[1] === 0x82 ? 6 : -1;
	if (algIdStart >= 0 && der.slice(algIdStart, algIdStart + SECP256K1_ALG_ID.length).equals(SECP256K1_ALG_ID)
			&& bPostPemCurvesFix)
		return verifyMessageWithSecp256k1PemPubKey(message, signature, der);
```

**File:** signature.js (L50-56)
```javascript
function verifyMessageWithSecp256k1PemPubKey(message, signature, der) {
	try {
		// Locate the BIT STRING for an uncompressed public key: 03 42 00 04 <32 X> <32 Y>
		var bitStringIdx = der.indexOf(Buffer.from([0x03, 0x42, 0x00]));
		if (bitStringIdx === -1) return false;
		var pubkey = der.slice(bitStringIdx + 3, bitStringIdx + 68); // 65 bytes: 04 + 32 + 32
		if (pubkey.length !== 65 || pubkey[0] !== 0x04) return false;
```

**File:** signature.js (L117-134)
```javascript
function validateAndFormatPemPubKey(pem_key, algo, handle, bPostPemCurvesFix) {

	if (!ValidationUtils.isNonemptyString(pem_key))
		return handle("pem key should be a non empty string");

	//we remove header and footer if present
	var contentAloneB64 = pem_key.replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", ""); 
	
	//we remove space, tab space or carriage returns
	contentAloneB64 = contentAloneB64.replace(/\s/g, "");

	if (contentAloneB64.length > 736) // largest is RSA 4096 bits
		return handle("pem content is too large");

	if (!ValidationUtils.isValidBase64(contentAloneB64))
		return handle("not valid base64 encoding" + contentAloneB64);

	var contentAloneBuffer = Buffer.from(contentAloneB64, 'base64');
```

**File:** signature.js (L136-181)
```javascript
	if (contentAloneBuffer[0] != 0x30)
		return handle("pem key doesn't start with a sequence");

//we determine start and length of algo/curve identifiers
	if (contentAloneBuffer[1] <= 0x7F){
		if (contentAloneBuffer[2] != 0x30)
			return handle("pem key doesn't have a second sequence");
		var identifiersStart = 4;
		var identifiersLength = contentAloneBuffer[3];
	} else if (contentAloneBuffer[1] == 0x81){
		if (contentAloneBuffer[3] != 0x30) 
			return handle("pem key doesn't have a second sequence");
		var identifiersStart = 5;
		var identifiersLength = contentAloneBuffer[4];
	} else if (contentAloneBuffer[1] == 0x82){
		if (contentAloneBuffer[4] != 0x30) 
			return handle("pem key doesn't have a second sequence");
		var identifiersStart = 6;
		var identifiersLength = contentAloneBuffer[5];
	} else {
		return handle("wrong length tag");
	}

	//we decode the length of identifiers
	if (identifiersLength != 13 && identifiersLength != 16 && identifiersLength != 19 && identifiersLength != 20)
		return handle("wrong identifiers length" + identifiersLength);

	//we isolate the identifiers
	var contentAloneHex = contentAloneBuffer.toString('hex')
	var typeIdentifiersHex = contentAloneHex.slice(identifiersStart * 2, identifiersStart *2 + identifiersLength *2);

	if (!objSupportedPemTypes[typeIdentifiersHex])
		return handle("unsupported algo or curve in pem key");

	if (bPostPemCurvesFix && !objSafePemTypes.has(typeIdentifiersHex))
		return handle("unsupported curve after pem curves fix MCI");

	if (algo != "any"){
		if (algo == "ECDSA" && objSupportedPemTypes[typeIdentifiersHex].algo != "ECDSA")
			return handle("PEM key is not ECDSA type");
		if (algo == "RSA" && objSupportedPemTypes[typeIdentifiersHex].algo != "RSA")
			return handle("PEM key is not RSA type");
	}

	if (objSupportedPemTypes[typeIdentifiersHex].algo == "ECDSA" && objSupportedPemTypes[typeIdentifiersHex].hex_pub_key_length != (contentAloneHex.length - identifiersStart * 2 - identifiersLength *2 - 8))
		return handle("wrong key length");
```
