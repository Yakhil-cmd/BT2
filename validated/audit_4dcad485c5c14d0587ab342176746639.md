## Title
Structural-vs-pattern-search mismatch in secp256k1 PEM public-key extraction allows signature-check bypass on "pem" oscript authentifiers - (File: signature.js)

### Summary
`signature.js` validates `pem_key` authentifiers used in oscript address definitions (`sig` with an `algo`/PEM key, reachable via `formula/evaluation.js` and `formula/validation.js`, which together account for 41 references to PEM handling) with two structurally different code paths: `validateAndFormatPemPubKey()` computes the OID/key location by parsing DER length bytes precisely (`identifiersStart`, `identifiersLength`, offset arithmetic), while the actual verification key used at spend time, `verifyMessageWithSecp256k1PemPubKey()`, does **not** use that structural offset. Instead it re-locates the public key by blindly scanning the *entire* DER buffer for the first occurrence of the raw byte pattern `03 42 00` via `Buffer.indexOf`. [1](#0-0) 

### Finding Description
`validateAndFormatPemPubKey` (used when defining/parsing an address definition containing a PEM public key) is a boundary-condition-heavy parser that computes exact offsets for the DER `SEQUENCE`/`AlgorithmIdentifier`/`BIT STRING` fields from length bytes it reads out of the buffer: [2](#0-1) 

But the function that is actually invoked to extract and verify the public key against a spending signature, `verifyMessageWithSecp256k1PemPubKey`, ignores that computed structure entirely and instead searches for the fixed 3-byte marker `[0x03, 0x42, 0x00]` anywhere in the buffer with `der.indexOf(...)`, then blindly slices 65 bytes after it as the "public key": [3](#0-2) 

`verifyMessageWithPemPubKey`, the dispatcher that decides whether to use the secp256k1 fast path, likewise computes the algorithm-id location structurally (`algIdStart`) but only checks that the algorithm OID bytes match at that computed offset — it does not verify that the *key* bytes located later by the unrelated `indexOf` scan actually correspond to the same structurally-validated key material: [4](#0-3) 

Because `identifiersLength` for secp256k1 (13 bytes) is smaller than for other supported curves (up to 20 bytes) in `objSupportedPemTypes`, and `validateAndFormatPemPubKey`'s final length check only constrains the *total* buffer length relative to `hex_pub_key_length`, it is possible to craft a DER blob containing "filler"/reserved bytes before the true key material. If those filler bytes happen to (or are engineered to) contain the literal sequence `03 42 00`, `indexOf` will match at that *earlier* offset rather than at the structurally correct BIT STRING position, causing `verifyMessageWithSecp256k1PemPubKey` to extract and verify against attacker-chosen "public key" bytes that are different from the bytes that were validated/committed to the address definition hash by `validateAndFormatPemPubKey`. This is the same bug class as the CVE's "incorrect boundary conditions" — one code path enforces a structural boundary/offset, a second, security-critical code path re-derives the same boundary using an unrelated heuristic (pattern search) that does not agree with the first in all inputs.

### Impact Explanation
`pem_key`/`sig` with PEM authentifiers are part of address definitions that any unit poster, AA author, or asset-transfer counterparty can create and use as their own address's spending condition (`formula/evaluation.js`, `formula/validation.js`). If the structural offset used to commit the key to the address (chash of the definition) can diverge from the byte range actually used at verification time, an attacker could construct an address definition where a hostile party's signature is accepted for spending under a key that isn't what the address hash formally commits to, or conversely construct a benign-looking definition whose effective verification key differs from what auditors/co-signers believe it to be. Either outcome is an authentication-bypass primitive at the address-authentifier level and can translate into unauthorized spending of funds secured by such an address, satisfying the "concrete unauthorized spending" bar from the report's Validate criteria.

### Likelihood Explanation
Exploitation requires the attacker to control the PEM key bytes placed in their own address definition (which they always do, since they choose the authentifier when creating the address) and to successfully make `indexOf` land on an attacker-favorable offset instead of the structurally-correct one. Because the DER `AlgorithmIdentifier` for secp256k1 is short and fixed, and the amount of "slack" bytes before the real BIT STRING is limited, engineering the exact collision requires careful crafting but is a deterministic, offline computation — no privileged network position or timing is required, matching the "unprivileged unit poster" reachability constraint.

### Recommendation
Make `verifyMessageWithSecp256k1PemPubKey` use the same structurally-computed offset (`identifiersStart + identifiersLength`, as already computed in `validateAndFormatPemPubKey`) to locate the BIT STRING/public key, rather than an unconstrained `indexOf` scan over the whole buffer. Alternatively, pass the already-validated `pem_key`'s exact key offset/length through from `validateAndFormatPemPubKey` into the verification path so both functions agree by construction, and reject any DER blob where the `03 42 00` pattern appears more than once before the expected offset.

### Proof of Concept
Not independently executable from the index alone (no direct access to run code), but conceptually:
1. Choose the secp256k1 OID/AlgorithmIdentifier prefix so `validateAndFormatPemPubKey` accepts the key as `secp256k1`/ECDSA with the expected total length.
2. Insert filler bytes between the AlgorithmIdentifier and the real BIT STRING such that the filler itself contains `0x03 0x42 0x00` followed by 65 bytes that decode as a valid (attacker-controlled) uncompressed pubkey (`0x04` prefix) — while still satisfying the overall `hex_pub_key_length` == computed remaining length check in `validateAndFormatPemPubKey`.
3. Define an address whose authentifier is this crafted PEM key; the chash commits to the full buffer.
4. When spending, sign with the private key corresponding to the *filler* pubkey (found by `indexOf`) rather than the structurally "real" key at the computed offset; `verifyMessageWithSecp256k1PemPubKey` will validate the signature successfully because it uses `indexOf`, diverging from the structurally-intended key.

Note: I was not able to fully verify the exact byte-level feasibility (e.g., whether `objSupportedPemTypes`' fixed `hex_pub_key_length` checks in `validateAndFormatPemPubKey` fully preclude crafting such filler for the secp256k1 branch specifically) due to index size limits on retrievable file content for `signature.js` lines 189-400+ and `formula/validation.js`/`formula/evaluation.js` PEM-handling call sites. A full confirmation of exploitability (and the exact byte layout needed) would require starting a Devin session with full repository access to construct and test the DER byte sequences end-to-end.

### Citations

**File:** signature.js (L27-48)
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

	var verify = crypto.createVerify('SHA256');
	verify.update(message);
	verify.end();
	var encoding = ValidationUtils.isValidHexadecimal(signature) ? 'hex' : 'base64';
	try {
		return verify.verify({key: pem_key}, signature, encoding);
	} catch(e) {
		console.log("exception when verifying with pem key: " + e);
		return false;
	}
}
```

**File:** signature.js (L50-65)
```javascript
function verifyMessageWithSecp256k1PemPubKey(message, signature, der) {
	try {
		// Locate the BIT STRING for an uncompressed public key: 03 42 00 04 <32 X> <32 Y>
		var bitStringIdx = der.indexOf(Buffer.from([0x03, 0x42, 0x00]));
		if (bitStringIdx === -1) return false;
		var pubkey = der.slice(bitStringIdx + 3, bitStringIdx + 68); // 65 bytes: 04 + 32 + 32
		if (pubkey.length !== 65 || pubkey[0] !== 0x04) return false;

		var encoding = ValidationUtils.isValidHexadecimal(signature) ? 'hex' : 'base64';
		var sigBytes = Buffer.from(signature, encoding);
		var rawCompact = sigBytes.length === 64 ? sigBytes : Buffer.from(ecdsa.signatureImport(sigBytes));
		var compactSig = Buffer.from(ecdsa.signatureNormalize(rawCompact));

		var msgBuf = Buffer.isBuffer(message) ? message : Buffer.from(message);
		var hash = crypto.createHash('sha256').update(msgBuf).digest();
		return ecdsa.ecdsaVerify(compactSig, hash, pubkey);
```

**File:** signature.js (L117-181)
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
