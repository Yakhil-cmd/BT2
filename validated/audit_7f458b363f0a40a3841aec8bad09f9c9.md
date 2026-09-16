### Title
Wide-character-pointer-style confusion in secp256k1 PEM pubkey extraction allows spurious/attacker-steerable key location — (File: signature.js)

### Summary
`ungetwc`'s CVE-2026-5928 root cause is that the wide-character pushback path reads from the wrong buffer pointer (`fp->_IO_read_ptr` instead of `fp->_wide_data->_IO_read_ptr`), so two independently-maintained "views" of the same stream diverge and an offset computed for one is used against the other, producing a spurious match / out-of-bounds read. `signature.js` has the same class of bug: two different, independently computed offsets into the *same* DER buffer are used by two different code paths that are supposed to agree but don't, and the un-trusted-input consumer (`verifyMessageWithSecp256k1PemPubKey`) uses an unstructured `Buffer.indexOf` byte-pattern scan instead of the same structural ASN.1 offset arithmetic used elsewhere.

### Finding Description
`validateAndFormatPemPubKey` (signature.js:117-188) parses a caller/attacker-supplied PEM key structurally: it computes `identifiersStart`/`identifiersLength` from the ASN.1 length-tag bytes and only checks the algorithm/curve OID located at that exact structural offset [1](#0-0) .

Separately, `verifyMessageWithPemPubKey` (signature.js:27-48) recomputes a *different* offset, `algIdStart`, using its own independent ASN.1 length-tag decoding, and only checks equality with `SECP256K1_ALG_ID` at that position [2](#0-1) .

When the secp256k1 branch is taken, `verifyMessageWithSecp256k1PemPubKey` (signature.js:50-70) abandons offset arithmetic entirely and instead locates the public-key BIT STRING by scanning the whole buffer for the first occurrence of the 3-byte pattern `03 42 00` via `der.indexOf(...)`, then blindly slices 65 bytes after it as the public key: [3](#0-2) .

This mirrors the CVE's failure mode exactly: instead of using the pointer/offset that was actually validated by the structural parser, a second, unsynchronized mechanism (`indexOf`) is used to locate the "real" data, and if the byte sequence `03 42 00` occurs anywhere earlier in the buffer than the true bit-string location (e.g., inside the OID/algorithm-identifier region, inside a crafted "parameters" field, or in padding bytes that the structural check at `identifiersStart`/`algIdStart` never inspects for uniqueness), `bitStringIdx` will point to the wrong offset — a "spurious match" in the same sense the CVE describes for overlapping single-byte/multi-byte encodings. The 65 bytes read after this spurious offset are attacker-arrangeable bytes that were never covered by any structural validation, i.e., data outside the field that `validateAndFormatPemPubKey` actually vetted (the c-hash/algorithm check is decoupled from the pubkey bytes that end up being used for verification).

### Impact Explanation
This function is reachable directly from unprivileged AA-trigger data through the `is_valid_sig` oscript op: `pem_key` is evaluated from arbitrary trigger-controlled expressions, passed to `validateAndFormatPemPubKey`, then to `verifyMessageWithPemPubKey`/`verifyMessageWithSecp256k1PemPubKey` [4](#0-3) . Because the byte range consumed as "the public key" is chosen by an unstructured scan rather than the offset that was structurally validated, an AA that hard-codes/expects a specific pubkey embedded at a specific, validated DER position (e.g., verifying a counter-party's identity supplied partly by a trusted party and partly steered by the trigger sender) can be made to authenticate against a different 65-byte region than the one that was structurally checked. This breaks the intended binding between "the algorithm/curve that was validated" and "the exact key material that gets used for signature verification," which is precisely the mechanism `is_valid_sig` relies on to authorize AA fund release. A caller who can influence any bytes in the DER blob outside the exact position enforced by the structural checks (padding, unchecked bytes between the algorithm identifier and the bit string, or attacker-supplied `parameters`) can cause the wrong key material to be used for verification, undermining the security guarantee that `is_valid_sig` is supposed to provide for AA authorization logic — potentially enabling AA fund loss/misdirected authorization decisions when the AA logic assumes a 1:1 binding between validated PEM structure and verified key bytes.

### Likelihood Explanation
Likelihood is moderate: reaching the vulnerable code path requires no privileges — any unit/AA-trigger author can supply the `pem_key` argument to `is_valid_sig` [4](#0-3) , and the `bPostPemCurvesFix` secp256k1 fast-path is unconditionally taken once the OID matches at the "correct" structural offset [2](#0-1) . However, exploitation for concrete fund loss additionally requires an AA design that trusts the pubkey extracted by this function as bound to something validated independently of the caller's full control over the buffer (e.g., only part of the DER is attacker-controlled, such as a template with attacker-fillable padding/parameters and a fixed trusted OID+addr prefix) — a scenario that is plausible for AA templates validating counter-party PEM identities but was not exhaustively confirmed against a specific shipped AA.

### Recommendation
Replace the `indexOf`-based scan in `verifyMessageWithSecp256k1PemPubKey` with the same structural ASN.1 offset arithmetic (`identifiersStart`/`identifiersLength`, or `algIdStart` + fixed `SECP256K1_ALG_ID.length`) already used and validated in `validateAndFormatPemPubKey`/`verifyMessageWithPemPubKey`, so the byte range that is structurally checked is guaranteed to be identical to the byte range whose key material is actually used for `ecdsaVerify`. Reject the key if the computed bit-string offset does not immediately follow the validated algorithm identifier (no gap/extra bytes permitted).

### Proof of Concept
1. Craft a DER `SubjectPublicKeyInfo` blob whose leading `SEQUENCE`/`AlgorithmIdentifier` at the structurally-checked offset (`algIdStart`) matches `SECP256K1_ALG_ID` exactly, so `verifyMessageWithPemPubKey` dispatches to `verifyMessageWithSecp256k1PemPubKey` [2](#0-1) .
2. Insert extra attacker-controlled bytes (e.g., inside an unchecked `parameters` field or padding after the algorithm identifier and before the real BIT STRING) that happen to contain the sequence `03 42 00` followed by a 65-byte buffer starting with `0x04` that is a valid uncompressed secp256k1 point the attacker holds the private key for.
3. Base64-encode and PEM-wrap this blob, submit it as `trigger.data.pem_key` together with `trigger.data.message` and a signature produced with the attacker's private key over that message.
4. `der.indexOf(Buffer.from([0x03,0x42,0x00]))` in `verifyMessageWithSecp256k1PemPubKey` returns the spurious, attacker-planted offset (not the offset validated by `validateAndFormatPemPubKey`), and `ecdsaVerify` succeeds against the attacker's key instead of the key implied by the structurally-validated identifier location [3](#0-2) .

### Citations

**File:** signature.js (L32-36)
```javascript
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

**File:** signature.js (L139-165)
```javascript
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
```

**File:** formula/evaluation.js (L1722-1731)
```javascript
						evaluate(pem_key, function (evaluated_pem_key) {
							if (fatal_error)
								return cb(false);
							signature.validateAndFormatPemPubKey(evaluated_pem_key, "any", function (error, formatted_pem_key){
								if (error)
									return setFatalError("bad PEM key in is_valid_sig: " + error, { arr }, false, cb);
								var result = signature.verifyMessageWithPemPubKey(evaluated_message, evaluated_signature, formatted_pem_key, bPostPemCurvesFix);
								return cb(result);
							}, bPostPemCurvesFix);
						});
```
