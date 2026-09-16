## Title
`is_valid_sig()`/`vrf_verify()` reject valid compressed-format secp256k1 public keys, permanently freezing AA-gated funds - (File: signature.js)

### Summary
`signature.js` implements PEM public-key parsing and secp256k1 signature verification used by the oscript functions `is_valid_sig()` and `vrf_verify()`. Both `validateAndFormatPemPubKey()` and the dedicated `verifyMessageWithSecp256k1PemPubKey()` (added as part of the "pemCurvesFix" hardening of secp256k1 verification) hard-code the assumption that the embedded EC public key is in **uncompressed SEC1 format** (`0x04` prefix, 65 bytes). Neither function recognizes the equally valid, standards-compliant **compressed** SEC1 format (`0x02`/`0x03` prefix, 33 bytes). This mirrors the reported EigenPod issue, where the code checked for only one valid prefix (`0x01`) and had no branch for another valid, upgrade-introduced prefix (`0x02`), causing correctly-formatted data to be rejected.

### Finding Description
`validateAndFormatPemPubKey()` computes the expected key length from a static `hex_pub_key_length` table and rejects any key whose byte length doesn't match: [1](#0-0) 
This length is derived only for uncompressed keys (raw X,Y coordinates); a compressed key (`02`/`03` + X only) is exactly half that size and is unconditionally rejected with `"wrong key length"`.

Even if this generic check were bypassed, the dedicated post-fix secp256k1 verifier used for `objSafePemTypes` entries (added specifically to avoid relying on OpenSSL for secp256k1) only locates and parses an uncompressed point: [2](#0-1) 
It searches the DER for the fixed byte pattern `03 42 00` (BIT STRING tag/length for a 66-byte content, i.e. 1 unused-bits byte + 65-byte uncompressed key) and then requires `pubkey[0] === 0x04`. A compressed key produces a `03 22 00` bit-string header (34-byte content) and a leading `0x02`/`0x03` byte, so `bitStringIdx` is never found (`-1`) and the function returns `false` even though the underlying signature and key are cryptographically valid.

This code path is directly reachable by any AA trigger sender or oscript author through the `is_valid_sig` and `vrf_verify` formula operators, which call these functions on user/trigger-supplied PEM keys and signatures: [3](#0-2) 

Prior to the "pemCurvesFix" hardening, secp256k1 PEM signatures were verified via Node's generic `crypto.createVerify`, which fully supports SEC1 point compression through OpenSSL. The dedicated safe-curve path introduced for secp256k1 dropped this compatibility, so a compressed-key signature that verified correctly before the fix will now always fail after it: [4](#0-3) [5](#0-4) 

### Impact Explanation
AAs are free to use `is_valid_sig()`/`vrf_verify()` as a condition for releasing funds (e.g., verifying an externally-signed oracle attestation, bridge proof, or off-chain approval before paying out). If the counterparty's tooling produces a standard **compressed** secp256k1 public key (a common default in many crypto libraries, including OpenSSL's `-conv_form compressed`), the verification will deterministically return `false` for every legitimately signed message, and for RSA-independent ECDSA curves generally the length check in `validateAndFormatPemPubKey` will reject it outright with an error. Funds whose release is gated on this check become permanently unspendable/frozen — matching the accepted impact class of "AA fund loss or freezing." No malicious behavior by any party is required; a standards-valid input format is simply never recognized.

### Likelihood Explanation
Any user can trigger this by simply presenting a compressed-format public key/signature pair to an AA that performs `is_valid_sig`/`vrf_verify` checks — this requires no special privileges, only a normal trigger unit or AA definition using these documented oscript primitives. Compressed public keys are a very common, standards-compliant encoding, making accidental triggering likely for any AA author or integrator who doesn't happen to force uncompressed-only key generation.

### Recommendation
Extend `validateAndFormatPemPubKey()` and `verifyMessageWithSecp256k1PemPubKey()` (and any other curve-specific paths) to recognize and correctly parse both compressed (`0x02`/`0x03`, 33-byte) and uncompressed (`0x04`, 65-byte) SEC1 public key encodings, decompressing compressed points before passing them to `ecdsaVerify`, and updating the length-validation table to accept both key sizes per curve.

### Proof of Concept
1. Generate a secp256k1 EC key pair and export the public key in **compressed** SEC1/DER PEM form (e.g., `openssl ec -pubout -conv_form compressed`).
2. Sign an arbitrary message with the corresponding private key.
3. Deploy an AA whose logic pays out funds when `is_valid_sig(message, pem_key, signature)` (or `vrf_verify`) returns `true` for this key/signature/message.
4. Submit a trigger supplying the message, the compressed PEM public key, and the valid signature.
5. Observe that `validateAndFormatPemPubKey()` returns `"wrong key length"` (or, if that check is bypassed, `verifyMessageWithSecp256k1PemPubKey()` returns `false` due to `bitStringIdx === -1`), even though the signature is cryptographically valid — the AA condition can never be satisfied and any funds contingent on it are permanently frozen.

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

**File:** signature.js (L50-69)
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
	} catch(e) {
		console.log('secp256k1 pem verify exception: ' + e);
		return false;
	}
```

**File:** signature.js (L180-181)
```javascript
	if (objSupportedPemTypes[typeIdentifiersHex].algo == "ECDSA" && objSupportedPemTypes[typeIdentifiersHex].hex_pub_key_length != (contentAloneHex.length - identifiersStart * 2 - identifiersLength *2 - 8))
		return handle("wrong key length");
```

**File:** signature.js (L190-198)
```javascript
// Curves that are safe to use across all deployment targets.
// All other curves in objSupportedPemTypes are blocked for new AAs after pemCurvesFixMci.
var objSafePemTypes = new Set([
	'06072a8648ce3d020106082a8648ce3d030107', // prime256v1 (P-256)
	'06072a8648ce3d020106052b81040021',        // secp224r1  (P-224)
	'06072a8648ce3d020106052b81040022',        // secp384r1  (P-384)
	'06072a8648ce3d020106052b8104000a',        // secp256k1  (verified via secp256k1 npm, not OpenSSL)
	'06092a864886f70d0101010500',              // RSA (PKCS #1)
]);
```

**File:** formula/evaluation.js (L1704-1734)
```javascript
			case 'is_valid_sig':
				var message = arr[1];
				var pem_key = arr[2];
				var sig = arr[3];
				evaluate(message, function (evaluated_message) {
					if (fatal_error)
						return cb(false);
					if (!ValidationUtils.isNonemptyString(evaluated_message))
						return setFatalError("bad message string in is_valid_sig", { arr }, false, cb);
					evaluate(sig, function (evaluated_signature) {
						if (fatal_error)
							return cb(false);
						if (!ValidationUtils.isNonemptyString(evaluated_signature))
							return setFatalError("bad signature string in is_valid_sig", { arr }, false, cb);
						if (evaluated_signature.length > 1024)
							return setFatalError("signature is too large", { arr }, false, cb);
						if (!ValidationUtils.isValidHexadecimal(evaluated_signature) && !ValidationUtils.isValidBase64(evaluated_signature))
							return setFatalError("bad signature string in is_valid_sig", { arr }, false, cb);
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
					});
				});
				break;
```
