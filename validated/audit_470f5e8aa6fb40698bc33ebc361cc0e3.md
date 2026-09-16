### Title
Cross-implementation ECDSA verification inconsistency in oscript `is_valid_sig`/`vrf_verify` (mixed OpenSSL vs. secp256k1-npm backends) can cause AA validation to diverge between nodes - (File: signature.js)

### Summary
`is_valid_sig` and `vrf_verify` in oscript let any unprivileged AA author or trigger sender supply an arbitrary PEM public key and signature, which is checked with `signature.verifyMessageWithPemPubKey` [1](#0-0) . Depending on the curve embedded in the PEM key, verification is routed to two structurally different cryptographic backends: Node's native OpenSSL `crypto.createVerify` for P‑256/P‑384/P‑224/RSA, versus the `secp256k1` npm library (libsecp256k1 bindings) for the `secp256k1` curve [2](#0-1) . This mirrors the CL‑2020‑18 bug class: the same "signature valid?" question can receive different answers depending on which underlying crypto implementation a given node/OS/OpenSSL build uses, because DER/ASN.1 signature parsing strictness and malleability handling differ across libraries and OpenSSL versions.

### Finding Description
`verifyMessageWithPemPubKey` dispatches based solely on the AlgorithmIdentifier OID found in the attacker-supplied PEM key [2](#0-1) :
- For `secp256k1`, it manually extracts the raw pubkey point and calls `ecdsa.ecdsaVerify` from the `secp256k1` npm package after `signatureNormalize` (enforcing canonical low-S form) [3](#0-2) .
- For every other curve accepted by `validateAndFormatPemPubKey` (P‑256, P‑224, P‑384, RSA, and pre-fix legacy curves such as brainpool/prime192/prime239/secp112/wtls variants), verification falls through to Node's built-in `crypto.createVerify('SHA256').verify(...)`, which delegates DER parsing and signature validity entirely to the linked OpenSSL library [4](#0-3) , with **no equivalent canonicalization or strict-DER enforcement** applied.

`validateAndFormatPemPubKey` only restricts the *curve* via `objSafePemTypes` after `pemCurvesFixMci` [5](#0-4) , but this restriction narrows the *key type*, not the *signature encoding*. Historically, ASN.1 BER-vs-DER ambiguity in OpenSSL's ECDSA/RSA signature parsers has led to divergent accept/reject behavior across OpenSSL versions/builds (extra zero padding, indefinite-length encodings, or non-minimal integer encodings being accepted by some OpenSSL releases and rejected by others). Because `is_valid_sig`/`vrf_verify` results feed directly into AA state-variable computations and bounce decisions via `evaluate` in `formula/evaluation.js`, a signature crafted to exploit this OpenSSL-version-dependent leniency would validate as `true` on nodes running one OpenSSL build and `false` on nodes running another, exactly as different BLS libraries (herumi/py_ecc/milagro_bls/blst) disagreed on the same aggregate signature test vector in CL-2020-18.

### Impact Explanation
If two nodes evaluate the same AA trigger and reach different boolean results for `is_valid_sig`/`vrf_verify`, they will compute different AA responses (different outputs, different state variable updates, or accept vs. bounce the trigger). Since AA execution results are consensus-critical (they determine unit content and stability), this leads to **node disagreement on unit/AA validity**, which can fork network consensus on which units are valid — one of the explicitly accepted high-severity outcomes.

### Likelihood Explanation
Triggering requires only posting an AA trigger unit containing an oscript formula invoking `is_valid_sig`/`vrf_verify` with attacker-chosen PEM key/signature/message — reachable by any unprivileged AA author or trigger sender [6](#0-5) . However, actually producing a signature that different OpenSSL builds interpret differently requires finding a specific low-level DER-encoding edge case that is accepted by one deployed OpenSSL version and rejected by another currently deployed among the node fleet — this is plausible in principle (well documented ASN.1 leniency bugs exist historically in OpenSSL) but not proven here without testing against the actual range of OpenSSL versions used by ocore full nodes.

### Recommendation
- Enforce strict DER validation (reject any signature that doesn't re-encode byte-for-byte to the same DER the parser derives) before calling `crypto.createVerify(...).verify()` for all non-secp256k1 curves, removing reliance on OpenSSL's own leniency.
- Alternatively, pin/vendor a single deterministic ECDSA/RSA verification library (as already done for secp256k1 via the npm package) for all supported curves instead of delegating to the platform's OpenSSL, removing the version-dependent behavior entirely.
- Add signature-malleability/canonical-form tests across the currently supported curve set analogous to `test/pem_sig.test.js`, specifically targeting non-canonical DER encodings, to confirm consistent accept/reject behavior across supported Node.js/OpenSSL versions.

### Proof of Concept
Conceptual (not exploited end-to-end here, pending confirmation of an actual divergent OpenSSL version pair):
1. Attacker crafts a P‑256 (or RSA) key/message pair and a signature encoded with a non-minimal/non-canonical DER form known to be accepted by one common OpenSSL release.
2. Attacker submits an AA trigger whose oscript formula includes `is_valid_sig(message, pem_key, signature)` [1](#0-0) , using this malformed signature.
3. Nodes running the OpenSSL build that accepts the malformed encoding evaluate the AA formula as `true`; nodes running a stricter OpenSSL build evaluate it as `false`.
4. The AA response unit (and hence stability status) diverges between these two node populations, producing a validity/consensus disagreement.

### Citations

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

**File:** signature.js (L50-70)
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
}
```

**File:** signature.js (L167-198)
```javascript
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

	//we add back header and footer
	pem_key =	"-----BEGIN PUBLIC KEY-----" + "\n";
	pem_key += contentAloneB64+"\n";
	pem_key += "-----END PUBLIC KEY-----";
	return handle(null,pem_key);
}

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
