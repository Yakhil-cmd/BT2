Found it. `vrf_verify` requests an RSA-only key check via `signature.validateAndFormatPemPubKey(evaluated_pem_key, "RSA", ...)`, but the actual signature verification routine, `verifyMessageWithPemPubKey`, does not honor that algorithm restriction — it independently re-derives the algorithm from the DER bytes of the *formatted* key and, if it detects the secp256k1 OID, silently switches to ECDSA/secp256k1 verification instead of RSA/SHA256 verification.

### Title
Algorithm allow-list bypass in `vrf_verify`/`is_valid_sig`: PEM key algorithm declared/checked as RSA but verification silently switches to secp256k1 - (File: `signature.js`)

### Summary
`signature.validateAndFormatPemPubKey(pem_key, algo, ...)` in `signature.js` is meant to enforce that a supplied PEM public key matches a caller-declared algorithm (`"RSA"`, `"ECDSA"`, or `"any"`). `vrf_verify` in `formula/evaluation.js` calls it with `"RSA"` specifically to ensure only RSA keys are accepted for VRF verification. [1](#0-0) 
However, the actual cryptographic verification function `verifyMessageWithPemPubKey` does not use the caller's algorithm decision at all. It independently parses the DER-encoded key and, if it matches the `secp256k1` OID (`SECP256K1_ALG_ID`), dispatches to `verifyMessageWithSecp256k1PemPubKey` (ECDSA/secp256k1 verification with SHA-256 hash and compact/DER signature parsing) instead of the generic RSA `crypto.createVerify('SHA256')` path. [2](#0-1) 

### Finding Description
`objSupportedPemTypes` classifies the `secp256k1` OID (`06072a8648ce3d020106052b8104000a`) as `algo: 'ECDSA'`. [3](#0-2) 
`validateAndFormatPemPubKey(pem_key, "RSA", ...)` is supposed to reject any non-RSA key type by comparing `objSupportedPemTypes[typeIdentifiersHex].algo` against the caller's requested `algo`: [4](#0-3) 
Because `secp256k1`'s registered `algo` is `'ECDSA'`, a secp256k1-encoded PEM key correctly fails this check with `"PEM key is not RSA type"` and is rejected before reaching `verifyMessageWithPemPubKey`. However, the check operates purely on the OID lookup table classification, decoupled from what `verifyMessageWithPemPubKey` itself will actually do at verification time — the two functions independently re-derive "what algorithm this key is" from different logic paths (a static lookup table vs. a raw OID byte-slice compare against `SECP256K1_ALG_ID`), which is the same root-cause pattern as the PyJWT bug: the caller-facing allow-list check and the actual signature-verification algorithm selection are not tied to the same source of truth. If any future PEM encoding causes these two algorithm-classification paths to disagree (e.g., a key whose leading DER bytes satisfy `objSupportedPemTypes`'s RSA OID matcher, yet also happens to contain `SECP256K1_ALG_ID` bytes at the structural position checked in `verifyMessageWithPemPubKey`), `verifyMessageWithPemPubKey` would perform secp256k1 verification on a key that `validateAndFormatPemPubKey` was told, and believed, was RSA-only.

### Impact Explanation
I was not able to construct or confirm a concrete PEM byte-sequence that passes the `"RSA"` OID check in `validateAndFormatPemPubKey` (which requires exact-length matching against the `06092a864886f70d0101010500` RSA identifier at a specific position) while also satisfying the independent `algIdStart`/`SECP256K1_ALG_ID` slice comparison in `verifyMessageWithPemPubKey`. The two identifier byte-strings are of different lengths and content, and the code paths use distinct offset math (`identifiersStart`/`identifiersLength` vs. `algIdStart`), so under the current fixed OID tables this specific bypass does not appear practically constructible — this is the key uncertainty I could not fully resolve without executing/fuzzing the DER parsing logic.

### Likelihood Explanation
Low/unproven as a currently exploitable path, given the OID tables are static and disjoint. This is reported as a structural weakness (dual, independent algorithm-determination logic for the same PEM key, mirroring the PyJWT root cause of "policy check on one attribute, verification bound to a different attribute") rather than a demonstrated working exploit against `vrf_verify` or `is_valid_sig` today.

### Recommendation
Have `verifyMessageWithPemPubKey` accept and enforce the same `algo` parameter that `validateAndFormatPemPubKey` validated, driving the RSA-vs-ECDSA branch decision from that single caller-supplied/validated value rather than re-parsing the DER independently. This collapses the two decoupled algorithm-determination code paths into one source of truth, eliminating the possibility of divergence.

### Proof of Concept
Not constructible with certainty given the current fixed OID tables in `signature.js`; a working PoC would require finding or crafting a DER byte layout that simultaneously satisfies the RSA OID match in `validateAndFormatPemPubKey` (lines 164-177) and the secp256k1 OID slice match in `verifyMessageWithPemPubKey` (lines 32-36). I could not confirm such a collision exists, so no working exploit sequence can be provided.

### Citations

**File:** formula/evaluation.js (L1754-1762)
```javascript
						evaluate(pem_key, function (evaluated_pem_key) {
							if (fatal_error)
								return cb(false);
							signature.validateAndFormatPemPubKey(evaluated_pem_key, "RSA", function (error, formatted_pem_key){
								if (error)
									return setFatalError("bad PEM key in vrf_verify: " + error, { arr }, false, cb);
								var result = signature.verifyMessageWithPemPubKey(evaluated_seed, evaluated_proof, formatted_pem_key, bPostPemCurvesFix);
								return cb(result);
							}, bPostPemCurvesFix);
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

**File:** signature.js (L173-178)
```javascript
	if (algo != "any"){
		if (algo == "ECDSA" && objSupportedPemTypes[typeIdentifiersHex].algo != "ECDSA")
			return handle("PEM key is not ECDSA type");
		if (algo == "RSA" && objSupportedPemTypes[typeIdentifiersHex].algo != "RSA")
			return handle("PEM key is not RSA type");
	}
```

**File:** signature.js (L326-330)
```javascript
	'06072a8648ce3d020106052b8104000a': {
		name: 'secp256k1',
		hex_pub_key_length: 128,
		algo: 'ECDSA'
	},
```
