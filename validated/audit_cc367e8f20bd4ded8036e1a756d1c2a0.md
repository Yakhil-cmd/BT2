This confirms the finding: `is_valid_sig` in `formula/evaluation.js` calls `signature.validateAndFormatPemPubKey(evaluated_pem_key, "any", ...)` which only enforces a maximum key size (736 base64 chars ≈ RSA-4096) but never a minimum RSA modulus size. RSA keys as small as 512 bits pass validation and successful signature verification (as confirmed by the test suite's `is_valid_sig RSA 512 bits` tests), and `objSafePemTypes` in `signature.js` unconditionally whitelists the RSA OID regardless of key size, so even after `pemCurvesFixMci` (which was specifically added to block weak elliptic curves) small RSA keys remain accepted for AAs.

### Title
Missing minimum RSA key-size check in `is_valid_sig`/`vrf_verify` PEM key validation allows forgeable weak-RSA authentication in AAs - (File: `signature.js`)

### Summary
`signature.validateAndFormatPemPubKey()` enforces only a maximum PEM content length (`contentAloneB64.length > 736`, sized for RSA‑4096) and, after `pemCurvesFixMci`, blocks weak elliptic curves via `objSafePemTypes`. However RSA (OID `06092a864886f70d0101010500`) is unconditionally included in `objSafePemTypes` regardless of modulus size, and there is no minimum bit-length check anywhere in `validateAndFormatPemPubKey`. Any RSA key — including trivially factorable sizes like 512 or 700 bits — is accepted by `is_valid_sig(message, pem_key, signature)` and `vrf_verify(seed, proof, pem_key)`, both reachable from unprivileged AA trigger data and oscript formulas. [1](#0-0) [2](#0-1) 

### Finding Description
`is_valid_sig` in `formula/evaluation.js` evaluates attacker-controlled `pem_key`/`signature`/`message` from `trigger.data` (or any expression), passes the PEM key through `validateAndFormatPemPubKey(evaluated_pem_key, "any", ..., bPostPemCurvesFix)`, then verifies the signature with `signature.verifyMessageWithPemPubKey`. [3](#0-2) 

`validateAndFormatPemPubKey` checks the DER structure, algorithm OID, and (post-fix) that the OID is in `objSafePemTypes`, but it never inspects the RSA modulus size — the only size-related check is the overall base64 length cap of 736 chars. [4](#0-3) 

`objSafePemTypes`, the whitelist used for post-`pemCurvesFixMci` AAs, includes the RSA OID with no key-size qualifier at all, unlike the EC curves which were deliberately restricted to P-256/P-224/P-384/secp256k1. [5](#0-4) 

The test suite itself demonstrates that 512-bit and 700-bit RSA keys are accepted and verified successfully by `is_valid_sig`, confirming there is no lower bound enforced. [6](#0-5) [7](#0-6) 

This is the same bug class as the reported CVE (weak/undersized cryptographic key permitted, enabling brute-force/factorization break of the key) — here in a production oscript primitive rather than a demo script.

### Impact Explanation
`is_valid_sig`/`vrf_verify` are typically used inside AA definitions or address/asset spending conditions as an authentication or oracle-proof mechanism (e.g., verifying externally-signed data feeds, VRF proofs, or attestations that gate fund release). An attacker who controls or influences which PEM key is registered as the trusted key (or who can get a victim AA/definition author to use a "convenient" small RSA key) can factor a 512–1024 bit RSA modulus with commodity resources, recover the private key, and forge arbitrary signatures accepted by `is_valid_sig`. Any AA logic that conditions fund release, data-feed acceptance, or oscript branching on `is_valid_sig`/`vrf_verify` with such a key can be spoofed, leading to unauthorized spending or fund loss from the AA.

### Likelihood Explanation
Requires an AA (or address/asset condition) design that trusts a weak RSA public key via `is_valid_sig`/`vrf_verify` — this is a plausible and encouraged usage pattern (external attestations, VRF proofs) and nothing in validation prevents it; the vulnerability is purely in the platform's missing lower-bound check, not in AA author diligence. The `pemCurvesFixMci` precedent shows the project itself recognized and fixed the analogous EC weak-curve problem but left the RSA path unbounded.

### Recommendation
Add a minimum RSA modulus size check (e.g., ≥2048 bits) in `validateAndFormatPemPubKey` in `signature.js`, applied at least for `bPostPemCurvesFix` (and ideally introduce a similar new upgrade MCI gate for RSA, mirroring the EC curve fix), rejecting PEM keys with `algo === 'RSA'` whose modulus is below the safe threshold.

### Proof of Concept
1. Generate a 512-bit RSA key pair (trivially factorable, e.g., with `openssl genrsa 512`).
2. Craft an AA (or `sig`/`hash`-free spending condition/data-feed check) whose oscript formula includes `is_valid_sig(message, pem_key_512, signature)`, as exercised by `test/pem_sig.test.js` "is_valid_sig RSA 512 bits" cases.
3. Post a unit/trigger; `formula/evaluation.js`'s `is_valid_sig` handler accepts the key because `validateAndFormatPemPubKey` only checks structure/OID/length-cap, not modulus strength. [8](#0-7) 
4. Factor the 512-bit modulus offline (well within reach of modern factoring tools/cloud compute), recover the RSA private key, and produce forged signatures that `is_valid_sig` will accept, bypassing the intended authentication/attestation check.

### Citations

**File:** signature.js (L117-182)
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

**File:** test/pem_sig.test.js (L826-844)
```javascript
test.cb('is_valid_sig RSA 700 bits', t => {
	var trigger = { data: 
		{
			pem_key: "-----BEGIN PUBLIC KEY-----\n\
			MHMwDQYJKoZIhvcNAQEBBQADYgAwXwJYDFoRKRkIqYRLtowxgBCrrS92DpoeTcnq\n\
			UOi3ixzFxhWrQ2q64LYiczp6ESHAy1DI9p8LWjMmhMpW6kIIRGPiE6txmzbCJmIy\n\
			kvSqAQ+617L1TejNZYpTAQIDAQAB\n\
			-----END PUBLIC KEY-----",
			message: "44e8fd580c05c2ea8af20fbec3c83c6314baa7c05ec4e147fd21fd613eba73ce",
			signature: "A8PSEg4KkDHhUmSBwXtMG1sXc8dPmSK+ls85+MM+utTwKuDZKCjH0jHIArLGoQS1/enf1sqduu+0GbHgz2AZCx+knMM/pqZ0RvJwAJqpk0fjaGqcDf7tXw=="
		}
	};
	
	evalFormulaWithVars({ conn: null, formula:  "is_valid_sig(trigger.data.message, trigger.data.pem_key, trigger.data.signature)", trigger: trigger, objValidationState: objValidationState, address: 'MXMEKGN37H5QO2AWHT7XRG6LHJVVTAWU' }, (res, complexity) => {
		t.deepEqual(res, true);
		t.deepEqual(complexity, 2);
		t.end();
	})
});
```

**File:** test/pem_sig.test.js (L2223-2236)
```javascript
test.cb('sign message with RSA 512 bits (deterministic)', t => {
	var signature = asymSig.signMessageWithRsaPemPrivKey("zouplaboom", null, "-----BEGIN RSA PRIVATE KEY-----\n\
	MIIBOgIBAAJBALpW4O8MZitz/kPWqqs0H/Rip69LH0a5isg2o7mFZJzirzmN2lA3\n\
	eWNfiNkW1o9RFOsjQ9NpBDj6XHgyOMMU9PECAwEAAQJAXSsTTHLmotNcTo8GxpNJ\n\
	Zufs77if6rzap0CqnBgWNlpG2YIPZqDO9ZmCtqZl4xxO8ynp74PFzu62kMP4nHcA\n\
	AQIhANq7vgLgKzlrB4djg75kOJNtWAC2IkHrcWIGg74EYSmdAiEA2hY+BZ6r1MuH\n\
	ENVA3xgUHV7ZiOprV6gf73K5Z/3UkmUCIHnpL9NMe+rps22LUo9YLoxE4kqrONbC\n\
	0hQPi3fp2vmlAiEAjHp9UxNlLfo4M3Cai9ovwseBKn+Ny3YBtDTbFxBbKD0CIA5s\n\
	8UgPeZrMh+R1uihikqny8p3KGeJopjerZ9IQpnN2\n\
	-----END RSA PRIVATE KEY-----\n\
")
	t.deepEqual(signature, "as2PhM4+/GfvWZjmH7y3S5ZDm0+mW2y2u2TSSq8Ty3l61GH/kB8gHNrRaezLyrW7PTjOHjJdl8EH7GQ7DrgXlQ==");
	t.end();
});
```
