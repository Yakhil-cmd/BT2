### Title
Missing Minimum RSA Modulus Length Validation in `validateAndFormatPemPubKey` Allows Forgeable Signatures via `is_valid_sig`/`vrf_verify` - (File: signature.js)

### Summary
The oscript primitives `is_valid_sig` and `vrf_verify`, which any Autonomous Agent (AA) can use to verify externally supplied signatures/proofs against a PEM-encoded public key, rely on `validateAndFormatPemPubKey` to sanity-check the supplied key before verification. This function enforces only an upper bound on the encoded key size and never enforces a minimum RSA modulus bit-length (nor any exponent-strength check), so cryptographically weak, factorable RSA keys (e.g. 512–700 bits) are accepted as valid keys for on-chain signature verification.

### Finding Description
`validateAndFormatPemPubKey` parses the DER-encoded PEM key, validates the ASN.1 structure/OID, and enforces a maximum encoded length ("largest is RSA 4096 bits"), but performs no minimum-size check for RSA keys: [1](#0-0) 

The only length check that exists (`hex_pub_key_length`) is applied exclusively to ECDSA curves; for RSA keys (`objSupportedPemTypes[...].algo == "RSA"`) no equivalent minimum-modulus check is performed: [2](#0-1) 

This is exercised end-to-end by `is_valid_sig` and `vrf_verify` in the oscript evaluator, which call `validateAndFormatPemPubKey` with the attacker/user-controlled key material and then verify the signature/proof with `verifyMessageWithPemPubKey`: [3](#0-2) [4](#0-3) 

The test suite confirms that an RSA key far below any secure size (700 bits, well under NIST/2048-bit recommendations) is accepted and a signature over it verifies successfully: [5](#0-4) 

There is no analog of `_hasNonZeroExponent`/minimum-exponent check either: the public exponent embedded in the DER is never inspected, and RSA verification is delegated entirely to Node's `crypto.createVerify`/`verify.verify`, with no independent modulus-strength or oddness validation: [6](#0-5) 

### Impact Explanation
`is_valid_sig` and `vrf_verify` are general-purpose oscript primitives available to any AA author to implement authorization/authentication schemes (e.g., federated oracle attestations, off-chain co-signer/bridge schemes, "register a public key now, verify signed messages against it later"). Because the protocol layer performs no minimum RSA modulus enforcement, an AA design that trusts a participant-supplied or externally-registered RSA public key for authorizing sensitive actions (e.g., releasing AA funds, approving a payout, attesting oracle data) can be undermined by a participant intentionally registering a small/weak RSA key. Such a key can be factored off-chain (trivial for 512–700-bit RSA), after which an attacker can forge arbitrary "valid" signatures/proofs that the AA will accept as authentic, leading to unauthorized fund release or arbitrary state transitions gated by these primitives.

### Likelihood Explanation
Exploitability requires an AA design that lets a party register or supply their own RSA public key to be used later for signature/proof verification via `is_valid_sig`/`vrf_verify` — a legitimate and foreseeable oscript usage pattern given these primitives exist specifically to support such schemes. Because the protocol gives no warning or enforcement of key strength, AA authors have no built-in protection and may reasonably assume any accepted PEM key is "safe" the same way the underlying RSA library normally rejects insecure key sizes at generation time (Node/OpenSSL typically won't generate <512-bit RSA keys by default, but nothing prevents an attacker from crafting one for this specific purpose). No node-level or network-level assumptions are required — this is fully reachable from a single AA definition plus a single subsequently posted trigger.

### Recommendation
In `validateAndFormatPemPubKey` (signature.js), when `objSupportedPemTypes[typeIdentifiersHex].algo == "RSA"`, parse the modulus from the DER structure and reject keys with modulus bit-length below a secure minimum (e.g., 2048 bits), consistent with the fix applied upstream in the referenced Matter Labs report. Additionally consider enforcing a minimum/allow-listed public exponent (e.g., ≥ 65537) to mitigate low-exponent attacks, mirroring `_hasNonZeroExponent`/exponent hardening in the cited analog.

### Proof of Concept
1. An AA is authored that, upon a `register_key` trigger, stores a caller-provided PEM public key (`trigger.data.pem_key`) in a state variable, intending to later authenticate signed messages from that registered key via `is_valid_sig(message, state[...].pem_key, signature)`.
2. Attacker registers a deliberately weak RSA key (e.g., 512 or 700 bits) as demonstrated to be accepted by the existing test `is_valid_sig RSA 700 bits`, which returns `true` for a valid signature check with no length rejection: [5](#0-4) .
3. Attacker factors the weak modulus offline (computationally trivial for this size) and derives the private key.
4. Attacker forges signatures over arbitrary messages/triggers that the AA will treat as authentic via `is_valid_sig`, bypassing the intended authorization and triggering unauthorized fund transfers or state changes controlled by that check.

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

**File:** signature.js (L117-132)
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
```

**File:** signature.js (L173-188)
```javascript
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

**File:** formula/evaluation.js (L1736-1766)
```javascript
			case 'vrf_verify':
				var seed = arr[1];
				var proof = arr[2];
				var pem_key = arr[3];
				evaluate(seed, function (evaluated_seed) {
					if (fatal_error)
						return cb(false);
					if (!ValidationUtils.isNonemptyString(evaluated_seed))
						return setFatalError("bad seed in vrf_verify", { arr }, false, cb);
					evaluate(proof, function (evaluated_proof) {
						if (fatal_error)
							return cb(false);
						if (!ValidationUtils.isNonemptyString(evaluated_proof))
							return setFatalError("bad proof string in vrf_verify", { arr }, false, cb);
						if (evaluated_proof.length > 1024)
							return setFatalError("proof is too large", { arr }, false, cb);
						if (!ValidationUtils.isValidHexadecimal(evaluated_proof))
							return setFatalError("bad signature string in vrf_verify", { arr }, false, cb);
						evaluate(pem_key, function (evaluated_pem_key) {
							if (fatal_error)
								return cb(false);
							signature.validateAndFormatPemPubKey(evaluated_pem_key, "RSA", function (error, formatted_pem_key){
								if (error)
									return setFatalError("bad PEM key in vrf_verify: " + error, { arr }, false, cb);
								var result = signature.verifyMessageWithPemPubKey(evaluated_seed, evaluated_proof, formatted_pem_key, bPostPemCurvesFix);
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
