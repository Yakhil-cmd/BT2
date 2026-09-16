## #Vulnerability found

### Title
Signature malleability in `is_valid_sig()` allows bypass of "signature-used" replay protection in AA authorizations - (File: `signature.js`, `formula/evaluation.js`)

### Summary
The oscript function `is_valid_sig(message, pem_key, signature)`, reachable by any AA trigger sender, verifies secp256k1 signatures via `signature.verifyMessageWithSecp256k1PemPubKey()`, which accepts a signature in either raw 64-byte compact form or DER form, and in either hex or base64 encoding, before normalizing and verifying it [1](#0-0) . Because several distinct byte-strings can represent the same underlying `(r, s)` pair (DER vs. compact encoding, hex vs. base64, or the mirrored `s`/`n-s` value inherent to ECDSA before normalization), an AA that implements "signature already used" replay protection by storing the raw signature string itself (rather than the message hash, `r` value, or a nonce) can be bypassed by resubmitting a re-encoded but equivalent signature.

### Finding Description
`is_valid_sig` is dispatched from the oscript evaluator and is directly reachable from any AA trigger, since it only requires a message string, a PEM public key, and a signature string supplied in the trigger data [2](#0-1) . The signature argument is only checked for length and being valid hex-or-base64 - no canonical-encoding check is enforced [3](#0-2) .

The actual verification path `verifyMessageWithSecp256k1PemPubKey` imports non-64-byte inputs via `ecdsa.signatureImport` (DER decoding) and always calls `ecdsa.signatureNormalize` before `ecdsaVerify` [4](#0-3) . This means:
- The same logical signature can be supplied as raw compact bytes or as DER-encoded bytes, in hex or base64, and all forms validate successfully.
- Because normalization is applied only internally for verification purposes, the raw signature string that an AA might store as a "used" marker is not canonicalized before being persisted, so different encodings of the identical authorization are treated as different strings.

This mirrors the OpenZeppelin `ECDSA.recover`/`tryRecover` malleability class cited in the report: functions accepting flexible single-argument signature formats are unsafe for any mechanism that marks "the signature itself" (rather than the signed message/nonce) as consumed.

### Impact Explanation
An AA author who implements an authorization/voucher scheme (e.g., "spend once per off-chain-signed permit") using `is_valid_sig` combined with a `var[...]['used_' || signature]` style dedup check in oscript is exposed to signature replay: a user can resubmit the same authorization encoded differently (DER vs. compact, hex vs. base64) and have it validate as a "new" signature, allowing repeated triggering of AA logic that was intended to execute only once per signed message (e.g., double withdrawal, double-crediting, or bypassing a one-time-use gate). This can lead to AA fund loss.

### Likelihood Explanation
Exploitability depends on an AA author's specific use of `is_valid_sig` for uniqueness tracking keyed on the raw signature bytes rather than the message/nonce. Given `is_valid_sig` is a documented and available oscript primitive intended precisely for building custom signature-based authorization schemes in AAs, and the encoding flexibility is not restricted or documented as a caveat, this is a realistic misuse pattern for AA developers, and any AA trigger sender can supply the alternate encoding without special privileges.

### Recommendation
- In `signature.verifyMessageWithSecp256k1PemPubKey` (and `verifyMessageWithPemPubKey`), require and only accept a single canonical signature encoding (e.g., canonical low-S compact 64-byte form) for `is_valid_sig`, rejecting DER or non-canonical/high-S inputs rather than silently normalizing them.
- Alternatively, expose a canonicalized signature (or its hash) to oscript so AA authors can dedup on a normalized value, and document that `is_valid_sig`'s raw `signature` argument is malleable and must not be used directly as a replay-protection key.

### Proof of Concept
1. An AA author writes an oscript rule permitting a payout the first time a valid `is_valid_sig(message, pem_key, signature)` is presented for a given `message`, storing `var['used_' || signature] = 1` to prevent replay.
2. Attacker submits trigger #1 with signature `sig_compact` (64-byte raw form, low-S) — payout executes, `used_' || sig_compact` is recorded.
3. Attacker computes the equivalent DER-encoded (or hex vs base64 re-encoded, or high-S `n-s`) representation `sig_der` of the same `(r,s)` pair.
4. Attacker submits trigger #2 with `signature = sig_der`. `verifyMessageWithSecp256k1PemPubKey` imports/normalizes it and validates successfully [4](#0-3) , but `used_' || sig_der` is a different string than `used_' || sig_compact`, so the dedup check passes and the payout executes again — double payout from a single signed authorization.

### Citations

**File:** signature.js (L50-66)
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
