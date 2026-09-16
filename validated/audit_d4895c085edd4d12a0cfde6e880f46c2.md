### Title
ECDSA signature malleability accepted by `verifyMessageWithSecp256k1PemPubKey` breaks anti-replay assumptions in `is_valid_sig`/`vrf_verify` — ([File: signature.js])

### Summary
The Sherlock report flags a project for relying on an OpenZeppelin `ECDSA` build vulnerable to signature malleability (a signer's message can be validated under two different valid `(r,s)` encodings, breaking any logic that assumes a signature is a unique, one-time token). The same bug **class** exists natively in ocore's own crypto helper `signature.js`, specifically in the secp256k1-over-PEM verification path used by the oscript primitives `is_valid_sig` and `vrf_verify`, which any AA author's contract can expose to an unprivileged trigger sender.

### Finding Description
`signature.js` contains two different verification paths for secp256k1 signatures:

- The "canonical" address-authentifier path, `verify()`, is called with the exact bytes provided in the `authentifiers` for a `['sig', ...]` definition, with no normalization step: [1](#0-0) 

- The PEM/secp256k1 path used by oscript, `verifyMessageWithSecp256k1PemPubKey()`, explicitly imports **and normalizes** whatever signature encoding is supplied (`ecdsa.signatureImport` for DER, then `ecdsa.signatureNormalize`) before calling `ecdsaVerify`: [2](#0-1) 

This function is reachable from oscript through `is_valid_sig` and `vrf_verify`, evaluated in AA trigger handling with attacker-controlled `message`, `pem_key`, and `signature` arguments coming straight from `trigger.data`: [3](#0-2) [4](#0-3) 

Because `signatureNormalize` forces any high-`S` signature into its low-`S` canonical counterpart before verification, **both** `s` and `n - s` encodings of the same `(message, pubkey)` pair validate as `true`. This is exactly the malleability defect referenced in the external report — the difference is that here it is *intentionally* introduced by the ocore helper itself for the secp256k1-PEM branch, rather than inherited from a vulnerable third-party version. This creates an inconsistency with the base `sig` authentifier path (`verify()`), which does not normalize and therefore does not exhibit the same malleability.

### Impact Explanation
`is_valid_sig`/`vrf_verify` are documented, general-purpose oscript primitives meant for AA authors to validate externally-issued signed messages (vouchers, oracle attestations, order tickets, off-chain authorizations, etc.). A very common and natural AA pattern for anti-replay/one-time-use protection is to key a `var[...]` "used" flag off a hash that includes the signature bytes themselves (e.g. `sha256(message || signature)`) rather than solely off application-level nonce fields — because the primitive is a raw `is_valid_sig(message, pem_key, signature)` and does not expose or guarantee signature canonicalization to the AA author. With this normalization behavior, an attacker who has observed one valid signature for a message can trivially derive a second, distinct-but-equally-valid signature (flip `S` to `n - S`, or re-encode DER) for the exact same authorization, and resubmit it in a new trigger. Any AA that uses the raw signature (or its hash) as the uniqueness key for a one-time voucher/authorization will accept the resubmission as a "different" signature and re-execute the payout/state transition — directly enabling **double-spend of AA funds** for that class of contracts, with no special privilege required by the attacker (any trigger sender can invoke `is_valid_sig`/`vrf_verify` and craft the second malleated signature themselves once the first one becomes public, e.g. from a broadcast unit).

### Likelihood Explanation
Likelihood depends on AA author's replay-protection design; contracts that key uniqueness off `message` content/nonce fields (as sampled in `test/samples/order_book_exchange.oscript` and `payment_channels.oscript`, which use `is_valid_signed_package`/`sig`-authentifier path — not affected) are safe. But `is_valid_sig`/`vrf_verify` are documented, general primitives specifically intended for arbitrary external signature verification use-cases (oracle attestations, vouchers) where authors are not guided to avoid keying on signature bytes, and the malleability is silent — normal test vectors (`test/pem_sig.test.js`) don't exercise or flag it. Given ocore explicitly ships two different behaviors (strict vs. normalizing) for the "same" cryptographic primitive without documenting the difference, this is a realistic and likely-to-be-hit trap for AA authors, triggerable by any address able to send a unit/trigger.

### Recommendation
Do not silently normalize attacker-supplied signatures before verification in `verifyMessageWithSecp256k1PemPubKey`. Instead, reject non-canonical (high-`S`) signatures outright (mirror the behavior of the base `sig` authentifier's `verify()`), i.e. verify the signature as given and fail if it does not already satisfy `signatureNormalize(sig) === sig`, rather than transparently rewriting it into canonical form. At minimum, document in `is_valid_sig`/`vrf_verify` specification that two distinct signature byte-strings can be valid for the same `(message, pubkey)`, and that AA authors must never use raw signature bytes (or their hash) as a replay/uniqueness key — only the signed message content should be used for that purpose.

### Proof of Concept
1. Sign a message `m` with secp256k1 private key `k`, producing canonical `(r, s)`.
2. Compute the malleated signature `(r, n - s)` where `n` is the secp256k1 curve order (pure arithmetic, no private key needed).
3. Call oscript `is_valid_sig(m, pem_pubkey, sig1)` → `true`, and `is_valid_sig(m, pem_pubkey, sig2)` → `true`, verified via `signature.js`'s `verifyMessageWithSecp256k1PemPubKey`, both going through `ecdsa.signatureNormalize` before `ecdsaVerify`: [5](#0-4) 
4. In any AA that stores `var[sha256(m || sig)] = true` to mark a voucher/authorization as consumed, submit trigger 1 with `sig1` to claim the payout, then submit trigger 2 with `sig2` for the same `m` — the "used" check keyed on the full signature bytes does not match, and the payout logic executes a second time, draining AA funds.

### Citations

**File:** signature.js (L16-25)
```javascript
function verify(hash, b64_sig, b64_pub_key){
	try{
		var signature = Buffer.from(b64_sig, "base64"); // 64 bytes (32+32)
		return ecdsa.ecdsaVerify(signature, hash, Buffer.from(b64_pub_key, "base64"));
	}
	catch(e){
		console.log('signature verification exception: '+e.toString());
		return false;
	}
};
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
