### Title
ECDSA Signature Malleability in `is_valid_sig()` secp256k1 PEM Verification Path Enables Replay of AA/Address Anti-Replay Nonces - (File: signature.js)

### Summary
The `verifyMessageWithSecp256k1PemPubKey` function in `signature.js` explicitly normalizes any supplied secp256k1 signature to its canonical low-S form before verification. Because ECDSA signatures are inherently malleable (for every valid `(r, s)` there exists an equally valid `(r, n-s)`), and the code accepts *either* form and treats them as the same normalized signature, anyone who has observed one valid signature can trivially derive a second, distinct signature blob that is also accepted as valid — without access to the private key. This is reachable from oscript's `is_valid_sig()` function, which is usable both in AA formulas and in ordinary address definitions.

### Finding Description
`signature.js` exposes two secp256k1 verification code paths:

1. The plain `verify()` function (used for unit "sig" authentifiers, device messages, hub logins) calls `ecdsa.ecdsaVerify(signature, hash, pubkey)` directly with no normalization step: [1](#0-0) 

2. `verifyMessageWithSecp256k1PemPubKey`, used by the `is_valid_sig` (and transitively `vrf_verify` for non-RSA keys) oscript formula function, explicitly calls `ecdsa.signatureNormalize(rawCompact)` before calling `ecdsaVerify`: [2](#0-1) 

By normalizing the signature *prior to* verification, the function accepts both the canonical low-S signature `(r, s)` and its malleable twin `(r, n-s)` as equally valid for the exact same message and public key. Deriving `(r, n-s)` from `(r, s)` requires only a single modular subtraction (`s' = n - s`) and no knowledge of the private key.

This path is reachable via `formula/evaluation.js`'s `is_valid_sig` case, which any AA author (or, since the restriction only applies to `is_valid_signed_package`, any address-definition/oscript author) can invoke: [3](#0-2) 

Note that `is_valid_sig` is not restricted to AA-only usage the way `is_valid_signed_package` is: [4](#0-3) 

### Impact Explanation
`is_valid_sig()` is a general-purpose primitive intended to let AA/oscript authors validate arbitrary externally-supplied signatures over arbitrary messages (e.g., off-chain vouchers, oracle attestations, one-time claim tokens, escrow-release authorizations). A very common and natural pattern for such constructs is to use the signature bytes themselves (or a hash of them) as a nonce/anti-replay key — e.g., an AA that stores `var['used_' + sig] = 1` to prevent a claim/voucher from being redeemed twice. Because the verification path malleates any accepted signature into two independently-distinct valid bit strings for the same message and key, an attacker (or the same legitimate signer replaying the funds they already claimed) can compute the second variant `(r, n-s)` themselves and resubmit it. The "already used" check keyed on the literal signature bytes will not recognize this as a repeat, allowing the same authorization to be redeemed a second time — resulting in double redemption of AA-held funds/vouchers (AA fund loss) or bypass of a one-time-use address/definition authorization.

### Likelihood Explanation
This is directly reachable by any unprivileged AA author or definition author who chooses to use `is_valid_sig()` for one-time-authorization patterns keyed on the raw signature — a design pattern that is natural and likely to be used given the primitive's stated purpose (verifying external signatures inside oscript). No special privilege, hub/peer compromise, or node cooperation is required; the malleable signature can be derived purely offline from any one previously-observed valid signature.

### Recommendation
In `verifyMessageWithSecp256k1PemPubKey`, do not silently normalize attacker-supplied signatures before verification. Instead, verify the signature exactly as submitted (reject if it is not already in canonical low-S form), mirroring the behavior of the non-malleable `verify()` function used for standard "sig" authentifiers. If normalization is required for signature-format compatibility (e.g., accepting DER-encoded input), perform the DER→compact conversion but reject (rather than silently normalize) any signature whose `s` value is not already canonical/low-S, so that only one of the two malleable variants is ever accepted.

### Proof of Concept
1. An AA author deploys an AA that accepts a secp256k1-signed voucher via oscript: `is_valid_sig(message, pem_key, trigger.data.sig)`, and, upon success, marks the voucher as redeemed by storing `var['redeemed_' || trigger.data.sig] = 1`, guarding future redemptions with `require(!var['redeemed_' || trigger.data.sig])`.
2. A legitimate voucher holder (or an observer of the trigger unit, since triggers/units are public) obtains one valid signature `(r, s)` for the voucher message.
3. The attacker computes the malleable twin signature `s' = n - s` (trivial arithmetic, `n` is the public secp256k1 curve order) and re-encodes it as a new signature blob `(r, s')`.
4. The attacker submits a new AA trigger with `sig = (r, s')`. `verifyMessageWithSecp256k1PemPubKey` in `signature.js` normalizes `(r, s')` back to the canonical low-S form (identical to what `(r, s)` normalized to) and `is_valid_sig` returns `true`.
5. Because `var['redeemed_' || sig]` is keyed by the literal signature bytes, which differ between `(r, s)` and `(r, s')`, the redemption check does not detect the replay, and the voucher is redeemed a second time, draining additional AA funds.

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

**File:** formula/validation.js (L815-842)
```javascript
			case 'is_valid_signed_package':
				if (!bAA && (mci >= constants.pemCurvesFixMci || require('../storage.js').getMinRetrievableMci() >= constants.pemCurvesFixMci)) // sign transactions instead, otherwise signer definition can call is_valid_signed_package again
					return cb(op + ' in non-AA');
				complexity++;
				var signed_package_expr = arr[1];
				var address_expr = arr[2];
				evaluate(signed_package_expr, function (err) {
					if (err)
						return cb(err);
					evaluate(address_expr, cb);
				});
				break;

			case 'is_valid_sig':
				complexity+=1;
				var message = arr[1];
				var pem_key = arr[2];
				var sig = arr[3];
				evaluate(message, function (err) {
					if (err)
						return cb(err);
					evaluate(pem_key, function (err) {
						if (err)
							return cb(err);
						evaluate(sig, cb);
					});
				});
				break;
```
