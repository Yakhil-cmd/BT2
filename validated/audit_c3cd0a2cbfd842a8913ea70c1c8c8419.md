## Analog Found

### Title
Signature malleability in `is_valid_sig()` due to unconditional signature normalization before ECDSA verification - (File: `signature.js`)

### Summary
The oscript/AA-reachable `is_valid_sig()` formula function ultimately calls `signature.verifyMessageWithSecp256k1PemPubKey()`, which normalizes an attacker-supplied secp256k1 signature to its canonical low-S form *before* verifying it. Because ECDSA signatures are symmetric under `s → n-s` (with a flipped recovery bit), this means two syntactically different signature byte strings — the original and its malleable counterpart — both verify as "valid" for the exact same message and public key. Any AA logic that treats the raw signature string as a unique, non-reusable token (e.g., for single-use vouchers, meta-transaction replay protection, or off-chain-signed authorization tracking) can be bypassed.

### Finding Description
`verifyMessageWithSecp256k1PemPubKey` explicitly imports/normalizes the caller-supplied signature before calling `ecdsaVerify`: [1](#0-0) 

```
var sigBytes = Buffer.from(signature, encoding);
var rawCompact = sigBytes.length === 64 ? sigBytes : Buffer.from(ecdsa.signatureImport(sigBytes));
var compactSig = Buffer.from(ecdsa.signatureNormalize(rawCompact));
...
return ecdsa.ecdsaVerify(compactSig, hash, pubkey);
```

`ecdsa.signatureNormalize()` forcibly converts a high-S signature into its low-S equivalent prior to verification. This is the opposite of the standard EIP-2/SWC-117 mitigation, which is to *reject* non-canonical (high-S) signatures rather than normalize-and-accept them. As a result, for any valid `(r, s)` an attacker (or anyone who has merely observed one valid signature, without knowing the private key) can trivially compute the equally-valid `(r, n-s)` variant and both will pass `is_valid_sig()`.

This is reachable from oscript directly through the `is_valid_sig` formula opcode, whose only inputs (`message`, `pem_key`, `sig`) are attacker/trigger-controlled expressions evaluated from AA trigger data: [2](#0-1) 

By contrast, the base-protocol `sig` authentifier path (`ecdsaSig.verify` in `signature.js` lines 16-25, used from `definition.js`) calls `ecdsaVerify` directly on the raw signature without normalization, so it relies on libsecp256k1's built-in rejection of non-canonical signatures and is not affected the same way. The vulnerable path is specifically the `is_valid_sig`/PEM secp256k1 verification helper.

### Impact Explanation
Any AA that uses `is_valid_sig()` to validate off-chain-signed data and then stores/keys off the raw signature string (e.g., `var['used_' || sig] = true` to prevent replay of a signed voucher, price attestation, or authorization) can be defeated: an attacker derives the malleable counterpart of a previously-seen valid signature and resubmits it as a "new, unused" signature that still verifies against the same message and pubkey. This enables duplicate execution of single-use AA logic — e.g., double redemption of a signed payment authorization or duplicate triggering of fund-releasing logic — leading to AA fund loss.

### Likelihood Explanation
Exploitation requires only that the attacker (or trigger sender) has observed one previously valid `(message, pem_key, sig)` triple involving a secp256k1 key, which is often the case since such messages/signatures are typically embedded in a public trigger's `data` field to invoke the AA. Computing `n-s` is a standard, well-known operation, requiring no cryptographic secret. The bug is deterministic and always reachable via the public `is_valid_sig()` opcode, once an AA relies on signature-string-based replay protection.

### Recommendation
In `verifyMessageWithSecp256k1PemPubKey`, reject non-canonical (high-S) signatures instead of normalizing them: compare the parsed/imported signature to its normalized form and return `false` if they differ, i.e. only accept signatures that are already in low-S canonical form. This preserves the one-to-one mapping between a message/pubkey and a single canonical signature, closing the malleability-based replay path for any AA that depends on signature uniqueness.

### Proof of Concept
1. An AA defines logic using `is_valid_sig(trigger.data.message, $pem_key, trigger.data.sig)` and records `var['used_' || trigger.data.sig]` to prevent replaying the same signed voucher/message.
2. A legitimate signer produces `sig = (r, s)` for `message` and submits it once; the AA marks `used_sig_(r,s) = true` and pays out.
3. The attacker computes `s' = n - s` (trivial arithmetic, no private key needed) and DER/compact-encodes `(r, s')` as a new signature string `sig'`.
4. The attacker submits a new trigger with the same `message` but `trigger.data.sig = sig'`. `is_valid_sig()` normalizes `sig'` internally to the same canonical low-S form and returns `true`, while `var['used_sig_(r,s')_string']` was never set, bypassing the replay check and allowing the AA logic (e.g., fund payout) to execute again for the same underlying signed authorization.

### Citations

**File:** signature.js (L58-65)
```javascript
		var encoding = ValidationUtils.isValidHexadecimal(signature) ? 'hex' : 'base64';
		var sigBytes = Buffer.from(signature, encoding);
		var rawCompact = sigBytes.length === 64 ? sigBytes : Buffer.from(ecdsa.signatureImport(sigBytes));
		var compactSig = Buffer.from(ecdsa.signatureNormalize(rawCompact));

		var msgBuf = Buffer.isBuffer(message) ? message : Buffer.from(message);
		var hash = crypto.createHash('sha256').update(msgBuf).digest();
		return ecdsa.ecdsaVerify(compactSig, hash, pubkey);
```

**File:** formula/evaluation.js (L1704-1730)
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
```
