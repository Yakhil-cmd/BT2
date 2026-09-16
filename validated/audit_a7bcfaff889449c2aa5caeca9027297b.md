### Title
Unvalidated attacker-controlled EC public key passed directly to native secp256k1 `ecdh` in device-message decryption - ([File: device.js])

### Summary
`decryptPackage()` in `device.js` only type-checks that `dh.sender_ephemeral_pubkey` is a string before handing it to `deriveSharedSecret()`, which decodes it from base64 and feeds the raw bytes directly into the native `secp256k1` addon's `ecdh()` call with no length or format validation, mirroring the CVE-2025-20260 root cause (buffer processed by native code without validating its size/shape before use).

### Finding Description
`decryptPackage` validates only `typeof objEncryptedPackage.dh.sender_ephemeral_pubkey !== 'string'` [1](#0-0) , then calls `deriveSharedSecret(objEncryptedPackage.dh.sender_ephemeral_pubkey, priv_key)` [2](#0-1) .

Inside `deriveSharedSecret`, the string is base64-decoded into a `Buffer` with no check on length (should be 33 or 65 bytes for a valid compressed/uncompressed secp256k1 point) or on the leading prefix byte (`0x02`/`0x03`/`0x04`), and is passed straight into `ecdsa.ecdh(pubkey, privKey, {hashfn: (x, y) => x}, Buffer.alloc(32))`, where `ecdsa` is the native `secp256k1` npm binding: [3](#0-2) , [4](#0-3) .

This is directly analogous to the ClamAV PDF flaw: an incorrectly-sized/attacker-shaped buffer is handed to lower-level native processing code without the calling JS layer verifying its size/structure first, relying entirely on the native library to reject malformed input safely. Any paired device (or a hub relaying a spoofed/replayed encrypted package, since the hub only forwards opaque JSON) can set `sender_ephemeral_pubkey` to an arbitrary base64 string of arbitrary length/content — e.g. 0 bytes, 1 byte, or thousands of bytes — before it reaches the native `ecdh` call.

### Impact Explanation
If the installed `secp256k1` native binding does not perform strict internal length/format validation on the public-key buffer before dereferencing it in native (C) code, this can lead to an out-of-bounds read in the native addon, causing a process crash (DoS) of the wallet/hub process handling the device message — analogous to the ClamAV CVE's DoS outcome, and in the worst case memory corruption. Even in the more defensive case, this is a reachable code path where the application layer has abdicated all input validation to a native, non-JS-managed buffer boundary, which is exactly the anti-pattern behind CVE-2025-20260.

### Likelihood Explanation
`decryptPackage` is invoked whenever a device receives an encrypted message from any correspondent device via a hub [1](#0-0) ; the `dh.sender_ephemeral_pubkey` field is fully attacker-controlled JSON content within that message and undergoes no format/length validation before reaching native code, so exploitation requires only sending a single malformed encrypted package to a paired device — no privileged access needed.

### Recommendation
Before calling `ecdsa.ecdh`, validate `pubkey.length` is exactly 33 or 65 bytes and that the first byte matches a valid point-encoding prefix, and use `ecdsa.publicKeyVerify(pubkey)` (provided by the `secp256k1` package) to confirm the buffer decodes to a valid curve point before it is passed into `ecdh`; reject and log/drop the message otherwise instead of forwarding unvalidated bytes into native code.

### Proof of Concept
1. As a paired device (or anyone able to submit a `decryptPackage`-shaped JSON object to a device, e.g. via hub relay), send an encrypted package where `dh.sender_ephemeral_pubkey` is set to a base64 string decoding to 1 byte (e.g. `"AA=="`) or to an oversized buffer, while `recipient_ephemeral_pubkey` matches the target's current temp/permanent key so the code path in `decryptPackage` is taken.
2. The target calls `deriveSharedSecret("AA==", priv_key)`, which decodes to a 1-byte buffer and passes it directly into `ecdsa.ecdh(pubkey, privKey, ...)` with no prior validation.
3. Depending on the native `secp256k1` addon's internal robustness, this either throws a JS exception (best case) or triggers unsafe memory access in the native module, since the JS layer performs no length/format check before the native boundary — confirming the missing-validation root cause described above.

### Citations

**File:** device.js (L397-402)
```javascript
function deriveSharedSecret(peer_b64_pubkey, privKey){
	var pubkey = new Buffer(peer_b64_pubkey, 'base64');
	var shared_secret_src = Buffer.from(ecdsa.ecdh(pubkey, privKey, {hashfn: (x, y) => x}, Buffer.alloc(32)));
	var shared_secret = crypto.createHash("sha256").update(shared_secret_src).digest().slice(0, 16);
	return shared_secret;
}
```

**File:** device.js (L404-409)
```javascript
function decryptPackage(objEncryptedPackage, depth = 0){
	if (depth > 2)
		return console.log("too many layers of encryption");
	var priv_key;
	if (typeof objEncryptedPackage.iv !== 'string' || typeof objEncryptedPackage.authtag !== 'string' || typeof objEncryptedPackage.encrypted_message !== 'string' || !objEncryptedPackage.dh || typeof objEncryptedPackage.dh !== 'object' || typeof objEncryptedPackage.dh.sender_ephemeral_pubkey !== 'string' || typeof objEncryptedPackage.dh.recipient_ephemeral_pubkey !== 'string')
		return console.log("wrong params in encrypted package");
```

**File:** device.js (L442-442)
```javascript
	var shared_secret = deriveSharedSecret(objEncryptedPackage.dh.sender_ephemeral_pubkey, priv_key);
```

**File:** signature.js (L1-3)
```javascript
/*jslint node: true */
"use strict";
var ecdsa = require('secp256k1');
```
