### Title
Unvalidated ephemeral pubkey in device-message ECDH can force a predictable/degenerate shared secret - (File: device.js)

### Summary
The CVE (CVE-2024-9355) describes an uninitialized/zeroed buffer being returned by a FIPS-mode primitive that can (a) be mistaken for a valid computed value in a comparison, or (b) cause a derived key to end up all zeros instead of unpredictable. The closest reachable analog in ocore is the device-pairing E2E-encryption code in `device.js`, where a shared secret used to encrypt/decrypt wallet-pairing messages is derived from a peer-supplied ephemeral public key without validating that the key is a well-formed, non-degenerate curve point before it is fed into `ecdh`.

### Finding Description
`deriveSharedSecret` computes the AES-GCM key material directly from an attacker/peer-controlled base64 pubkey: [1](#0-0) 
```
function deriveSharedSecret(peer_b64_pubkey, privKey){
	var pubkey = new Buffer(peer_b64_pubkey, 'base64');
	var shared_secret_src = Buffer.from(ecdsa.ecdh(pubkey, privKey, {hashfn: (x, y) => x}, Buffer.alloc(32)));
	var shared_secret = crypto.createHash("sha256").update(shared_secret_src).digest().slice(0, 16);
	return shared_secret;
}
```
`peer_b64_pubkey` comes straight from an incoming encrypted-package descriptor (`objEncryptedPackage.dh.sender_ephemeral_pubkey`) that is only checked for being a non-empty string, never validated as a valid, on-curve, non-identity secp256k1 point before use: [2](#0-1) 
```
function decryptPackage(objEncryptedPackage, depth = 0){
	if (depth > 2)
		return console.log("too many layers of encryption");
	var priv_key;
	if (typeof objEncryptedPackage.iv !== 'string' || typeof objEncryptedPackage.authtag !== 'string' || typeof objEncryptedPackage.encrypted_message !== 'string' || !objEncryptedPackage.dh || typeof objEncryptedPackage.dh !== 'object' || typeof objEncryptedPackage.dh.sender_ephemeral_pubkey !== 'string' || typeof objEncryptedPackage.dh.recipient_ephemeral_pubkey !== 'string')
		return console.log("wrong params in encrypted package");
```
`ecdh` is invoked with an explicit output buffer pre-allocated as all-zero via `Buffer.alloc(32)` and a custom `hashfn` that simply returns the raw x-coordinate `x` rather than doing a keyed hash. This is the same shape of bug class as the advisory: an output buffer that starts zeroed is handed to the crypto primitive, and if the primitive fails to fully/validly populate it for a malformed or degenerate input point (e.g., invalid pubkey encoding, point-at-infinity-adjacent inputs, or any code path that returns early without writing to the buffer), the zeroed buffer is silently carried forward into `shared_secret_src` and hashed into the "shared secret" used as the AES-128-GCM key. No check exists anywhere in this path that verifies the peer pubkey is a valid, non-trivial point (`ecdsa.publicKeyVerify` is used elsewhere in `device.js` for the local temp-key generation loop, but never applied to the incoming peer key here), so the guarantee that the ECDH output is unpredictable rests entirely on the underlying `secp256k1` binding's internal validation — which is exactly the class of assumption the CVE shows can silently fail.

### Impact Explanation
If a peer (a paired device / correspondent, which is an actor explicitly in scope) can cause `shared_secret_src` to be the zero buffer (or any other attacker-predictable value) instead of a genuine ECDH output, the resulting AES-128-GCM key for that message exchange becomes attacker-known or attacker-influenced. That would let the malicious paired device (or someone who can inject a crafted `dh.sender_ephemeral_pubkey`/`recipient_ephemeral_pubkey`) decrypt or forge wallet-pairing/chat payloads that are supposed to be confidential between the two device keys, including private-payment chain messages and contract/dispute payloads that are exchanged over this channel (`wallet.js` `arbiter_dispute_request` handling, private-profile/payment delivery, etc.), i.e. contract fund loss or unauthorized disclosure/spoofing of payment-related device messages.

### Likelihood Explanation
This requires the underlying `secp256k1` native/JS binding's `ecdh` to actually mishandle a malformed/degenerate input point by leaving the caller-supplied zeroed output buffer unmodified (or otherwise returning a low-entropy/zero value) rather than throwing — behavior I could not directly confirm from the ocore repository itself, since the `secp256k1` package internals are outside this codebase and were not indexed here. The reachable trigger (crafting `dh.sender_ephemeral_pubkey`) is fully within an unprivileged paired device's control, and there is no explicit pubkey validity check in `device.js` guarding this call, which is the concrete root-cause gap this analog highlights.

### Recommendation
- Validate `peer_b64_pubkey` with `ecdsa.publicKeyVerify()` (already used elsewhere in this file) before calling `ecdh` in `deriveSharedSecret`, rejecting malformed/degenerate points outright.
- After calling `ecdh`, explicitly check that the returned/filled buffer is not all-zero (or otherwise implausible) before using it to derive `shared_secret`, so a failure mode in the underlying library can't silently degrade into a predictable key.
- Avoid relying on a pre-zeroed output buffer passed into `ecdh`; if the library contract permits the buffer to remain unwritten on certain inputs, that ambiguity should be treated as an error rather than silently accepted.

### Proof of Concept
Conceptual (cannot be fully executed without access to the exact `secp256k1` binding version's edge-case behavior):
1. A malicious paired device sends an `encrypted_package` (via `sendMessageToHub`/`handleMessageFromHub`) whose `dh.sender_ephemeral_pubkey` is a syntactically valid base64 string that decodes to a compressed/uncompressed point encoding that is invalid or degenerate (e.g., not on the curve, or crafted to trigger an early-return path in the native `ecdh` binding).
2. `decryptPackage` passes this value straight into `deriveSharedSecret` without any `publicKeyVerify` check. [3](#0-2) 
3. If the `ecdh` call fails to overwrite the `Buffer.alloc(32)` output buffer for this crafted input, `shared_secret_src` remains all-zero, and `shared_secret` becomes `sha256(zero_buffer).slice(0,16)` — a value fully known in advance to the attacker, letting them decrypt/forge subsequent AES-GCM traffic keyed with this secret.

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

**File:** device.js (L404-410)
```javascript
function decryptPackage(objEncryptedPackage, depth = 0){
	if (depth > 2)
		return console.log("too many layers of encryption");
	var priv_key;
	if (typeof objEncryptedPackage.iv !== 'string' || typeof objEncryptedPackage.authtag !== 'string' || typeof objEncryptedPackage.encrypted_message !== 'string' || !objEncryptedPackage.dh || typeof objEncryptedPackage.dh !== 'object' || typeof objEncryptedPackage.dh.sender_ephemeral_pubkey !== 'string' || typeof objEncryptedPackage.dh.recipient_ephemeral_pubkey !== 'string')
		return console.log("wrong params in encrypted package");
	if (objEncryptedPackage.dh.recipient_ephemeral_pubkey === objMyTempDeviceKey.pub_b64){
```

**File:** device.js (L442-446)
```javascript
	var shared_secret = deriveSharedSecret(objEncryptedPackage.dh.sender_ephemeral_pubkey, priv_key);
	var iv = Buffer.from(objEncryptedPackage.iv, 'base64');
	var decipher = crypto.createDecipheriv('aes-128-gcm', shared_secret, iv);
	var authtag = Buffer.from(objEncryptedPackage.authtag, 'base64');
	decipher.setAuthTag(authtag);
```
