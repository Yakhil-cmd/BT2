Based on my investigation, I found a concrete analog reachable by an unprivileged paired-device peer.

### Title
Unvalidated attacker-controlled EC public key passed to native secp256k1 ECDH in device message decryption - (File: device.js)

### Summary
`decryptPackage()` in `device.js` derives a shared secret from the attacker-supplied `sender_ephemeral_pubkey` field of an incoming device message without validating that it is a well-formed secp256k1 public key before it is handed to the native `secp256k1` addon's `ecdh()` function.

### Finding Description
When a `hub/message`/`hub/deliver` device message arrives, `decryptPackage()` is invoked on the attacker-controlled `objEncryptedPackage` [1](#0-0) . It calls `deriveSharedSecret(objEncryptedPackage.dh.sender_ephemeral_pubkey, priv_key)` [2](#0-1) , where `deriveSharedSecret` does: [3](#0-2) 
The only prior checks on this field are `typeof ... !== 'string'` [4](#0-3)  — there is no length or format check (unlike `objTempPubkey.temp_pubkey`, which is validated with `isValidPubKey()` before being used, e.g. at [5](#0-4) , and `network.js`'s `hub/temp_pubkey` handler, which enforces `isStringOfLength(..., constants.PUBKEY_LENGTH)` [6](#0-5) ). The `sender_ephemeral_pubkey` on the *decryption* path has no equivalent length/point-validity check, so an arbitrary base64 string of any length or content is turned into a `Buffer` via `new Buffer(peer_b64_pubkey, 'base64')` and fed straight into `ecdsa.ecdh(pubkey, privKey, ...)`, the native/WASM secp256k1 binding, which expects a strictly 33- or 65-byte, well-formed EC point buffer.

This is the same bug class as the Chrome CVE: untrusted, attacker-crafted binary data (in Chrome's case an extension payload; here a base64-decoded "public key") is passed without prior structural validation into a lower-level native parser/arithmetic routine that assumes well-formed input, risking out-of-bounds reads/heap corruption in the native addon.

### Impact Explanation
Any correspondent (or anyone who can get a device message routed to the target, since `hub/deliver` only checks basic signature/shape fields before reaching decryption [7](#0-6) ) can supply a malformed `sender_ephemeral_pubkey`. If the underlying native `secp256k1` binding does not itself perform bounds/format validation before dereferencing the buffer as a fixed-size EC point, this can crash the node process (denial of service to the wallet/hub) or, in the worst case matching the CVE's severity, cause heap corruption in the native addon exploitable for further compromise.

### Likelihood Explanation
Reaching this code only requires sending one attacker-crafted device message to a paired/target device address; the message signature check is on the outer envelope (`objDeviceMessage.signature`/`pubkey`) which the attacker fully controls with their own keys, so no privileged access is needed — this satisfies "AA/device message poster" reachability. The actual exploitability depends on whether the installed `secp256k1` native binding validates the public key buffer length/format before invoking curve arithmetic; I could not confirm from the indexed files whether that validation exists inside the native module itself (its source was not present in the index), so likelihood is uncertain pending confirmation of the library version/behavior in use.

### Recommendation
Validate `objEncryptedPackage.dh.sender_ephemeral_pubkey` (and `recipient_ephemeral_pubkey`) with the same `isValidPubKey()`/length check used elsewhere (e.g., `constants.PUBKEY_LENGTH`, and ideally `ecdsa.publicKeyVerify()`) before calling `deriveSharedSecret()`/`ecdsa.ecdh()`, mirroring the check already applied to `objTempPubkey.temp_pubkey`.

### Proof of Concept
1. As any device correspondent (or anyone able to reach the target's hub `hub/deliver` endpoint), craft a device message where `encrypted_package.dh.sender_ephemeral_pubkey` is a base64 string decoding to a buffer that is not a valid 33/65-byte secp256k1 point (e.g., all zero bytes, or a short/long buffer).
2. Send it as `hub/message`/`hub/deliver`; the envelope signature check only validates the outer message, not the DH fields [7](#0-6) .
3. On the recipient device, `decryptPackage()` reaches `deriveSharedSecret()` and calls `ecdsa.ecdh()` with the malformed buffer [3](#0-2) .
4. Depending on the native binding's internal checks, this triggers an exception (best case) or undefined/out-of-bounds native memory access (worst case).

**Caveat on confidence:** I was unable to inspect the actual `secp256k1` native module's C/WASM source in this index to confirm whether it performs its own input validation before the ocore-level check would matter; this determines whether the missing length check translates into an actual memory-safety bug versus a caught JS-level exception. A Devin session with full filesystem access could pull the exact `secp256k1` npm dependency version from `package.json` and inspect its bindings to close this gap definitively.

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

**File:** device.js (L442-442)
```javascript
	var shared_secret = deriveSharedSecret(objEncryptedPackage.dh.sender_ephemeral_pubkey, priv_key);
```

**File:** device.js (L644-644)
```javascript
		if (!isValidPubKey(objTempPubkey.temp_pubkey))
```

**File:** network.js (L3509-3527)
```javascript
		case 'hub/deliver':
			var objDeviceMessage = params;
			if (!objDeviceMessage || !objDeviceMessage.signature || !objDeviceMessage.pubkey || !objDeviceMessage.to
					|| !objDeviceMessage.encrypted_package || !objDeviceMessage.encrypted_package.dh
					|| !objDeviceMessage.encrypted_package.dh.sender_ephemeral_pubkey 
					|| !objDeviceMessage.encrypted_package.dh.recipient_ephemeral_pubkey 
					|| !objDeviceMessage.encrypted_package.encrypted_message
					|| !objDeviceMessage.encrypted_package.iv || !objDeviceMessage.encrypted_package.authtag)
				return sendErrorResponse(ws, tag, "missing fields");
			if (!ValidationUtils.isValidDeviceAddress(objDeviceMessage.to))
				return sendErrorResponse(ws, tag, "invalid to address");
			if (isTooDeeplyNestedOrHasTooManyNodes(objDeviceMessage, 5, 100))
				return sendErrorResponse(ws, tag, "device message is too deeply nested or has too many nodes");
			var bToMe = (my_device_address && my_device_address === objDeviceMessage.to);
			if (!conf.bServeAsHub && !bToMe)
				return sendErrorResponse(ws, tag, "I'm not a hub");
			try {
				if (!ecdsaSig.verify(objectHash.getDeviceMessageHashToSign(objDeviceMessage), objDeviceMessage.signature, objDeviceMessage.pubkey))
					return sendErrorResponse(ws, tag, "wrong message signature");
```

**File:** network.js (L3614-3617)
```javascript
			if (!ValidationUtils.isStringOfLength(objTempPubkey.temp_pubkey, constants.PUBKEY_LENGTH))
				return sendErrorResponse(ws, tag, "wrong temp_pubkey length");
			if (!ValidationUtils.isStringOfLength(objTempPubkey.pubkey, constants.PUBKEY_LENGTH))
				return sendErrorResponse(ws, tag, "wrong pubkey length");
```
