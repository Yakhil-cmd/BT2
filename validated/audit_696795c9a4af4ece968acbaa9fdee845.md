### Title
Unvalidated attacker-controlled ephemeral public key length passed to native secp256k1 ECDH before hashing - (File: device.js)

### Summary
`decryptPackage()` in `device.js` derives a shared secret for every incoming end-to-end encrypted device message by calling `deriveSharedSecret(objEncryptedPackage.dh.sender_ephemeral_pubkey, priv_key)` [1](#0-0) . `deriveSharedSecret` takes the field verbatim, base64-decodes it into a `Buffer` of arbitrary attacker-chosen length, and hands it straight to the native `secp256k1` addon's `ecdh()` function with no length or point-validity check beforehand: `var pubkey = new Buffer(peer_b64_pubkey, 'base64'); var shared_secret_src = Buffer.from(ecdsa.ecdh(pubkey, privKey, {hashfn: (x, y) => x}, Buffer.alloc(32)));` [2](#0-1) . This mirrors the JLSEC-2026-137 bug class: a length field taken from untrusted input is used to feed a native/binary parsing routine (here, the compiled `secp256k1` C binding) without first checking that the buffer matches the expected fixed size (33 or 65 bytes) before it is copied/used inside native memory.

### Finding Description
`objEncryptedPackage.dh.sender_ephemeral_pubkey` originates from a fully attacker-controlled JSON payload sent by *any paired correspondent* (or by a hub relaying `hub/message`/`hub/deliver`), and is only checked with `typeof ... !== 'string'` before use [3](#0-2) [4](#0-3) . No length, format, or on-curve validation is performed on the decoded bytes before they are passed into `ecdsa.ecdh(pubkey, privKey, ...)` [2](#0-1) . The `secp256k1` npm module's `ecdh` binding expects a public key buffer of exactly 33 (compressed) or 65 (uncompressed) bytes; passing a buffer of a different length is exactly the "unvalidated length before it is used by native/binary code" pattern that the OpenEXR advisory describes for its heap-based buffer overflow. Unlike the DER-parsing code in `signature.js`, which uses safe JS `Buffer.slice`/`indexOf` operations that cannot read out of bounds [5](#0-4) , the `ecdh` call crosses into native/compiled code where V8's automatic bounds checking no longer applies, so the attacker directly controls the size of an input buffer consumed by a native cryptographic routine.

### Impact Explanation
If exploitable in the native binding, the result would be a crash (denial of service for the receiving wallet/hub) or, per the CVE's threat model, potential memory corruption/RCE in the recipient's process — an outcome far more serious than the excluded "network-DoS" category because it can lead to code execution in the same process that holds private keys and controls fund-spending signatures, directly threatening unauthorized spending. Since decryption is attempted for *every* incoming device message on the always-on device-key path, a single crafted `sender_ephemeral_pubkey` field is sufficient to trigger the code path in any wallet or hub that receives it.

### Likelihood Explanation
Reachability is high and requires only routine device-messaging protocol elements available to any paired device or hub relay: no special privileges beyond being an existing (or newly pairing, for `pairing`/`my_xpubkey` subjects that bypass correspondent checks) counterparty are needed, since `hub/message`/`hub/deliver` accept the encrypted package with only signature/shape checks that don't constrain the `sender_ephemeral_pubkey` length [4](#0-3) . Whether this actually triggers memory corruption depends on the internal bounds-checking behavior of the compiled `secp256k1` addon used by this repo, which is a third-party native dependency whose internal C/C++ source was not available for review in this codebase — this is the main uncertainty in confirming exploitability versus a merely thrown exception.

### Recommendation
Before calling `ecdsa.ecdh()`, explicitly validate that the decoded `sender_ephemeral_pubkey` (and `recipient_ephemeral_pubkey`) buffer is exactly 33 or 65 bytes and passes `ecdsa.publicKeyVerify()` (a function already exposed by the `secp256k1` package for this purpose), rejecting the message with `ifError`/`sendErrorResponse` otherwise, mirroring the strict length checks already used elsewhere for `PUBKEY_LENGTH`-sized fields (e.g., `hub/temp_pubkey` in `network.js`) [6](#0-5) .

### Proof of Concept
1. As any paired correspondent (or via a malicious/compromised hub relaying `hub/deliver`), send a `hub/message`/`hub/deliver` payload whose `encrypted_package.dh.sender_ephemeral_pubkey` is a base64 string decoding to a buffer of an unexpected length (e.g., 1 byte or several hundred bytes) instead of 33/65 bytes.
2. The other required string fields (`iv`, `authtag`, `encrypted_message`, `recipient_ephemeral_pubkey`) can be arbitrary valid base64 strings sufficient to pass the `typeof` checks in `handleJustsaying`'s `hub/message` case [7](#0-6) , and `recipient_ephemeral_pubkey` set to match the victim's current temp/permanent key so `decryptPackage` proceeds to `deriveSharedSecret` [8](#0-7) .
3. Once delivered, the victim's `decryptPackage` invokes `deriveSharedSecret(sender_ephemeral_pubkey, priv_key)`, which decodes the malformed-length buffer and calls `ecdsa.ecdh(pubkey, privKey, ...)` directly [2](#0-1) .
4. Observe whether the native binding crashes the process or exhibits undefined behavior — confirming this final step requires inspecting the compiled `secp256k1` addon's native source, which was not retrievable from this repository's index.

### Citations

**File:** device.js (L147-160)
```javascript
		case 'hub/message':
			var objDeviceMessage = body.message;
			var message_hash = body.message_hash;
			var respondWithError = function(error){
				network.sendError(ws, error);
				network.sendJustsaying(ws, 'hub/delete', message_hash);
			};
			if (!ValidationUtils.isNonemptyString(message_hash) || !objDeviceMessage || !objDeviceMessage.signature || !objDeviceMessage.pubkey || !objDeviceMessage.to
					|| !objDeviceMessage.encrypted_package || !objDeviceMessage.encrypted_package.dh
					|| !objDeviceMessage.encrypted_package.dh.sender_ephemeral_pubkey 
					|| !objDeviceMessage.encrypted_package.dh.recipient_ephemeral_pubkey 
					|| !objDeviceMessage.encrypted_package.encrypted_message
					|| !objDeviceMessage.encrypted_package.iv || !objDeviceMessage.encrypted_package.authtag)
				return network.sendError(ws, "missing fields");
```

**File:** device.js (L397-402)
```javascript
function deriveSharedSecret(peer_b64_pubkey, privKey){
	var pubkey = new Buffer(peer_b64_pubkey, 'base64');
	var shared_secret_src = Buffer.from(ecdsa.ecdh(pubkey, privKey, {hashfn: (x, y) => x}, Buffer.alloc(32)));
	var shared_secret = crypto.createHash("sha256").update(shared_secret_src).digest().slice(0, 16);
	return shared_secret;
}
```

**File:** device.js (L404-442)
```javascript
function decryptPackage(objEncryptedPackage, depth = 0){
	if (depth > 2)
		return console.log("too many layers of encryption");
	var priv_key;
	if (typeof objEncryptedPackage.iv !== 'string' || typeof objEncryptedPackage.authtag !== 'string' || typeof objEncryptedPackage.encrypted_message !== 'string' || !objEncryptedPackage.dh || typeof objEncryptedPackage.dh !== 'object' || typeof objEncryptedPackage.dh.sender_ephemeral_pubkey !== 'string' || typeof objEncryptedPackage.dh.recipient_ephemeral_pubkey !== 'string')
		return console.log("wrong params in encrypted package");
	if (objEncryptedPackage.dh.recipient_ephemeral_pubkey === objMyTempDeviceKey.pub_b64){
		priv_key = objMyTempDeviceKey.priv;
		if (objMyTempDeviceKey.use_count)
			objMyTempDeviceKey.use_count++;
		else
			objMyTempDeviceKey.use_count = 1;
		console.log("message encrypted to temp key");
	}
	else if (objMyPrevTempDeviceKey && objEncryptedPackage.dh.recipient_ephemeral_pubkey === objMyPrevTempDeviceKey.pub_b64){
		priv_key = objMyPrevTempDeviceKey.priv;
		console.log("message encrypted to prev temp key");
		//console.log("objMyPrevTempDeviceKey: "+JSON.stringify(objMyPrevTempDeviceKey));
		//console.log("prev temp private key buf: ", priv_key);
		//console.log("prev temp private key b64: "+priv_key.toString('base64'));
	}
	else if (objEncryptedPackage.dh.recipient_ephemeral_pubkey === objMyPermanentDeviceKey.pub_b64){
		priv_key = objMyPermanentDeviceKey.priv;
		console.log("message encrypted to permanent key");
	}
	else{
		console.log("message encrypted to unknown key");
		setTimeout(function(){
			throw Error("message encrypted to unknown key, device "+my_device_address+", len="+objEncryptedPackage.encrypted_message.length+". The error might be caused by restoring from an old backup or using the same keys on another device.");
		}, 100);
	//	eventBus.emit('nonfatal_error', "message encrypted to unknown key, device "+my_device_address+", len="+objEncryptedPackage.encrypted_message.length, new Error('unknown key'));
		return null;
	}
	
	//var ecdh = crypto.createECDH('secp256k1');
	//if (process.browser) // workaround bug in crypto-browserify https://github.com/crypto-browserify/createECDH/issues/9
		//ecdh.generateKeys("base64", "compressed");
	//ecdh.setPrivateKey(priv_key);
	var shared_secret = deriveSharedSecret(objEncryptedPackage.dh.sender_ephemeral_pubkey, priv_key);
```

**File:** network.js (L3508-3527)
```javascript
		// I'm a hub, the peer wants to deliver a message to one of my clients
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

**File:** signature.js (L50-56)
```javascript
function verifyMessageWithSecp256k1PemPubKey(message, signature, der) {
	try {
		// Locate the BIT STRING for an uncompressed public key: 03 42 00 04 <32 X> <32 Y>
		var bitStringIdx = der.indexOf(Buffer.from([0x03, 0x42, 0x00]));
		if (bitStringIdx === -1) return false;
		var pubkey = der.slice(bitStringIdx + 3, bitStringIdx + 68); // 65 bytes: 04 + 32 + 32
		if (pubkey.length !== 65 || pubkey[0] !== 0x04) return false;
```
