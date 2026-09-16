This confirms the exploitable path: `handleJustsaying` in `device.js` only checks that the sender's `objDeviceMessage.signature`/hash are well-formed and that `sender_ephemeral_pubkey` / `recipient_ephemeral_pubkey` are non-empty strings — it never calls `isValidPubKey`/`ecdsa.publicKeyVerify` on the ephemeral DH pubkeys before decryption. It then calls `decryptPackage`, which calls `deriveSharedSecret(objEncryptedPackage.dh.sender_ephemeral_pubkey, priv_key)`, feeding the attacker-controlled `sender_ephemeral_pubkey` directly into `ecdsa.ecdh()` with no curve-membership validation. [1](#0-0) [2](#0-1) 

### Title
Private device-key extraction via invalid-curve ECDH inputs in encrypted device messaging - (File: device.js)

### Summary
`ocore`'s device-to-device end-to-end messaging layer (`device.js`) derives AES-GCM keys from ECDH between the recipient's permanent/temp private key and an attacker-supplied `sender_ephemeral_pubkey` taken straight from an incoming `hub/message`. The library used for this ECDH is `secp256k1` npm package, and `package.json` explicitly maps the browser/bundled build to `secp256k1/elliptic` (`"secp256k1": "secp256k1/elliptic"`), the exact vulnerable code path described in CVE-2024-48930/GHSA-584q-6j8j-r5pm, and the pinned semver range `^4.0.3` resolves to versions that predate the fix (5.0.1+). [3](#0-2) [4](#0-3) 

### Finding Description
`handleJustsaying` validates only that the message hash matches and that `objDeviceMessage.signature`/`pubkey` correctly sign the *outer* envelope; it does not validate the `dh.sender_ephemeral_pubkey`/`dh.recipient_ephemeral_pubkey` fields as points on the secp256k1 curve before passing them into decryption. [1](#0-0) 

`decryptPackage` selects the correct local private key (temp, prev-temp, or permanent device key) matching `recipient_ephemeral_pubkey`, then calls `deriveSharedSecret(objEncryptedPackage.dh.sender_ephemeral_pubkey, priv_key)`. [5](#0-4) 

`deriveSharedSecret` passes the raw base64-decoded attacker pubkey straight into `ecdsa.ecdh(pubkey, privKey, ...)` with no `publicKeyVerify`/curve-membership check anywhere in the call chain. [2](#0-1) 

Under the vulnerable `secp256k1/elliptic` implementation, `loadCompressedPublicKey` (as described in the referenced advisory) fails to validate that a decompressed X coordinate actually yields a point on `y² = x³ + 7`; when no valid Y exists it silently returns a point on a *different* curve `y² = x³ + D` that may have small, factorable order. Feeding such a crafted compressed pubkey as `sender_ephemeral_pubkey` causes the resulting "ECDH" output to be a low-order point, leaking several bits of the recipient's static private key (`priv` for the matched temp/prev-temp/permanent device key) per message. An attacker who is a paired correspondent device (or anyone who can get a `hub/message` accepted for a target, since the hub only checks outer-envelope well-formedness before forwarding) can send a sequence of crafted encrypted packages to the target and, by observing decryption success/failure and/or downstream effects, recover the ECDH remainders needed to reconstruct the recipient's `objMyPermanentDeviceKey.priv` (or temp key) via CRT, exactly as in the PoC in the advisory.

Because `objMyPermanentDeviceKey` is also used to sign device messages, unlock signed message flows, and is tied to `my_device_address` via `objectHash.getDeviceAddress`, recovering this key lets the attacker impersonate the victim device to correspondents/hub, including for wallet/AA-related device messages (payment requests, chain forwarding, private payment chain sharing) that this codebase routes through the device layer. [6](#0-5) 

### Impact Explanation
Full extraction of a victim's device private key (permanent or temp) allows the attacker to impersonate that device toward its correspondents and hub — sign arbitrary device messages, hijack encrypted channels for shared/multisig wallet coordination, private payment chain exchanges, and AA-related signing requests conducted over the device messaging layer. This is a High-severity key-compromise primitive reachable purely by sending crafted `hub/message` packages to a target device, without requiring any pre-existing privileged access.

### Likelihood Explanation
The attack requires no more than being able to address `hub/message`s at the victim (any correspondent device, or an attacker who obtains the target's permanent pubkey via `getMyDevicePubKey`/device pairing) and observing decryption results across ~11+ sessions, mirroring the advisory's PoC. The only gating factor is confirmation that this deployment actually resolves to the vulnerable `secp256k1/elliptic` build at runtime for the affected process (browser/bundled builds always use it per `package.json`; Node builds may use native bindings unless bundled) — I could not fully verify from the index which builds/environments (mobile wallet, browser extension, headless node) are in production use, so likelihood may vary by deployment.

### Recommendation
- Upgrade the `secp256k1` dependency to a patched version (>=5.0.1) that fixes `loadCompressedPublicKey`'s missing curve-membership check, for both the native and `elliptic` code paths, and pin/lock the version instead of a permissive `^4.0.3` range.
- Defense in depth: explicitly call `ecdsa.publicKeyVerify()` (already present as `device.isValidPubKey`) on `dh.sender_ephemeral_pubkey` and `dh.recipient_ephemeral_pubkey` before calling `deriveSharedSecret`/`ecdh` in `decryptPackage`, rejecting the message if verification fails.
- Consider validating that decompressed public keys actually satisfy the curve equation independently of the underlying library, as a redundant check.

### Proof of Concept
1. Attacker becomes (or spoofs) a correspondent whose messages the target's `handleJustsaying` accepts for decryption (`objDeviceMessage.to === getMyDeviceAddress()` and outer signature is valid — the attacker signs the outer envelope with their own valid key, only the DH pubkey embedded inside `encrypted_package.dh` needs to be malicious).
2. Attacker sends a `hub/message` with a crafted 33-byte compressed `sender_ephemeral_pubkey` chosen per the advisory's method (an X coordinate with no valid Y on the real curve, causing `loadCompressedPublicKey` to return a low-order point on an alternate curve).
3. Target's `decryptPackage`/`deriveSharedSecret` computes `ecdsa.ecdh(maliciousPubkey, priv_key, ...)`, producing one of a small set of possible shared secrets.
4. Attacker observes success/failure of AES-GCM auth-tag verification (or other side effects) to determine which of the small candidate set matched, leaking bits of `priv_key`.
5. Repeating with ~10 different crafted pubkeys and one final check per the advisory's `Solver`, attacker reconstructs the victim's permanent/temp device private key via CRT. [7](#0-6)

### Citations

**File:** device.js (L50-63)
```javascript
function setDevicePrivateKey(priv_key){
	breadcrumbs.add("setDevicePrivateKey");
	var bChanged = (!objMyPermanentDeviceKey || priv_key !== objMyPermanentDeviceKey.priv);
	objMyPermanentDeviceKey = {
		priv: priv_key,
		pub_b64: Buffer.from(ecdsa.publicKeyCreate(priv_key, true)).toString('base64')
	};
	var new_my_device_address = objectHash.getDeviceAddress(objMyPermanentDeviceKey.pub_b64);
	if (my_device_address && my_device_address !== new_my_device_address){
		breadcrumbs.add('different device address: old '+my_device_address+', new '+new_my_device_address);
		throw Error('different device address: old '+my_device_address+', new '+new_my_device_address);
	}
	breadcrumbs.add("same device addresses: "+new_my_device_address);
	my_device_address = new_my_device_address;
```

**File:** device.js (L154-177)
```javascript
			if (!ValidationUtils.isNonemptyString(message_hash) || !objDeviceMessage || !objDeviceMessage.signature || !objDeviceMessage.pubkey || !objDeviceMessage.to
					|| !objDeviceMessage.encrypted_package || !objDeviceMessage.encrypted_package.dh
					|| !objDeviceMessage.encrypted_package.dh.sender_ephemeral_pubkey 
					|| !objDeviceMessage.encrypted_package.dh.recipient_ephemeral_pubkey 
					|| !objDeviceMessage.encrypted_package.encrypted_message
					|| !objDeviceMessage.encrypted_package.iv || !objDeviceMessage.encrypted_package.authtag)
				return network.sendError(ws, "missing fields");
			if (objDeviceMessage.to !== getMyDeviceAddress())
				return network.sendError(ws, "not mine");
			try {
				const bOldHashIsCorrect = (message_hash === objectHash.getBase64Hash(objDeviceMessage));
				if (!bOldHashIsCorrect && message_hash !== objectHash.getBase64Hash(objDeviceMessage, true))
					return network.sendError(ws, "wrong hash");
				if (!ecdsaSig.verify(objectHash.getDeviceMessageHashToSign(objDeviceMessage), objDeviceMessage.signature, objDeviceMessage.pubkey))
					return respondWithError("wrong message signature");
			}
			catch(e){
				return respondWithError("failed to caculate message hash to sign:" + e);
			}
			// end of checks on the open (unencrypted) part of the message. These checks should've been made by the hub before accepting the message
			
			// decrypt the message
			try {
				var json = decryptPackage(objDeviceMessage.encrypted_package);
```

**File:** device.js (L397-479)
```javascript
function deriveSharedSecret(peer_b64_pubkey, privKey){
	var pubkey = new Buffer(peer_b64_pubkey, 'base64');
	var shared_secret_src = Buffer.from(ecdsa.ecdh(pubkey, privKey, {hashfn: (x, y) => x}, Buffer.alloc(32)));
	var shared_secret = crypto.createHash("sha256").update(shared_secret_src).digest().slice(0, 16);
	return shared_secret;
}

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
	var iv = Buffer.from(objEncryptedPackage.iv, 'base64');
	var decipher = crypto.createDecipheriv('aes-128-gcm', shared_secret, iv);
	var authtag = Buffer.from(objEncryptedPackage.authtag, 'base64');
	decipher.setAuthTag(authtag);
	var enc_buf = Buffer.from(objEncryptedPackage.encrypted_message, "base64");
//	var decrypted1 = decipher.update(enc_buf);
	// under browserify, decryption of long buffers fails with Array buffer allocation errors, have to split the buffer into chunks
	var arrChunks = [];
	var CHUNK_LENGTH = 4096;
	for (var offset = 0; offset < enc_buf.length; offset += CHUNK_LENGTH){
	//	console.log('offset '+offset);
		arrChunks.push(decipher.update(enc_buf.slice(offset, Math.min(offset+CHUNK_LENGTH, enc_buf.length))));
	}
	var decrypted1 = Buffer.concat(arrChunks);
	arrChunks = null;
	try {
		var decrypted2 = decipher.final();
	} catch(e) {
		return console.log("Failed to decrypt package: " + e);
	}
	breadcrumbs.add("decrypted lengths: "+decrypted1.length+" + "+decrypted2.length);
	var decrypted_message_buf = Buffer.concat([decrypted1, decrypted2]);
	var decrypted_message = decrypted_message_buf.toString("utf8");
	console.log("decrypted: "+decrypted_message);
	try {
		var json = JSON.parse(decrypted_message);
	}
	catch (e) {
		console.log("failed to parse decrypted message: " + e);
		return null;
	}
	if (json.encrypted_package){ // strip another layer of encryption
		console.log("inner encryption");
		return decryptPackage(json.encrypted_package, depth + 1);
	}
	else
		return json;
```

**File:** package.json (L25-28)
```json
  "browser": {
    "request": "browser-request",
    "secp256k1": "secp256k1/elliptic"
  },
```

**File:** package.json (L43-43)
```json
    "secp256k1": "^4.0.3",
```
