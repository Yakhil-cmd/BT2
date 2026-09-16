## Title
Unbounded Base64 decode and JSON parse of attacker-supplied device message before size validation causes resource-exhaustion DoS on the recipient device - ([File: device.js])

### Summary
The paired-device end-to-end encrypted messaging path in `device.js` decrypts and JSON-parses an attacker-controlled `encrypted_package.encrypted_message` field without ever checking its size, mirroring the RUSTSEC-2026-0229 pattern: a size-unbounded field is fully Base64-decoded and then JSON-parsed before any validation of its content or authorization gates spending/allocation cost.

### Finding Description
When a device message arrives (via hub `'hub/message'` justsaying, handled in `device.js` `handleJustsaying`, or directly via `'hub/deliver'` in `network.js`), only structural presence checks and a shallow nesting/node-count check are performed: [1](#0-0) [2](#0-1) 

None of these checks bound the *length* of the `encrypted_package.encrypted_message`, `iv`, or `authtag` strings — `isTooDeeplyNestedOrHasTooManyNodes(objDeviceMessage, 5, 100)` only limits nesting depth/node count, not string length of a single field.

The message is then passed to `decryptPackage()`, which:
1. Fully Base64-decodes `encrypted_message` into a `Buffer` with no prior size check: [3](#0-2) 
2. Decrypts the entire buffer in a loop regardless of size: [4](#0-3) 
3. Then calls `JSON.parse()` on the fully decrypted string with no length limit: [5](#0-4) 

Because the sender legitimately knows the recipient's ephemeral/permanent device pubkey (obtained during pairing, which is how any paired correspondent — or the hub itself relaying `hub/deliver` — can reach this code), the sender can construct a message that decrypts and parses correctly while being arbitrarily large, forcing the victim to allocate memory for the Base64 decode, run AES-GCM decryption over the whole buffer, and then execute `JSON.parse` over a proportionally large string — exactly the same "decode-then-parse-before-limiting" defect described in the NIP-98 advisory.

This is reachable purely from a paired correspondent device sending an oversized `"sign"`/`"private_payments"`/other-subject encrypted message; no privileged network/hub role is required for the recipient-side impact (the hub simply relays it, or in "always-online own hub" mode the client processes it directly).

### Impact Explanation
Repeated delivery of oversized encrypted device messages by any correspondent (or a malicious hub relaying attacker-supplied payloads it stores/forwards) forces the recipient wallet/AA-controlling node to spend CPU and memory decoding/decrypting/parsing on every message before any content validation (e.g., before `handlePrivatePaymentChains` or `wallet.js` subject dispatch even runs). Sustained abuse can degrade or stall a wallet/hub node's ability to process legitimate device traffic (signing requests, private payment chain delivery), which for an AA-controlling or actively-trading device can translate into missed signing windows or delayed private-payment processing — a service-denial condition against a specific counterparty-facing node rather than mere waste.

### Likelihood Explanation
High. Any paired device (a legitimate but potentially malicious correspondent — the exact "paired device" actor class listed as in-scope) can send messages through the hub delivery path with no server-side size cap on `encrypted_message` before decode/decrypt/parse. No signature bypass or cryptographic break is needed; the attacker is a normal correspondent constructing normal-looking but oversized payloads.

### Recommendation
Enforce a maximum length on `objDeviceMessage.encrypted_package.encrypted_message` (and `iv`/`authtag`) immediately in `network.js` `hub/deliver` and in `device.js`'s `'hub/message'` handler, before any Base64 decoding or decryption occurs, analogous to the fix in the referenced `nostr` commit (reject oversized encoded input before allocation, and reject decoded content beyond a fixed cap before `JSON.parse`). Additionally, add an explicit byte-length check on `decrypted_message` in `decryptPackage()` prior to `JSON.parse`.

### Proof of Concept
1. Pair with (or act as) a correspondent device of a target node, obtaining the target's `objMyPermanentDeviceKey.pub_b64` (exchanged during pairing).
2. Construct a valid `encrypted_package` addressed to that pubkey where `encrypted_message` decrypts to a huge (e.g., tens/hundreds of MB) JSON string (e.g., large arrays inside a `"sign"` or `"private_payments"` body), correctly computing `iv`/`authtag`/signature per `createEncryptedPackage()`.
3. Submit via `'hub/deliver'` (network.js:3509) or send-through-hub so it lands as `'hub/message'` on the target.
4. Observe that `device.js`'s `decryptPackage()` (device.js:443-473) fully base64-decodes, decrypts, and JSON-parses the payload before any size-based rejection, consuming CPU/memory proportional to attacker-chosen size on every delivery/retry.

### Citations

**File:** device.js (L154-172)
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
```

**File:** device.js (L443-447)
```javascript
	var iv = Buffer.from(objEncryptedPackage.iv, 'base64');
	var decipher = crypto.createDecipheriv('aes-128-gcm', shared_secret, iv);
	var authtag = Buffer.from(objEncryptedPackage.authtag, 'base64');
	decipher.setAuthTag(authtag);
	var enc_buf = Buffer.from(objEncryptedPackage.encrypted_message, "base64");
```

**File:** device.js (L449-456)
```javascript
	// under browserify, decryption of long buffers fails with Array buffer allocation errors, have to split the buffer into chunks
	var arrChunks = [];
	var CHUNK_LENGTH = 4096;
	for (var offset = 0; offset < enc_buf.length; offset += CHUNK_LENGTH){
	//	console.log('offset '+offset);
		arrChunks.push(decipher.update(enc_buf.slice(offset, Math.min(offset+CHUNK_LENGTH, enc_buf.length))));
	}
	var decrypted1 = Buffer.concat(arrChunks);
```

**File:** device.js (L465-473)
```javascript
	var decrypted_message = decrypted_message_buf.toString("utf8");
	console.log("decrypted: "+decrypted_message);
	try {
		var json = JSON.parse(decrypted_message);
	}
	catch (e) {
		console.log("failed to parse decrypted message: " + e);
		return null;
	}
```

**File:** network.js (L3510-3521)
```javascript
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
```
