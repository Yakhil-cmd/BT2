### Title
Unbounded memory allocation from oversized device message payload in `hub/deliver` / `hub/message` handling - ([File: network.js])

### Summary
The Grafana advisory describes an endpoint that reads an entire request body into memory without a size bound, letting an authenticated caller trigger unbounded allocation and OOM. In ocore, the closest reachable analog is the device-messaging path (`hub/deliver` on a hub, and `hub/message` on the receiving device/wallet), where the `encrypted_package.encrypted_message` field (and the enclosing `objDeviceMessage`) is accepted, hashed, stored, forwarded and later fully base64-decoded/decrypted into memory with no upper bound on its length.

### Finding Description
`handleRequest`'s `'hub/deliver'` case only validates presence of fields and calls `isTooDeeplyNestedOrHasTooManyNodes(objDeviceMessage, 5, 100)`, which limits nesting depth and number of object/array *nodes*, but does **not** limit the length of individual string values such as `encrypted_package.encrypted_message`: [1](#0-0) 

The message is then hashed, `JSON.stringify`-ed, and written into the `device_messages` table, and immediately pushed to any connected recipient with `sendJustsaying`: [2](#0-1) 

Length is only checked opportunistically against a client-configured `max_message_length` (`client.max_message_length`), which is optional and controlled by the recipient itself, not enforced server-side as a hard cap: [3](#0-2) [4](#0-3) 

On the receiving side, `handleJustsaying`'s `'hub/message'` case in `device.js` accepts the message with only shape checks (existence of fields), no length checks, and hands the whole thing to `decryptPackage`: [5](#0-4) 

`decryptPackage` fully materializes the base64 payload into a `Buffer` (`Buffer.from(objEncryptedPackage.encrypted_message, "base64")`) before doing any chunked decryption, and the JSON-decoded plaintext is later `JSON.parse`d with no size guard either: [6](#0-5) 

Because `isTooDeeplyNestedOrHasTooManyNodes` only limits node counts/depth (not string byte-length), and the hub logs/echoes full message text (`console.log('RECEIVED ' + message.length ...)` combined with unlimited JSON.parse of the socket frame) before any application-level size check runs, a single very large string value inside one field bypasses all structural anti-spam checks while still forcing full in-memory base64 decoding, `Buffer.concat`, decryption, and DB storage of the entire blob.

### Impact Explanation
A device that is already paired with a hub/wallet (or any peer allowed to call `hub/deliver`) can submit an `objDeviceMessage` whose `encrypted_package.encrypted_message` field is arbitrarily large (limited in practice only by the underlying WebSocket frame limits, not by ocore's own validation). This is stored, forwarded, and later decrypted, causing large memory allocations (`Buffer.from`, `Buffer.concat`, `JSON.stringify`/`JSON.parse`) on the hub and on the recipient wallet/device process. Repeated or large-enough messages can exhaust available memory on the hub or the target device, crashing it (denial of service) and disrupting the ability of that device/wallet to send/receive payments or respond to AA/oscript-related device flows. This does not directly enable double-spend or fund loss but can freeze a wallet's ability to operate (denial of service), which fits the "AA fund... freezing" / "network unable to confirm new units" impact class when the disrupted node is a hub relied upon for message delivery.

### Likelihood Explanation
Any device that has previously paired with the target (a normal, low-privilege interaction — pairing codes are shared casually, e.g. for arbiter/prosaic contracts or ordinary chat) can send `hub/deliver` messages to that peer through the hub. The check `isTooDeeplyNestedOrHasTooManyNodes(objDeviceMessage, 5, 100)` gives a false sense of protection but does not bound string field length, so exploitation requires no special complexity — a single, oversized string in a known field is sufficient. Likelihood is Medium: it requires an established pairing relationship (not fully anonymous), but that is a very low bar in this protocol's threat model (the wiki/report also treats "paired device" as an authorized-but-limited actor).

### Recommendation
- Enforce an explicit maximum length on `objDeviceMessage.encrypted_package.encrypted_message` (and other string fields such as `iv`, `authtag`, `dh.*`) in the `hub/deliver` and `hub/message` handlers before any hashing/signature verification/decryption/storage occurs, e.g. via a new constant like `MAX_DEVICE_MESSAGE_LENGTH` similar to `constants.MAX_AUTHENTIFIER_LENGTH`.
- Extend `isTooDeeplyNestedOrHasTooManyNodes` (or add a companion check, similar to `isTooBigObj` used elsewhere) to also cap the cumulative/individual string lengths of the object being validated, and use that variant for device messages.
- Reject oversized messages at the socket layer as early as possible (before `JSON.parse` of the full frame) rather than relying solely on downstream node/depth checks.

### Proof of Concept
1. Pair a device with a target hub/wallet normally.
2. Craft a `hub/deliver` request whose `params.encrypted_package.encrypted_message` is a very large base64 string (e.g. tens/hundreds of MB), with syntactically valid but otherwise arbitrary `iv`/`authtag`/`dh` fields and a valid signature over the (large) object.
3. Send the request to the hub. `isTooDeeplyNestedOrHasTooManyNodes(objDeviceMessage, 5, 100)` passes because the object has few keys and no deep nesting.
4. Hub allocates/stores the full message (`JSON.stringify(objDeviceMessage)`, DB insert) and forwards it via `sendJustsaying` to the connected recipient.
5. Recipient's `device.js` `decryptPackage` allocates a `Buffer` from the entire base64 string and performs `Buffer.concat` over chunks, materializing the whole payload in memory.
6. Repeating this (or sending one sufficiently large message) drives memory usage toward the heap limit, matching the `watchMemory()` OOM-crash guard: [7](#0-6) , confirming the process is designed to crash under exactly this kind of memory pressure rather than reject the oversized input up front.

### Citations

**File:** network.js (L2735-2742)
```javascript
function deleteOverlengthMessagesIfLimitIsSet(ws, device_address, handle){
	if (ws.max_message_length)
		db.query("DELETE FROM device_messages WHERE device_address=? AND LENGTH(message)>?", [device_address, ws.max_message_length], function(){
			return handle();
		});
	else
		return handle();
}
```

**File:** network.js (L3012-3014)
```javascript
			if (objLogin.max_message_length && !ValidationUtils.isPositiveInteger(objLogin.max_message_length))
				return sendError(ws, "max_message_length must be an integer");
			if (objLogin.max_message_count && (!ValidationUtils.isPositiveInteger(objLogin.max_message_count) || objLogin.max_message_count > 100))
```

**File:** network.js (L3509-3521)
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
```

**File:** network.js (L3554-3567)
```javascript
				var message_string = JSON.stringify(objDeviceMessage);
				db.query(
					"INSERT "+db.getIgnore()+" INTO device_messages (message_hash, message, device_address) VALUES (?,?,?)", 
					[message_hash, message_string, objDeviceMessage.to],
					function(){
						// if the addressee is connected, deliver immediately
						[...wss.clients].concat(arrOutboundPeers).forEach(function(client){
							if (client.device_address === objDeviceMessage.to && (!client.max_message_length || message_string.length <= client.max_message_length) && !client.blockChat) {
								sendJustsaying(client, 'hub/message', {
									message_hash: message_hash,
									message: objDeviceMessage
								});
							}
						});
```

**File:** network.js (L4306-4316)
```javascript
function watchMemory() {
	const v8 = require('v8');
	const THRESHOLD_PERCENT = 80;

	setInterval(() => {
		const stats = v8.getHeapStatistics();
		const usagePercent = (stats.used_heap_size / stats.heap_size_limit) * 100;
		if (usagePercent > THRESHOLD_PERCENT) // crash with uncaughtException before OOM
			throw new Error(`Memory usage is at ${usagePercent.toFixed(2)}%`);
	}, 5000); // Check every 5 seconds
}
```

**File:** device.js (L154-181)
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
			}
			catch(e){
				return respondWithError("failed to decrypt: " + e);
			}
```

**File:** device.js (L404-468)
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
```
