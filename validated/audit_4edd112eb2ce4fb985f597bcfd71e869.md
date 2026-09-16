### Title
Unbounded-length "text" message from a paired device causes O(n) regex/emit DoS on wallet - (File: wallet.js)

### Summary
`handleMessageFromHub`'s `text` subject handler accepts a `body` string of unbounded length from any paired (or even not-yet-confirmed, in some subjects) device and runs it through four global regex `.replace()` passes before emitting it to the UI/event bus, with no length cap enforced on `body` itself.

### Finding Description
When a wallet receives a device message with `subject: "text"`, the only check performed is that `body` is a non-empty string: [1](#0-0) 
There is no `MAX_TEXT_LENGTH`-style bound on `body.length` anywhere in this path. The earlier guard in the same function, `isTooDeeplyNestedOrHasTooManyNodes(json, 20, 100000)`, only limits the number of JSON *nodes* and nesting depth of the whole message — a single giant string value counts as one node and is therefore not rejected regardless of its size: [2](#0-1) [3](#0-2) 
The message reaches this handler after `device.js` decrypts the AES-GCM package and `JSON.parse`s it, again with no length restriction on individual string fields, only depth/authtag/format checks: [4](#0-3) 
Once inside the handler, `body` (potentially megabytes/gigabytes long, bounded only by whatever the hub/device layer allows to be stored/relayed) is scanned four times with unanchored, greedy-search regexes (`/\(prosaic-contract:.+?\)/g`, etc.) before being emitted via `eventBus.emit("text", ...)`, which is consumed directly by wallet UI code. This is directly analogous to the reported bug class: an attacker-controlled field (there: an oversized filename in form-data; here: an oversized `text` message body from a device) is processed without an upper bound before expensive work is performed, leading to CPU/memory exhaustion and unresponsiveness of the victim's node/wallet process.

### Impact Explanation
A paired device (or, for subjects on the whitelist like non-correspondents sending certain subjects) can push an arbitrarily large `text` payload through the hub relay to a victim wallet. Since ocore's Node.js event loop is single-threaded, repeated large-string regex scanning and JSON stringify/parse of such payloads can stall the process, delaying processing of legitimate unit validation, payment handling, and network messages — a Denial of Service consistent with CVSS availability impact (`A:H`) in the referenced advisory. This does not directly cause fund loss, but it can freeze a node/wallet's ability to confirm or relay transactions while under attack, aligning with the "network unable to confirm new units" acceptance criterion for a single victim node.

### Likelihood Explanation
The `text` subject is reachable by any device that has been paired (a normal user action, not requiring hub or node compromise), and the message pipeline performs no length validation before the regex work runs. The attack requires only sending one signed, correctly encrypted device message — well within reach of a malicious paired counterparty and standard wallet-to-wallet correspondence.

### Recommendation
Enforce an explicit maximum length on `body` (and other free-form fields such as `object`) in `handleMessageFromHub`'s `text` case before running the `.replace()` regex passes, e.g. reject with `callbacks.ifError("text too long")` if `body.length` exceeds a small constant (comparable to `MAX_AA_STRING_LENGTH` or a dedicated `MAX_DEVICE_TEXT_LENGTH`). Consider also tightening `isTooDeeplyNestedOrHasTooManyNodes`/adding a companion `isTooBigObj` check (already present in `string_utils.js`) on the decrypted `json` in `handleMessageFromHub`, since that utility does bound total string length and is not currently applied here.

### Proof of Concept
1. Pair an attacker device with the victim wallet (or use `pairing`/whitelisted subjects to become a "correspondent").
2. Construct a device message `{ subject: "text", body: "A".repeat(50_000_000) }` (or larger), encrypt it with `createEncryptedPackage` to the victim's pubkey, sign it, and deliver it via `hub/deliver`/`hub/message` as in `device.js:134-223` and `network.js:3508-3582`.
3. On receipt, the victim's `handleMessageFromHub` passes the `isTooDeeplyNestedOrHasTooManyNodes` check (single large string, node count = 1) and proceeds to run four global regex replacements over the ~50MB string before emitting it, consuming CPU/memory disproportionate to message size and stalling the wallet's single-threaded event loop.

### Citations

**File:** wallet.js (L65-66)
```javascript
	if (isTooDeeplyNestedOrHasTooManyNodes(json, 20, 100000))
		return callbacks.ifError("message from hub is too deeply nested or has too many nodes");
```

**File:** wallet.js (L101-112)
```javascript
			case "text":
				message_counter++;
				if (!ValidationUtils.isNonemptyString(body))
					return callbacks.ifError("text body must be string");
				body = body
					.replace(/\(prosaic-contract:.+?\)/g, '')
					.replace(/\(arbiter-contract-offer:.+?\)/g, '')
					.replace(/\(arbiter-contract-event:.+?\)/g, '')
					.replace(/\(arbiter-dispute:.+?\)/g, '');
				// the wallet should have an event handler that displays the text to the user
				eventBus.emit("text", from_address, body, message_counter);
				callbacks.ifOk();
```

**File:** string_utils.js (L260-284)
```javascript
function isTooDeeplyNestedOrHasTooManyNodes(obj, depthLimit = 100, nodesLimit = 10000) {
	let nodeCount = 0;

	function check(variable, depth){
		if (depth > depthLimit || nodeCount > nodesLimit)
			return true;
		if (variable === null || typeof variable !== "object")
			return false;
		if (Array.isArray(variable)) {
			nodeCount += variable.length;
			for (let v of variable)
				if (check(v, depth + 1))
					return true;
		}
		else {
			nodeCount += Object.keys(variable).length;
			for (let key in variable)
				if (check(variable[key], depth + 1))
					return true;
		}
		return false;
	}

	return check(obj, 1);
}
```

**File:** device.js (L404-479)
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
