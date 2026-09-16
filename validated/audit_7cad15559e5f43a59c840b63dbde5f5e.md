### Title
Denial of Service via malformed `recipient_ephemeral_pubkey` in device message causes delayed uncaught exception that crashes the node process - ([File: device.js])

### Summary
`decryptPackage()` in `device.js` schedules a bare `throw Error(...)` inside a `setTimeout` callback when a device message's encryption target key does not match any of the node's known device keys. Because the throw fires asynchronously, outside the synchronous `try/catch` that wraps the `decryptPackage()` call in the caller, it becomes an uncaught exception. `network.js` installs a global `process.on('uncaughtException', ...)` handler that deliberately re-throws to terminate the process. Any remote party able to address a `hub/message` to the victim's device address (no prior pairing is required to trigger this specific code path) can crash the entire ocore process with a single malformed message — directly analogous to the webpack-dev-server bug class where a malformed header field triggers an uncaught exception that kills the process.

### Finding Description
`decryptPackage()` first validates the shape of `objEncryptedPackage.dh` and then checks whether `dh.recipient_ephemeral_pubkey` equals one of the node's known keys (current temp key, previous temp key, or permanent key). If none match, it does: [1](#0-0) 

The `throw` executes ~100ms later, on a fresh call stack, so it is not caught by the synchronous `try { var json = decryptPackage(...) } catch(e){...}` block that wraps the call at the message-handling site: [2](#0-1) 

The uncaught exception is picked up by the global handler in `network.js`, which intentionally re-throws to kill the process: [3](#0-2) 

The `hub/message` handler that leads to this call performs only structural field checks and verifies that the message is self-consistently signed by the sender's own claimed `pubkey` (an attacker trivially satisfies this using their own keypair) — it does not require the sender to be a known/paired correspondent before `decryptPackage()` is invoked: [4](#0-3) 

The correspondent-known/whitelisted-subject check happens only after decryption, i.e., after the crash has already occurred: [5](#0-4) 

A self-hosted hub (`bToMe`) path in `network.js` re-emits `message_from_hub` without validating `recipient_ephemeral_pubkey` against the node's registered keys at all, so an attacker delivering `hub/deliver` directly to a node acting as its own hub reaches the vulnerable code even more directly: [6](#0-5) 

### Impact Explanation
This is a full denial-of-service of a running ocore node/wallet/witness process: a single crafted `hub/message` (or `hub/deliver` for self-hosted hubs) with an arbitrary/non-matching `dh.recipient_ephemeral_pubkey` crashes the process outright, requiring the operator to restart it. No decryption material, valid ciphertext, or pairing relationship with the victim is required — only that the message pass field-shape checks and be self-signed by the attacker's own key. For witnesses, hubs acting as light vendors, or wallets, this halts unit posting/AA trigger processing/light vendor service until manual restart, matching the "network unable to confirm new units" impact class for the affected node.

### Likelihood Explanation
Likelihood is high: the message only needs valid `iv`, `authtag`, `encrypted_message` (any strings), `dh.sender_ephemeral_pubkey`, and a `dh.recipient_ephemeral_pubkey` that simply does not equal any of the node's 3 known keys — trivially satisfiable with a random 32-byte base64 string. The outer message (`objDeviceMessage`) only needs a valid self-signature, which any attacker can produce with their own keypair. No pairing, correspondent relationship, or hub compromise is required for the basic `hub/message` delivery path.

### Recommendation
Do not schedule the `throw` inside `setTimeout` in `decryptPackage()`. Instead, log the anomaly (optionally via `eventBus.emit('nonfatal_error', ...)`, which is already commented out in the code) and return `null` synchronously without ever throwing asynchronously and unrecoverably. If a hard crash-and-restart is intentionally desired for this diagnostic scenario, it should not be reachable from unauthenticated/unpaired input — at minimum this event should require confirmation that the sender is a known correspondent before triggering any crash behavior.

### Proof of Concept
1. Attacker generates their own device keypair (`pubkey_A`, `priv_A`) and computes `device_address_A`.
2. Attacker crafts `objDeviceMessage`:
   - `to`: victim's device address
   - `pubkey`: `pubkey_A`
   - `encrypted_package`: `{ iv: <base64>, authtag: <base64>, encrypted_message: <base64 garbage>, dh: { sender_ephemeral_pubkey: <any valid-looking base64 pubkey>, recipient_ephemeral_pubkey: <random base64 string not equal to victim's temp/prev-temp/permanent pub keys> } }`
   - `signature`: signs `objectHash.getDeviceMessageHashToSign(objDeviceMessage)` with `priv_A` (self-consistent, always verifies).
3. Attacker delivers this via `hub/deliver` to the victim's hub (or directly as `hub/message` if attacker controls a relay/hub), targeting the victim's `device_address`.
4. Victim's `handleJustsaying` `'hub/message'` case passes field/signature checks, calls `decryptPackage()`.
5. `decryptPackage()` finds no key match for `recipient_ephemeral_pubkey`, schedules `setTimeout(() => { throw Error(...) }, 100)`.
6. 100ms later the timer fires; the thrown error is uncaught, triggers `process.on('uncaughtException')` in `network.js`, which re-throws — the ocore process crashes.

### Citations

**File:** device.js (L146-184)
```javascript
		// I'm connected to a hub, received a message through the hub
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
			if (!json)
				return respondWithError("failed to decrypt");
			
```

**File:** device.js (L203-221)
```javascript
			// check that we know this device
			db.query("SELECT hub, is_indirect FROM correspondent_devices WHERE device_address=?", [from_address], function(rows){
				if (rows.length > 0){
					if (json.device_hub && typeof json.device_hub === 'string' && json.device_hub.length <= 200 && network.isValidWsUrl(conf.WS_PROTOCOL + json.device_hub) && json.device_hub !== rows[0].hub) // update correspondent's home address if necessary
						db.query("UPDATE correspondent_devices SET hub=? WHERE device_address=?", [json.device_hub, from_address], function(){
							handleMessage(rows[0].is_indirect);
						});
					else
						handleMessage(rows[0].is_indirect);
				}
				else{ // correspondent not known
					var arrSubjectsAllowedFromNoncorrespondents = ["pairing", "my_xpubkey", "wallet_fully_approved"];
					if (arrSubjectsAllowedFromNoncorrespondents.indexOf(json.subject) === -1){
						respondWithError("correspondent not known and not whitelisted subject");
						return;
					}
					handleMessage(false);
				}
			});
```

**File:** device.js (L429-436)
```javascript
	else{
		console.log("message encrypted to unknown key");
		setTimeout(function(){
			throw Error("message encrypted to unknown key, device "+my_device_address+", len="+objEncryptedPackage.encrypted_message.length+". The error might be caused by restoring from an old backup or using the same keys on another device.");
		}, 100);
	//	eventBus.emit('nonfatal_error', "message encrypted to unknown key, device "+my_device_address+", len="+objEncryptedPackage.encrypted_message.length, new Error('unknown key'));
		return null;
	}
```

**File:** network.js (L3534-3542)
```javascript
			// if i'm always online and i'm my own hub
			if (bToMe){
				sendResponse(ws, tag, "accepted");
				eventBus.emit("message_from_hub", ws, 'hub/message', {
					message_hash,
					message: objDeviceMessage
				});
				return;
			}
```

**File:** network.js (L4530-4543)
```javascript
process.on('uncaughtException', (err) => {
	console.log('Uncaught exception:', err);
	console.error('Uncaught exception:', err);
	if (!conf.bLight) {
		let hosts = [...Object.keys(messagesInWork), ...Object.keys(requestsInWork)];
		if (currentJointHost)
			hosts.push(currentJointHost);
		console.log('Clients with pending requests/messages at the time of uncaught exception:', hosts);
		const fs = require('fs');
		const app_data_dir = require('./desktop_app.js').getAppDataDir();
		fs.writeFileSync(`${app_data_dir}/uncaught_exception_clients.txt`, hosts.concat(Object.keys(assocBlockedPeers)).join('\n'), 'utf8');
	}
	throw err; // crash the process to avoid ending up in an inconsistent state
});
```
