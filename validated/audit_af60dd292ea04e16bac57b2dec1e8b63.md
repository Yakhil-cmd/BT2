### Title
Remote crash via device message encrypted to an unrecognized ephemeral key - ([File: device.js])

### Summary
`device.js`'s `decryptPackage()` explicitly throws an uncaught `Error` (via `setTimeout`) whenever an incoming device message's `dh.recipient_ephemeral_pubkey` does not match the node's known temp/prev-temp/permanent device keys. Because the top-level `process.on('uncaughtException', ...)` handler in `network.js` re-throws to crash the process, any unprivileged peer who can deliver a device message to a node's public device address can remotely crash that node. This mirrors CVE-2023-4012's bug class: the code fails to gracefully distinguish/handle an "unexpected internal state" (message addressed to a key state the node doesn't currently hold) and instead crashes.

### Finding Description
`decryptPackage()` in `device.js` checks the recipient ephemeral pubkey embedded in an incoming encrypted device message against `objMyTempDeviceKey`, `objMyPrevTempDeviceKey`, and `objMyPermanentDeviceKey`. If none matches, it logs "message encrypted to unknown key" and deliberately schedules a fatal, uncaught `Error` via `setTimeout`: [1](#0-0) 

This function is reached from the normal, unauthenticated device-message intake path. `handleJustsaying()` processes `hub/message` justsayings; it validates the message shape and an ECDSA signature that is fully attacker-controlled (attacker signs with their own `pubkey`), then calls `decryptPackage(objDeviceMessage.encrypted_package)`: [2](#0-1) 

Crucially, an attacker does not need to be an already-paired correspondent: `"pairing"`, `"my_xpubkey"`, and `"wallet_fully_approved"` subjects (and thus messages targeting an unpaired device address) are explicitly whitelisted from unknown senders, and even for correspondents, the sender only needs a valid self-signature — not knowledge of the recipient's real key state: [3](#0-2) 

An attacker can supply an `encrypted_package` whose `dh.recipient_ephemeral_pubkey` is an arbitrary value that intentionally does not correspond to any of the victim's current keys (e.g., a stale/garbage ephemeral pubkey), forcing execution into the `else` branch of `decryptPackage`.

Once the `Error` fires inside the `setTimeout` callback, it becomes an uncaught exception. The global handler in `network.js` re-throws it by design: [4](#0-3) 

This crashes the full node process — a hub, witness, or any online full node reachable at its device address — purely from a single unauthenticated/self-signed device message, with no valid pairing or prior relationship required.

### Impact Explanation
This is a straightforward remote, unauthenticated denial-of-service against any ocore node (including hubs and witnesses) that exposes a `my_device_address`. A single crafted device message crashes the node process. For witnesses or hubs this can disrupt network confirmation/availability (witnesses unable to sign, hub clients unable to relay/pair), and is trivially repeatable since the attacker only needs to know the victim's public device address (routinely shared for pairing).

### Likelihood Explanation
High likelihood: the attacker doesn't need any relationship with the target (whitelisted subjects like `"pairing"`, `"my_xpubkey"` allow delivery from unknown correspondents), and the signature check is self-signed and thus always satisfiable by the attacker. Crafting a `dh.recipient_ephemeral_pubkey` value that is guaranteed to not match any of the victim's live keys is trivial (any fixed random 33/65-byte base64 pubkey string not currently in use). The vulnerable code path is on the default hot path for handling `hub/message`.

### Recommendation
Do not throw/crash on "message encrypted to unknown key." Treat this as a recoverable, expected external-input error: return `null` (as the function already does) and let the caller (`respondWithError`) report the failure back over the protocol, without scheduling an uncaught exception. If diagnostic visibility is desired, emit a `nonfatal_error` event (the code already has this commented out) rather than throwing asynchronously.

### Proof of Concept
1. Obtain the victim node's public device address (`my_device_address`), e.g. via a pairing link/QR code that is routinely shared.
2. As an attacker, generate your own device keypair and self-sign a `hub/message` justsaying whose `objDeviceMessage.to` equals the victim's device address, with `subject: "pairing"` (or any subject) in the decrypted body.
3. Set `encrypted_package.dh.recipient_ephemeral_pubkey` to an arbitrary base64 pubkey string that is guaranteed not to equal the victim's current temp/prev-temp/permanent device key (e.g., a freshly generated throwaway pubkey never used by the victim).
4. Deliver this justsaying to the victim (directly if connected, or via `hub/deliver` to the victim's hub) so it reaches `device.js`'s `handleJustsaying` → `decryptPackage()`.
5. The victim's `decryptPackage()` hits the `else` branch, schedules the fatal `Error` via `setTimeout`, which fires 100ms later as an uncaught exception; `network.js`'s handler re-throws it, crashing the victim's node process.

### Citations

**File:** device.js (L154-184)
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
			if (!json)
				return respondWithError("failed to decrypt");
			
```

**File:** device.js (L213-221)
```javascript
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
