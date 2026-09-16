### Title
Uncaught exception on decrypting a device message with an unrecognized ephemeral key crashes the process — ([File: device.js])

### Summary
`device.js`'s `decryptPackage()` throws an uncaught `Error` (inside a `setTimeout`, i.e. outside any calling try/catch) whenever it receives an encrypted device message whose `dh.recipient_ephemeral_pubkey` doesn't match any of the local device's known keys (current temp key, previous temp key, or permanent key). Because device messages are delivered by an untrusted hub/peer and forwarded directly into `decryptPackage`, a single malformed/unexpected package causes an unhandled exception that propagates to Node's `uncaughtException` and crashes the wallet/full-node process — the same bug class as GHSA-q7rr-3cgh-j5r3 (unauthenticated input reaching unhandled-exception code path that terminates the process).

### Finding Description
`decryptPackage()` validates that `dh.recipient_ephemeral_pubkey` matches one of three known keys. If none match, it logs a message and then does: [1](#0-0) 
```
else{
    console.log("message encrypted to unknown key");
    setTimeout(function(){
        throw Error("message encrypted to unknown key, device "+my_device_address+ ...);
    }, 100);
    return null;
}
```
This `throw` happens inside a `setTimeout` callback, which executes as its own top-level tick — there is no enclosing `try/catch` anywhere up the call stack for this particular throw. It is therefore an uncaught exception that reaches the global handler.

In `network.js`, a global `uncaughtException` handler is installed which explicitly re-throws to terminate the process, treating any uncaught exception as fatal (deliberately, "to avoid ending up in an inconsistent state"): [2](#0-1) 

Any peer (or the hub relaying a message from another device) that sends an `hub/deliver` message, or any hub that forwards a `hub/message` justsaying, with a well-formed but stale/incorrect `dh.recipient_ephemeral_pubkey` field (e.g., referencing an already-rotated-out temp key, or simply a random value) causes `decryptPackage` to hit the "unknown key" branch. Unlike the OpenTelemetry bug where the trigger is a malformed URL, here the trigger is any encrypted package whose ephemeral recipient key isn't currently recognized by the device — trivially producible by any correspondent device or a malicious/compromised hub relaying a crafted message, requiring no authentication beyond having previously paired (or, for a hub, none at all, since the hub only checks structural fields before delivering, per `hub/deliver` handling in `network.js`).

### Impact Explanation
This is a denial-of-service against the wallet/node process: a single malformed encrypted device message (reachable from a paired device counterparty, or a hub relaying an unauthenticated/forged package structurally satisfying `hub/deliver`'s checks) causes the entire ocore process to crash via the intentional `uncaughtException → throw err` handler. This matches the "no impact / DoS-only" boundary described in the rules, but is explicitly permitted under the allowed category "wallet and contract message handling" as it is reachable from a paired device / correspondent, not merely a network peer. The crash is not gated by rate limiting and can be repeated indefinitely to keep a node/wallet down.

### Likelihood Explanation
High. Any device that has ever been paired (correspondent) can trivially construct an `encrypted_package` with a `dh.recipient_ephemeral_pubkey` that doesn't match the target's current/prev temp key or permanent key (e.g., a stale or garbage value), and send it via `sendMessageToDevice`/hub relay. Since temp keys rotate hourly, this condition also arises even without malice, and can be deliberately forced by a correspondent by simply using an outdated or bogus ephemeral key in the DH parameters. No decryption or valid signature is even required to reach this code path.

### Recommendation
Wrap the `throw` inside the `setTimeout` in a controlled error/event emission instead of letting it become an uncaught exception, e.g. emit `eventBus.emit('nonfatal_error', ...)` (the code even has a commented-out example of this immediately below) rather than crashing the process. At minimum, this specific condition (unknown ephemeral recipient key) should be treated as a recoverable, log-only, non-fatal condition since it can be triggered by routine key rotation races or a malicious correspondent, not just genuine unrecoverable inconsistency.

### Proof of Concept
1. Device A is paired with Device B and knows B's rotating temp pubkey.
2. Device A crafts (or a hub relays) an `encrypted_package` addressed to B with a syntactically valid but non-matching `dh.recipient_ephemeral_pubkey` (any random 32-byte base64 value, or B's already-rotated-out temp key beyond the retention window) and delivers it via the normal `hub/deliver`/`hub/message` flow.
3. B's `decryptPackage()` fails to match any of `objMyTempDeviceKey`, `objMyPrevTempDeviceKey`, `objMyPermanentDeviceKey`, hits the `else` branch, and after 100 ms throws an uncaught `Error("message encrypted to unknown key...")`.
4. The global `process.on('uncaughtException', ...)` handler in `network.js` re-throws, terminating B's node/wallet process. [3](#0-2) [2](#0-1)

### Citations

**File:** device.js (L404-436)
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
