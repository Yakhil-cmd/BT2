### Title
Malformed Encrypted Device Package Crashes the Whole Node via Uncaught Async Exception - (File: device.js)

### Summary
`decryptPackage()` in `device.js` throws an `Error` inside a `setTimeout` callback when a received encrypted device package cannot be matched to any known key. Because the throw happens asynchronously (outside of any surrounding `try/catch`), it becomes an uncaught exception that propagates to the global `process.on('uncaughtException', ...)` handler in `network.js`, which explicitly re-throws it to crash the whole process. This mirrors the CVE-2019-3011 bug class: a low-privileged, network-reachable actor sending malformed/unrecognized input triggers a crash/hang (denial of service) of the server process.

### Finding Description
`decryptPackage()` validates the shape of an incoming encrypted package and determines which key (temp, previous temp, or permanent) should be used for decryption based on `objEncryptedPackage.dh.recipient_ephemeral_pubkey`: [1](#0-0) 

When none of the known keys match, the function schedules a `throw` inside `setTimeout`, which is not wrapped in try/catch by any caller since it fires later on the event loop: [2](#0-1) 

This asynchronous throw becomes an uncaught exception. In `network.js`, the global `uncaughtException` handler logs diagnostic data and then intentionally re-throws the error to crash the process: [3](#0-2) 

An attacker only needs to be a paired correspondent device (or anyone able to reach the hub delivery path and address a device with a `recipient_ephemeral_pubkey` that isn't currently valid) to have an encrypted package delivered to a target device/wallet. A `recipient_ephemeral_pubkey` that doesn't correspond to the current temp key, previous temp key, or permanent key (e.g., a stale, tampered, or fabricated value) is enough to hit this branch, since key rotation naturally invalidates old temp keys and any mismatch — malicious or simply due to timing/rotation — reaches the same code path.

Note: I was unable to fully trace, within the available context, the exact top-level network handler (e.g., `hub/deliver`/`hub/deliver_message` request processing in `network.js`) that invokes `decryptPackage()` for an inbound device message before it reaches `handleMessageFromHub` in `wallet.js`, because the relevant call sites in `device.js`/`wallet.js` were only partially returned by search. The wrapping in `wallet.js`'s `handleMessageFromHub` catches synchronous exceptions via `try { doHandle(); } catch (e) { ... }`, but this catch cannot intercept the asynchronous `throw` inside `setTimeout` in `decryptPackage()`, since that throw fires on a separate tick of the event loop after the surrounding try/catch has already returned.

### Impact Explanation
A successful trigger crashes the entire ocore process (wallet, hub, or full node), not just the connection or peer session. In `network.js` the uncaught-exception handler deliberately calls `throw err` again to abort the process rather than attempt recovery, explicitly stating this is "to avoid ending up in an inconsistent state." For a wallet application receiving device messages, this results in denial of service to the end user (wallet becomes unusable / repeatedly crashes on restart if the poison message is retried). For a hub or any node acting as a paired device, this is a full node crash reachable by any correspondent that has previously been paired (a normal, low-privilege relationship, matching CVSS `PR:L` in the reference CVE) — no special network-level or infrastructure privilege is required, only a valid pairing/device relationship.

### Likelihood Explanation
Triggering the condition requires only sending an encrypted package object whose `dh.recipient_ephemeral_pubkey` does not match any of the three known keys (temp, previous temp, or permanent) for the targeted device — a condition trivially reachable by a correspondent device (or by racing/stale delivery around a key-rotation window) without needing to defeat any cryptography. The `depth`/format checks preceding this branch (`typeof ... !== 'string'`, etc.) are easily satisfied with a well-formed but semantically "wrong-key" package.

### Recommendation
- Do not `throw` asynchronously in a `setTimeout` callback for this normal/anticipated error condition; replace it with a caught error path (e.g., `eventBus.emit('nonfatal_error', ...)`, which is already present as a commented-out alternative) so the failure is reported without crashing the process.
- Ensure `decryptPackage()` returns an error result synchronously to its caller instead of relying on a delayed throw, and make sure both `wallet.js`'s `doHandle()`/`handleMessageFromHub` and any hub-side handler wrap all reachable code paths (including scheduled callbacks) so unrecognized-key packages fail closed per-message rather than crashing the whole node.
- Reassess whether `process.on('uncaughtException')` should always re-throw and kill the process, or whether specific, expected/recoverable error classes (like this one) should be filtered out before reaching that handler.

### Proof of Concept
1. Pair with (or reuse an existing pairing to) a target device/wallet running ocore.
2. Construct/send (via the hub delivery path) an encrypted device package with a syntactically valid shape (`iv`, `authtag`, `encrypted_message` as strings, and `dh` as an object with string `sender_ephemeral_pubkey`/`recipient_ephemeral_pubkey`) but with `dh.recipient_ephemeral_pubkey` set to an arbitrary/unrelated base64 public key value that does not match the target's current temp key, previous temp key, or permanent key.
3. On receipt, `decryptPackage()` in `device.js` (lines 404-436) fails to match any key and schedules `setTimeout(() => { throw Error(...) }, 100)`.
4. After 100ms, the thrown error is uncaught, propagates to `process.on('uncaughtException')` in `network.js` (lines 4530-4543), which logs it and re-throws, terminating the ocore process for all users of that node/wallet.

### Citations

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
