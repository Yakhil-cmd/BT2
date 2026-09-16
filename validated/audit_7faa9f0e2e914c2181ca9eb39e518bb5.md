### Title
Unauthenticated remote DoS via forced uncaught exception in encrypted device-message parsing - (File: `device.js`)

### Summary
`decryptPackage()` in `device.js` throws an unguarded `Error` from inside a `setTimeout` callback whenever an incoming encrypted device package cannot be matched to any known key. Because the throw happens asynchronously outside any try/catch, it becomes an uncaught exception that crashes the Node.js process, causing a denial of service. This is analogous to CVE-2017-12375, where malformed, attacker-supplied input reaching a message-parsing routine (`rfc2047` in `mbox.c`) without adequate validation led to an unhandled fault and a DoS condition — here the "fault" is a deliberately unguarded `throw` rather than a memory-safety bug, but the reachable outcome (crash of the scanning/parsing process on malformed peer-supplied input) is the same class.

### Finding Description
`decryptPackage()` is invoked when this device receives an encrypted message from a correspondent device (via the hub or directly). It performs only shallow type checks on `objEncryptedPackage` (that `iv`, `authtag`, `encrypted_message` are strings and `dh.*` fields exist), then tries to match `dh.recipient_ephemeral_pubkey` against the local temp/prev-temp/permanent device public keys: [1](#0-0) 

If none of the three keys match — which any correspondent (or anyone who can get a message routed to this device address, e.g. a paired device sending a stale/garbled/forged package) can trigger simply by sending an arbitrary `recipient_ephemeral_pubkey` value — the code schedules an unconditional `throw` 100 ms later: [2](#0-1) 

Because this `throw` executes inside a `setTimeout` callback, it is not inside the enclosing function's call stack and cannot be caught by any caller's try/catch (including the try/catch wrapping message dispatch in `wallet.js`'s `handleMessageFromHub`, which only guards synchronous exceptions): [3](#0-2) 

An uncaught exception thrown asynchronously terminates the Node.js process by default (no domain/global `uncaughtException` handler is shown wrapping this specific path), producing an immediate, remotely triggerable denial of service — the process must be restarted to resume normal operation (processing units, relaying payments, etc.).

### Impact Explanation
Any paired device (or any actor able to deliver a device-message payload to this node, e.g., via a compromised/malicious hub relaying spoofed packages, or a correspondent replaying an old package after a key rotation) can crash the node process by sending a single encrypted package whose `dh.recipient_ephemeral_pubkey` does not match a currently valid key. This satisfies the "network unable to confirm new units" / node-crash impact bar, since a crashed node stops validating and relaying units until manually restarted. It requires no valid decryption key and no prior authentication beyond being a correspondent device (or one able to reach the device's message-handling path), matching the CVE's "unauthenticated remote attacker sending crafted data causes DoS" pattern.

### Likelihood Explanation
Likelihood is high for any already-paired correspondent, and plausible even for less-trusted paths (e.g., a hub that already relays arbitrary JSON to the device, or a stale/duplicate package after this device rotates its temp key — `objMyPrevTempDeviceKey` covers only one prior generation, so replays after two rotations, or simply garbage `recipient_ephemeral_pubkey` values, reliably hit the `else` branch). No cryptographic material or valid signature is needed to reach the vulnerable branch — the `dh` sub-object need only have string-typed fields.

### Recommendation
- Do not `throw` from the `setTimeout` callback; instead, log and emit a `nonfatal_error` event (the already-present but commented-out `eventBus.emit('nonfatal_error', ...)` line) and return normally.
- If keeping a delayed diagnostic throw is desired, wrap it so it cannot escalate to a process crash (e.g., use `eventBus.emit` and/or explicit `process.on('uncaughtException')`-safe handling), or remove the artificial delay/throw entirely and simply log the condition synchronously.
- Add a global safety net (`process.on('uncaughtException')`/`unhandledRejection`) that prevents a single malformed device message from being able to terminate the entire node process.

### Proof of Concept
1. Attacker (any paired correspondent device, or an intermediary hub relaying an attacker-supplied device message) sends a `device` message whose JSON body is an "encrypted_package"-style object:
```json
{
  "iv": "<any 16 valid base64 bytes>",
  "authtag": "<any 16 valid base64 bytes>",
  "encrypted_message": "<any base64 bytes>",
  "dh": {
    "sender_ephemeral_pubkey": "<any valid base64 pubkey>",
    "recipient_ephemeral_pubkey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="  // does not match temp/prev-temp/permanent keys
  }
}
```
2. The receiving node's `decryptPackage()` fails to match the `recipient_ephemeral_pubkey`, logs "message encrypted to unknown key", and schedules the `setTimeout(() => { throw Error(...) }, 100)`.
3. 100 ms later, the process throws an uncaught exception and crashes, taking the node offline. [4](#0-3)

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

**File:** wallet.js (L75-81)
```javascript
		try {
			doHandle();
		}
		catch (e) {
			callbacks.ifError("exception in handleMessageFromHub: " + e.toString());
		}
	});
```
