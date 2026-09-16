This confirms the analog vulnerability. Any client connected to a hub can call `hub/get_temp_pubkey` with an arbitrary `permanent_pubkey` and learn whether that device is registered on this hub (device enumeration) and whether it has a temp pubkey set — no check that the requester is a paired correspondent of that device.

### Title
Unauthenticated device-registration/enumeration leak via `hub/get_temp_pubkey` - (File: network.js)

### Summary
The hub-side handler for the `hub/get_temp_pubkey` request accepts any device's permanent pubkey from any connected peer and returns whether that device is registered on the hub and its cached temporary pubkey package, without verifying that the requester is a paired correspondent of the target device.

### Finding Description
In `network.js` inside `handleRequest`, the `hub/get_temp_pubkey` case computes `device_address` from the caller-supplied `permanent_pubkey` and, when the hub serves as a hub (`conf.bServeAsHub`), queries `SELECT temp_pubkey_package FROM devices WHERE device_address=?` [1](#0-0) . The only checks performed are on the pubkey's length and whether the hub is configured to serve as a hub; there is no verification that `ws` (the requesting connection) is an authorized correspondent of `device_address`, nor any rate limiting or access control tied to pairing state. This is structurally the same class of bug as the Synapse advisory: cached per-device metadata (`temp_pubkey_package`, and implicitly device registration status) can be queried for arbitrary remote-user devices by unauthorized third parties, enabling enumeration of devices/users known to the hub. Registration status is directly observable from the two distinct error branches — `"device with this pubkey is not registered here"` versus `"temp pub key not set yet"` — which act as an oracle distinguishing "unknown device" from "known device, no temp key" from "known device, here is the temp key" [2](#0-1) . This is reachable by any peer that can open a websocket connection to the hub and does not require pairing, correspondent status, or any prior relationship with the target device or the hub operator's user base.

By contrast, the related `hub/deliver` handler, which actually forwards messages, at least requires the device to be registered and matches the encryption key, but still doesn't require the sender to be a correspondent of the recipient [3](#0-2) ; combined with `hub/get_temp_pubkey`, an attacker can systematically probe arbitrary permanent pubkeys (which they can derive off-band, e.g. via `objectHash.getDeviceAddress`) to enumerate which devices/users are hosted on a given hub.

### Impact Explanation
This leaks metadata about which device addresses (and by extension which wallet/AA users) are registered/paired via a specific hub, and whether their temp pubkey has been set (indicating device activity/liveness). This enables user enumeration and correlation attacks against hub-hosted wallets, similar to Synapse's remote-user enumeration issue. It does not by itself allow spending, double-spend, or AA fund manipulation, but it is a confidentiality leak (CWE-200) of device/user presence information reachable by any unauthenticated network peer.

### Likelihood Explanation
High likelihood of exploitation: no authentication, pairing, or prior relationship is required. An attacker only needs a permanent device pubkey (which can be derived from any previously observed device address/message) and a websocket connection to the target hub.

### Recommendation
Restrict `hub/get_temp_pubkey` responses to require that the requesting device (`ws.device_address`, after login) is a confirmed correspondent of the target device, or otherwise limit/rate-limit and unify error responses (e.g., a single generic "not found" error) so registration status cannot be distinguished by unauthenticated peers.

### Proof of Concept
1. Connect to a hub over websocket without pairing with any of its clients.
2. Send `hub/get_temp_pubkey` with a target device's known permanent pubkey (e.g., harvested from a publicly shared pairing code/QR).
3. Observe the distinct responses: `"device with this pubkey is not registered here"` (device not on this hub) vs. `"temp pub key not set yet"` (device registered here) vs. the actual `temp_pubkey_package` (device active) — enumerating hub users without ever pairing with them, as seen in `network.js` lines 3583-3600 [1](#0-0) .

### Citations

**File:** network.js (L3544-3553)
```javascript
			db.query("SELECT pubkey, temp_pubkey_package FROM devices WHERE device_address=?", [objDeviceMessage.to], function(rows){
				if (rows.length === 0)
					return sendErrorResponse(ws, tag, "address "+objDeviceMessage.to+" not registered here");
				let keys = [rows[0].pubkey];
				if (rows[0].temp_pubkey_package) {
					var objTempPubkey = JSON.parse(rows[0].temp_pubkey_package);
					keys.push(objTempPubkey.temp_pubkey);
				}
				if (!keys.includes(objDeviceMessage.encrypted_package.dh.recipient_ephemeral_pubkey))
					return sendErrorResponse(ws, tag, "wrong recipient ephemeral pubkey");
```

**File:** network.js (L3583-3600)
```javascript
		// I'm a hub, the peer wants to get a correspondent's temporary pubkey
		case 'hub/get_temp_pubkey':
			var permanent_pubkey = params;
			if (!ValidationUtils.isStringOfLength(permanent_pubkey, constants.PUBKEY_LENGTH))
				return sendErrorResponse(ws, tag, "wrong permanent_pubkey length");
			var device_address = objectHash.getDeviceAddress(permanent_pubkey);
			if (device_address === my_device_address) // to me
				return sendResponse(ws, tag, objMyTempPubkeyPackage); // this package signs my permanent key
			if (!conf.bServeAsHub)
				return sendErrorResponse(ws, tag, "I'm not a hub");
			db.query("SELECT temp_pubkey_package FROM devices WHERE device_address=?", [device_address], function(rows){
				if (rows.length === 0)
					return sendErrorResponse(ws, tag, "device with this pubkey is not registered here");
				if (!rows[0].temp_pubkey_package)
					return sendErrorResponse(ws, tag, "temp pub key not set yet");
				var objTempPubkey = JSON.parse(rows[0].temp_pubkey_package);
				sendResponse(ws, tag, objTempPubkey);
			});
```
