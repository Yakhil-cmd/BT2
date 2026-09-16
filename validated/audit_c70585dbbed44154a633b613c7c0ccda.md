## Finding [1](#0-0) [2](#0-1) [3](#0-2) 

### Title
Unprivileged Re-Pairing Message Unconditionally Clears `is_blackhole` and Bypasses User-Imposed Device Block - (File: device.js)

### Summary
`ocore`'s device-pairing protocol contains the same bug class as the Vikunja advisory: a state field that represents a security decision (here, `correspondent_devices.is_blackhole`, which silences a device the user has chosen to block/unpair) is unconditionally reset by a routine, unprivileged operation (`handlePairingMessage`) without checking whether that device was previously blacklisted by the local user.

### Finding Description
When a paired device sends `removed_paired_device` and the local wallet is configured with `conf.bIgnoreUnpairRequests`, the wallet does not actually drop the correspondent; instead it marks it as a "blackhole" so that outbound messages to that device are silently suppressed: [4](#0-3) 

This `is_blackhole` flag is enforced in `sendMessageToDevice`, which checks the flag before sending any subsequent message (signing requests, shared-address invitations, private-payment chains, arbiter contracts, etc.) to that device: [5](#0-4) 

However, `handlePairingMessage` — the handler for the `pairing` subject, reachable from any device that supplies a valid (possibly reusable/permanent) `pairing_secret` — unconditionally clears the flag for the sender's device address as soon as the pairing record is (re-)inserted, with no check of the correspondent's current `is_blackhole` state: [6](#0-5) 

Because pairing secrets can be permanent (`is_permanent=1`, matched via the wildcard `'*'`) or the peer may already know a previously-issued (reverse) pairing secret, a device that the user had already deliberately silenced can simply re-send a `pairing` message to reactivate itself as a full correspondent — exactly analogous to how Vikunja's `ResetPassword()` unconditionally set `user.Status = StatusActive` regardless of prior `StatusDisabled`.

### Impact Explanation
Once `is_blackhole` is cleared, the wallet resumes treating the previously-blocked device as a normal, trusted correspondent, resuming delivery of `arbiter_contract_shared`, shared-address definitions, signing requests, and private-payment payloads to it (all handled in `wallet.js`'s `handleMessageFromHub`). If the user's device automatically responds to signing/multisig requests from known correspondents (a common wallet workflow for shared/multisig addresses), this reactivation can result in unauthorized cosigning/spending requests being accepted from a device the user had explicitly decided to silence, as well as re-exposure of private payment chains and contract data to a device that was supposed to be blocked.

### Likelihood Explanation
The `pairing` message path is reachable by any device that possesses (or replays) a still-valid pairing secret, including a permanent one; no correspondent-list membership or additional authorization is required, matching the "unprivileged paired device" reachable path. The only precondition is that `bIgnoreUnpairRequests` is set and the peer previously requested unpairing (or was otherwise flagged), a state fully controllable by the attacking device itself.

### Recommendation
In `handlePairingMessage` (`device.js`), do not unconditionally reset `is_blackhole=0` for `from_address`. Either omit the reset entirely for devices marked as blackholed, or require explicit user confirmation before restoring an active correspondent relationship with a previously-blocked device.

### Proof of Concept
1. Pair device B with device A; then configure A with `conf.bIgnoreUnpairRequests = true`.
2. From B, send `removed_paired_device` to A — A sets `is_blackhole=1` for B (`wallet.js:133`) instead of removing the correspondent.
3. Confirm A no longer sends messages to B (`device.js:740-746`, `is_blackhole` check).
4. From B, send a `pairing` message re-using the original (or a permanent) `pairing_secret`.
5. A's `handlePairingMessage` matches the pairing secret and executes `UPDATE correspondent_devices SET is_blackhole=0 WHERE device_address=?` (`device.js:832`), silently restoring B as an active correspondent.
6. B can now again receive/initiate `arbiter_contract_shared`, shared-address, and signing-request messages from A, reversing A's earlier block decision.

### Citations

**File:** wallet.js (L124-140)
```javascript
			case "removed_paired_device":
			//	if(conf.bIgnoreUnpairRequests) {
			//		// unpairing is ignored
			//		callbacks.ifError("removed_paired_device ignored: "+from_address);
			//	} else {
					determineIfDeviceCanBeRemoved(from_address, function(bRemovable){
						if (!bRemovable)
							return callbacks.ifError("device "+from_address+" is not removable");
						if (conf.bIgnoreUnpairRequests){
							db.query("UPDATE correspondent_devices SET is_blackhole=1 WHERE device_address=?", [from_address]);
							return callbacks.ifOk();
						}
						device.removeCorrespondentDevice(from_address, function(){
							eventBus.emit("removed_paired_device", from_address);
							callbacks.ifOk();
						});
					});
```

**File:** device.js (L733-750)
```javascript
function sendMessageToDevice(device_address, subject, body, callbacks, conn){
	if (!device_address)
		throw Error("empty device address");
	conn = conn || db;
	conn.query("SELECT hub, pubkey, is_blackhole FROM correspondent_devices WHERE device_address=?", [device_address], function(rows){
		if (rows.length !== 1 && !conf.bIgnoreMissingCorrespondents)
			throw Error("correspondent not found");
		if (rows.length === 0 && conf.bIgnoreMissingCorrespondents || rows[0].is_blackhole){
			console.log(rows.length === 0 ? "ignoring missing correspondent " + device_address : "not sending to " + device_address + " which is set as blackhole");
			if (callbacks && callbacks.onSaved)
				callbacks.onSaved();
			if (callbacks && callbacks.ifOk)
				callbacks.ifOk();
			return;
		}
		sendMessageToHub(rows[0].hub, rows[0].pubkey, subject, body, callbacks, conn);
	});
}
```

**File:** device.js (L797-848)
```javascript
// {pairing_secret: "random string", device_name: "Bob's MacBook Pro", reverse_pairing_secret: "random string"}
function handlePairingMessage(json, device_pubkey, callbacks){
	var body = json.body;
	var from_address = objectHash.getDeviceAddress(device_pubkey);
	if (!ValidationUtils.isNonemptyString(body.pairing_secret))
		return callbacks.ifError("correspondent not known and no pairing secret");
	if (!ValidationUtils.isNonemptyString(json.device_hub)) // home hub of the sender
		return callbacks.ifError("no device_hub when pairing");
	if (json.device_hub.length > 200)
		return callbacks.ifError("device_hub too long");
	if (!network.isValidWsUrl(conf.WS_PROTOCOL + json.device_hub))
		return callbacks.ifError("invalid device_hub URL");
	if (!ValidationUtils.isNonemptyString(body.device_name))
		return callbacks.ifError("no device_name when pairing");
	if (body.device_name.length > 100)
		return callbacks.ifError("device_name too long");
	if ("reverse_pairing_secret" in body && !ValidationUtils.isNonemptyString(body.reverse_pairing_secret))
		return callbacks.ifError("bad reverse pairing secret");
	eventBus.emit("pairing_attempt", from_address, body.pairing_secret);
	db.query(
		"SELECT is_permanent FROM pairing_secrets WHERE pairing_secret IN(?,'*') AND expiry_date>"+db.getNow()+" ORDER BY (pairing_secret=?) DESC LIMIT 1", 
		[body.pairing_secret, body.pairing_secret], 
		function(pairing_rows){
			if (pairing_rows.length === 0)
				return callbacks.ifError("pairing secret not found or expired");
			// add new correspondent and delete pending pairing
			var safe_device_name = body.device_name.replace(/<[^>]*>?/g, '');
			db.query(
				"INSERT "+db.getIgnore()+" INTO correspondent_devices (device_address, pubkey, hub, name, is_confirmed) VALUES (?,?,?,?,1)", 
				[from_address, device_pubkey, json.device_hub, safe_device_name],
				function(){
					db.query( // don't update name if already confirmed
						"UPDATE correspondent_devices SET is_confirmed=1, name=? WHERE device_address=? AND is_confirmed=0", 
						[safe_device_name, from_address],
						function(){
							db.query("UPDATE correspondent_devices SET is_blackhole=0 WHERE device_address=?", [from_address], function(){
								eventBus.emit("paired", from_address, body.pairing_secret);
								if (pairing_rows[0].is_permanent === 0){ // multiple peers can pair through permanent secret
									db.query("DELETE FROM pairing_secrets WHERE pairing_secret=?", [body.pairing_secret], function(){});
									eventBus.emit('paired_by_secret-'+body.pairing_secret, from_address);
								}
								if (body.reverse_pairing_secret)
									sendPairingMessage(json.device_hub, device_pubkey, body.reverse_pairing_secret, null);
								callbacks.ifOk();
							});
						}
					);
				}
			);
		}
	);
}
```
