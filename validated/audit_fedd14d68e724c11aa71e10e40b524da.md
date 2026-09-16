### Title
Missing brute-force protection on device pairing secret allows attacker to hijack pairing sessions - (File: `device.js`)

### Summary
`ocore` generates a random "pairing secret" that is exchanged out-of-band (QR code, invitation link, arbiter/prosaic contract pairing code) so that two devices can establish a trusted device-to-device relationship (`correspondent_devices`). The hub-relayed `pairing` message handler that consumes this secret, `handlePairingMessage`, performs no rate limiting, lockout, or attempt-counting on repeated guesses of the secret, mirroring the class of bug in CVE-2022-31118 (Nextcloud federated-share token brute force): a short random token, checked without throttling, that grants a trust relationship once guessed correctly.

### Finding Description
A one-time pairing secret is created with 9 random bytes (72 bits, base64-encoded) via `startWaitingForPairing`: [1](#0-0) 

Any device (identified only by a device pubkey it controls) can send a `pairing` message to the hub, which is relayed to the target device and processed by `handlePairingMessage`. The function validates the format of the fields, then simply looks up the secret in the `pairing_secrets` table: [2](#0-1) 

If the guessed `pairing_secret` matches a row that hasn't expired, the sender is unconditionally inserted/confirmed as a trusted `correspondent_devices` entry: [3](#0-2) 

There is no counter, delay, IP/device throttling, or maximum-attempts enforcement anywhere in this code path — the only telemetry is an `eventBus.emit("pairing_attempt", ...)` event that application code may optionally listen to, but nothing in `ocore` itself rejects repeated guesses: [4](#0-3) 

This is structurally identical to the Nextcloud bug class described in the report: a bounded-length random token used as the sole authorization check for establishing a trusted relationship, checked by a handler with no attempt limiting, so an attacker who can send arbitrarily many guesses to the hub can eventually brute-force it and register itself as a paired correspondent of the victim device.

### Impact Explanation
Once an attacker's device is accepted as a correspondent (via a guessed pairing secret), it is treated by the victim device as a legitimate paired peer for all subsequent device-message flows: multisig/shared-address signing offers (`walletGeneral.sendOfferToSign`), arbiter/prosaic contract negotiation, and private-payment chain delivery. In shared-address / multi-device wallet setup flows, pairing is precisely the step used to bootstrap trust between co-signers before extended pubkeys and signing offers are exchanged; an attacker who wins the race to pair using a brute-forced secret can insert itself into that trust relationship, potentially intercepting private payment chains or being offered co-signing requests intended for the legitimate device, which can lead to unauthorized spending or loss of funds from a shared address.

### Likelihood Explanation
Exploitation requires only the ability to send hub-relayed messages containing pubkey/secret guesses, which any device (unprivileged, not requiring possession of any private key belonging to the victim) can do. With no throttling, an attacker can automate secret guessing continuously; the effective entropy (72 bits) sets an upper bound but the complete absence of rate limiting means the only defense is raw brute-force cost, exactly the condition flagged as insufficient in the referenced advisory.

### Recommendation
Add attempt limiting to `handlePairingMessage` (e.g., per source device/pubkey and/or per pairing_secret lookups), track and cap failed pairing attempts with exponential backoff or lockout, and shorten the exposure window for one-time pairing secrets (`startWaitingForPairing` currently allows a month-long validity window) to reduce the brute-force attack surface.

### Proof of Concept
1. Obtain any pubkey/hub combination for a target device (public information exposed in pairing-code use cases such as bot listings or arbiter contract pairing codes).
2. Repeatedly send `pairing` messages to the hub with different guessed `pairing_secret` values, exactly matching the message shape processed by `handlePairingMessage`.
3. Because there is no attempt counter or delay in the validation query at `device.js:816-821`, continue guessing until a match is found; upon match, the attacker's device is unconditionally added to `correspondent_devices` as confirmed, as shown in `device.js:824-841`.

### Citations

**File:** device.js (L765-776)
```javascript
function startWaitingForPairing(handlePairingInfo){
	var pairing_secret = crypto.randomBytes(9).toString("base64");
	var pairingInfo = {
		pairing_secret: pairing_secret,
		device_pubkey: objMyPermanentDeviceKey.pub_b64,
		device_address: my_device_address,
		hub: my_device_hub
	};
	db.query("INSERT INTO pairing_secrets (pairing_secret, expiry_date) VALUES(?, "+db.addTime("+1 MONTH")+")", [pairing_secret], function(){
		handlePairingInfo(pairingInfo);
	});
}
```

**File:** device.js (L797-841)
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
```
