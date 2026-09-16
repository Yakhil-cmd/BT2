### Title
Missing Brute Force Protection on Device Pairing Secret Allows Unauthorized Correspondent Pairing - (File: device.js)

### Summary
Device pairing in ocore is protected only by a random `pairing_secret`, which is verified in `handlePairingMessage` with a single unauthenticated database lookup and no attempt limiting, matching the CVE-2023-39958 bug class (missing brute-force protection on a bearer secret that grants an authorization outcome).

### Finding Description
`startWaitingForPairing` and `getOrGeneratePermanentPairingInfo` generate a `pairing_secret` from `crypto.randomBytes(9).toString("base64")` [1](#0-0) [2](#0-1) . This produces a 12-character base64 string (~72 bits of entropy in theory, but base64 of 9 random bytes has a fixed, guessable alphabet and, more importantly, no rate limiting is enforced anywhere on attempts to submit it).

Any device pubkey can send a `pairing` subject message to a hub, which is routed to `handlePairingMessage(json, device_pubkey, callbacks)`. The function validates only the structural shape of the body (non-empty strings, length limits, URL format) and then performs a single unauthenticated check:
```
db.query(
    "SELECT is_permanent FROM pairing_secrets WHERE pairing_secret IN(?,'*') AND expiry_date>"+db.getNow()+" ORDER BY (pairing_secret=?) DESC LIMIT 1",
    [body.pairing_secret, body.pairing_secret],
    function(pairing_rows){
        if (pairing_rows.length === 0)
            return callbacks.ifError("pairing secret not found or expired");
        ...
``` [3](#0-2) 

There is no per-secret, per-device, or per-hub attempt counter, no exponential backoff, and no lockout after repeated failed guesses of `pairing_secret`. An attacker who controls (or floods through) a hub connection, or who can reach the hub's message-relay endpoint with arbitrary device pubkeys, can send unlimited `pairing` messages guessing different `pairing_secret` values until one matches a victim's outstanding (non-permanent, time-limited) pairing secret, or — more critically — the victim's **permanent** pairing secret, which never expires (`expiry_date='2038-01-01'`) and is reused for QR-code/URI-based pairing (`uri.js` `pairing_secret` parsing) and for arbiter-contract acceptance flows (`arbiter_contract.js` composes `pairing_code = pubkey@hub#pairing_secret`) [2](#0-1) [4](#0-3) [5](#0-4) .

On a successful guess, `handlePairingMessage` inserts the attacker's device as a confirmed correspondent:
```
db.query("INSERT "+db.getIgnore()+" INTO correspondent_devices (device_address, pubkey, hub, name, is_confirmed) VALUES (?,?,?,?,1)", ...)
``` [6](#0-5) 
This makes the victim's wallet treat the attacker as a trusted, confirmed device correspondent for all future device-message flows (shared address setup, signature requests, arbiter contract offers, private payment chain forwarding).

### Impact Explanation
Successful brute-forcing of a pairing secret lets an attacker impersonate a legitimate peer device to the victim wallet. Because correspondent devices are used as trust anchors for shared-address key exchange (`wallet_defined_by_addresses`/`extended_pubkeys`), arbiter contract offers (`arbiter_contract.js` `arbiter_contract_offer` handler trusts `peer_device_address` from a confirmed correspondent) [7](#0-6) , and forwarded private payment chains, an attacker who becomes a confirmed correspondent can inject spoofed contract offers, signing-path/address-sharing messages, or private-payment forwarding into the victim's flows, potentially leading to AA/multisig fund loss, unauthorized shared-address membership, or forged arbiter contracts that the victim's wallet treats as coming from a real, previously-arranged counterparty.

### Likelihood Explanation
The permanent pairing secret is long-lived (effectively never expires) and is reused across QR-code pairing, chat pairing, and arbiter-contract acceptance, increasing the exposure window for guessing. There is no attempt limiting on the `pairing` message handler at any layer inspected (`handlePairingMessage`), so an attacker with hub access (any hub client) can send an unbounded number of guesses. The secret space (9 random bytes) provides cryptographic strength against a purely offline brute force, but the complete absence of any rate limiting, lockout, or monitoring on the pairing endpoint is itself the missing control mirrored in the referenced CVE, and combined with any weakening in secret generation/reuse (e.g., permanent secret, secret encoded in shareable URIs) meaningfully increases risk over time.

### Recommendation
Add explicit brute-force protection to `handlePairingMessage` in `device.js`: rate-limit or throttle pairing attempts per source device/hub/IP, use constant-time comparison, invalidate/rotate the permanent pairing secret after repeated failed attempts, and log/alert on repeated pairing failures. Consider requiring an additional out-of-band confirmation step before marking a correspondent `is_confirmed=1` on first pairing.

### Proof of Concept
1. Attacker generates a device keypair and connects to the victim's hub as any device client.
2. Attacker repeatedly sends `pairing` subject messages with different guessed `pairing_secret` values (varying the 12-character base64 string) targeting the victim's `device_pubkey`.
3. `handlePairingMessage` performs an unthrottled DB lookup for each guess [8](#0-7) ; failed attempts simply return `ifError` with no penalty, allowing immediate retry.
4. Once a correct secret is found (particularly the non-expiring permanent secret), the attacker's device is inserted as a confirmed correspondent [9](#0-8) , after which the attacker can send `arbiter_contract_offer`, signature, or private-payment forwarding messages that the victim's wallet processes as coming from a trusted peer.

Note: I could not fully trace where/how the hub-side rate limiting (if any) is implemented outside of `device.js`/`wallet.js`/`network.js` due to index coverage limits; a Devin session with full repo access would be needed to confirm whether any hub-level throttling middleware exists elsewhere that might partially mitigate this.

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

**File:** device.js (L778-795)
```javascript
function getOrGeneratePermanentPairingInfo(handlePairingInfo){
	db.query("SELECT pairing_secret FROM pairing_secrets WHERE is_permanent=1 ORDER BY expiry_date DESC LIMIT 1", [], function(rows){
		var pairing_secret;
		if (rows.length) {
			pairing_secret = rows[0].pairing_secret;
		} else {
			pairing_secret = crypto.randomBytes(9).toString("base64");
			db.query("INSERT INTO pairing_secrets (pairing_secret, is_permanent, expiry_date) VALUES(?, 1, '2038-01-01')", [pairing_secret]);
		}
		var pairingInfo = {
			pairing_secret: pairing_secret,
			device_pubkey: objMyPermanentDeviceKey.pub_b64,
			device_address: my_device_address,
			hub: my_device_hub
		};
		handlePairingInfo(pairingInfo);
	});
}
```

**File:** device.js (L797-847)
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
```

**File:** uri.js (L33-44)
```javascript
	// pairing / start a chat
//	var arrPairingMatches = value.match(/^([\w\/+]{44})@([\w.:\/-]+)(?:#|%23)([\w\/+]+)$/);
	var arrPairingMatches = value.replace('%23', '#').match(/^([\w\/+]{44})@([\w.:\/-]+)#(.+)$/);
	if (arrPairingMatches){
		objRequest.type = "pairing";
		objRequest.pubkey = arrPairingMatches[1];
		objRequest.hub = arrPairingMatches[2];
		objRequest.pairing_secret = arrPairingMatches[3];
		//if (objRequest.pairing_secret.length > 12)
		//    return callbacks.ifError("pairing secret too long");
		return callbacks.ifOk(objRequest);
	}
```

**File:** arbiter_contract.js (L140-150)
```javascript
		if (status === "accepted") {
			device.getOrGeneratePermanentPairingInfo(function(pairingInfo){
				var pairing_code = pairingInfo.device_pubkey + "@" + pairingInfo.hub + "#" + pairingInfo.pairing_secret;
				setField(objContract.hash, "my_pairing_code", pairing_code);
				composer.composeAuthorsAndMciForAddresses(db, [objContract.my_address], signer, function(err, authors) {
					if (err) {
						return cb(err);
					}
					send(authors, pairing_code);
				});
			});
```

**File:** wallet.js (L617-654)
```javascript
			case 'arbiter_contract_offer':
				body.peer_device_address = from_address;
				if (!body.title || !body.text || !body.creation_date || !body.arbiter_address || typeof body.me_is_payer === "undefined" || !body.my_pairing_code || !ValidationUtils.isPositiveInteger(body.amount) || !(body.ttl > 0))
					return callbacks.ifError("not all contract fields submitted");
				if (body.status)
					return callbacks.ifError("status must not be submitted in contract offer");
				if (!ValidationUtils.isValidAddress(body.my_address) || !ValidationUtils.isValidAddress(body.peer_address) || !ValidationUtils.isValidAddress(body.arbiter_address))
					return callbacks.ifError("either peer_address or address or arbiter_address is not valid in contract");
				if (body.hash !== arbiter_contract.getHash(body)) {
					return callbacks.ifError("wrong contract hash");
				}
				if (!/^\d{4}\-\d{2}\-\d{2} \d{2}:\d{2}:\d{2}$/.test(body.creation_date))
					return callbacks.ifError("wrong contract creation date");
				if (![body.title, body.text, body.my_pairing_code].every(ValidationUtils.isNonemptyString))
					return callbacks.ifError("wrong required fields");
				if (![body.my_contact_info, body.my_party_name, body.peer_party_name].every(field => !field || typeof field === "string"))
					return callbacks.ifError("wrong optional fields");
				if (!(body.asset === null || ValidationUtils.isValidBase64(body.asset, constants.HASH_LENGTH)))
					return callbacks.ifError("wrong asset");
				var my_address = body.peer_address;
				body.peer_address = body.my_address;
				body.my_address = my_address;
				var my_party_name = body.peer_party_name;
				body.peer_party_name = body.my_party_name;
				body.my_party_name = my_party_name;
				body.peer_pairing_code = body.my_pairing_code; body.my_pairing_code = null;
				body.peer_contact_info = body.my_contact_info; body.my_contact_info = null;
				body.me_is_payer = !body.me_is_payer;
				if (body.hash !== arbiter_contract.getHash(body))
					throw Error("wrong contract hash after swapping me and peer");
				db.query("SELECT 1 FROM my_addresses WHERE address=?", [body.my_address], function(rows) {
					if (!rows.length)
						return callbacks.ifError("contract does not contain my address");
					arbiter_contract.store(body, false, function() {
						eventBus.emit("arbiter_contract_offer", body.hash);
						callbacks.ifOk();
					});
				});
```
