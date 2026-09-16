### Title
Missing cosigner-authorization check on the `sign` device message lets any paired device request signing on a wallet's own address - (File: wallet.js)

### Summary
The Apache Ranger CVE-2026-40920 is a privilege-escalation bug caused by an authorization decision that trusts a client-supplied identifier without checking that the caller is actually entitled to act on it. The analogous pattern in ocore is in the `"sign"` device-message handler in `handleMessageFromHub`: when the target address is "local" (a wallet address whose private key lives on this device), the code accepts `body.address` from *any* paired device and triggers a `signing_request` without ever verifying that the sender (`from_address`) is a legitimate cosigner/counterparty for that address.

### Finding Description
In `wallet.js`, the `case "sign":` branch [1](#0-0)  validates the shape of `body.address`, `body.signing_path`, and `body.unsigned_unit`, and confirms that `body.address` is one of the unit's declared authors, but it never checks that the device sending the message (`from_address`, derived only from the sender's device pubkey) has any relationship to `body.address`.

The request is then routed through `findAddress(body.address, body.signing_path, ...)` [2](#0-1) . When the address resolves to a locally-held key (`ifLocal`), the authorization check that would confirm the sender is actually a cosigner is explicitly disabled in the code, with a comment acknowledging the trade-off: [3](#0-2) 

The commented-out block would have queried `extended_pubkeys` to confirm `from_address` is a genuine cosigner of the wallet before honoring the request; instead, `callbacks.ifOk()` is called immediately and a `signing_request` event is emitted unconditionally for **any** correspondent device that has ever paired with the victim, for **any** local address the victim's wallet controls (not just shared/multisig addresses the sender is a party to). This contrasts with the `ifRemote` branch just below, which does perform the equivalent check (`other_device_addresses.includes(from_address)`) before proceeding [4](#0-3) .

Because the signing_path regex (`^r(\.\d+)*$`) and the "address must be among unit authors" check are the only real gates, an attacker who is merely a paired correspondent (e.g. a stranger who exchanged pairing codes, a chat-bot contact, or a merchant integration) can construct an arbitrary `unsigned_unit` containing outputs of their choosing, name the victim's own address as an author, and push a `signing_request` UI event straight to the victim's wallet — impersonating a legitimate multisig cosigner or contract counterparty, even though the sender has no actual authority over that address.

### Impact Explanation
This is a privilege-escalation/authorization-bypass vulnerability: the check that should gate "who is allowed to ask this device to sign for address X" is missing for local addresses. The wallet's confirmation dialog is the only remaining control, and it is populated with attacker-controlled unit content routed through a code path that omits the sender-authorization check that exists for the mirror-image (`ifRemote`) case. This blurs the security boundary between "co-owner of a shared address" and "any paired device," directly matching the CVE's bug class (authorization decision keyed off an untrusted/unverified parameter). If a user has any correspondents who are not actual cosigners of a given address (which is the normal case, since pairing is separate from multisig membership), those correspondents can solicit signatures for spends from that address, effectively escalating from "paired device" to "co-signer of your wallet."

### Likelihood Explanation
This is trivially reachable by any device that has completed the (also low-friction) pairing handshake defined in `device.js` (`handlePairingMessage`) [5](#0-4) , then sends a single `"sign"` message. No special privilege beyond pairing is required, and the vulnerable branch is reached whenever the targeted address happens to be locally held — i.e., for the common case of a user's own wallet addresses, not just shared multisig addresses.

### Recommendation
Restore (in adapted form) the disabled cosigner check for the `ifLocal` branch of the `"sign"` handler: before emitting `signing_request`, verify that `from_address` is a recognized party for `body.address` — e.g., a cosigner of the shared address definition, a party to a known prosaic/arbiter contract for that address, or otherwise explicitly whitelisted — mirroring the check already performed in the `ifRemote` branch (`other_device_addresses.includes(from_address)`). If multilateral "sign this arbitrary contract with my address" flows must remain supported for non-cosigner correspondents, the UI confirmation dialog should explicitly and unambiguously disclose that the requester is *not* a verified cosigner, so users cannot mistake the request for a legitimate wallet-internal signing flow.

### Proof of Concept
1. Attacker device pairs with the victim's wallet via the normal `pairing` flow (`device.handlePairingMessage`), becoming a `correspondent_devices` entry with no wallet/cosigner relationship.
2. Attacker sends a `"sign"` device message to the victim's hub:
   ```
   {
     subject: "sign",
     body: {
       address: "<victim's own single-sig or shared address>",
       signing_path: "r",
       unsigned_unit: {
         version: ...,
         authors: [{ address: "<victim address>", authentifiers: {} }],
         messages: [{ app: "payment", payload_location: "inline", payload: { asset: null, inputs: [...], outputs: [{ address: "<attacker address>", amount: <victim's balance> }] } }]
       }
     }
   }
   ```
3. `handleMessageFromHub` reaches `case "sign"`, passes all format checks (address is a listed author, signing_path matches regex), and calls `findAddress`.
4. Because the address is locally held, `ifLocal` fires; the disabled cosigner check means `callbacks.ifOk()` executes and `signing_request` is emitted to the victim's UI with the attacker-crafted spend, despite the attacker never having been established as a cosigner of that address.

Note: because the final effect (whether the attacker actually obtains the victim's signature) also depends on how the wallet UI presents the `signing_request` event to the user, I was not able to fully verify from the indexed code whether any GUI/headless wallet in this repository could auto-approve such requests without genuine user review — that would require inspecting the UI/event-handler code, which was not found in the indexed files. If such handling exists, this issue would escalate to outright unauthorized spending.

### Citations

**File:** wallet.js (L251-278)
```javascript
			case "sign":
				// {address: "BASE32", signing_path: "r.1.2.3", unsigned_unit: {...}}
				if (!ValidationUtils.isValidAddress(body.address))
					return callbacks.ifError("no address or bad address");
				if (!ValidationUtils.isNonemptyString(body.signing_path) || !/^r(\.\d+)*$/.test(body.signing_path))
					return callbacks.ifError("bad signing path");
				var objUnit = body.unsigned_unit;
				if (typeof objUnit !== "object" || objUnit === null)
					return callbacks.ifError("no unsigned unit");
				if (!ValidationUtils.isNonemptyArray(objUnit.authors))
					return callbacks.ifError("no authors array");
				var bJsonBased = (objUnit.version !== constants.versionWithoutTimestamp);
				// replace all existing signatures with placeholders so that signing requests sent to us on different stages of signing become identical,
				// hence the hashes of such unsigned units are also identical
				try {
					objUnit.authors.forEach(function (author) {
						var authentifiers = author.authentifiers;
						for (var path in authentifiers)
							authentifiers[path] = authentifiers[path].replace(/./g, '-');
					});
					const authorAddresses = objUnit.authors.map(author => author.address);
					if (!authorAddresses.includes(body.address))
						return callbacks.ifError("address not found among authors");
				}
				catch (e) {
					return callbacks.ifError("invalid authors: " + e.toString());
				}
				var assocPrivatePayloads = body.private_payloads;
```

**File:** wallet.js (L331-349)
```javascript
				// findAddress handles both types of addresses
				findAddress(body.address, body.signing_path, {
					ifError: callbacks.ifError,
					ifLocal: function(objAddress){
						// the commented check would make multilateral signing impossible
						//db.query("SELECT 1 FROM extended_pubkeys WHERE wallet=? AND device_address=?", [row.wallet, from_address], function(sender_rows){
						//    if (sender_rows.length !== 1)
						//        return callbacks.ifError("sender is not cosigner of this address");
							callbacks.ifOk();
							if (objUnit.signed_message && !ValidationUtils.hasFieldsExcept(objUnit, ["signed_message", "authors", "version"])){
								try {
									objUnit.unit = objectHash.getBase64Hash(objUnit); // exact value doesn't matter, it just needs to be there
								}
								catch (e) {
									console.log("signed message hash failed", e);
									objUnit.unit = "failedunit";
								}
								return eventBus.emit("signing_request", objAddress, body.address, objUnit, assocPrivatePayloads, from_address, body.signing_path);
							}
```

**File:** wallet.js (L374-378)
```javascript
					ifRemote: function(device_address, other_device_addresses){
						if (device_address === from_address)
							return callbacks.ifError("looping signing request for address "+body.address+", path "+body.signing_path);
						if (!other_device_addresses.includes(from_address))
							return callbacks.ifError("you are not listed as a cosigner for this address "+body.address);
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
