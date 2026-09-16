### Title
Missing Origin/Cosigner Validation in Wallet "sign" Request Handler Allows Any Paired Device to Solicit Unauthorized Signatures - ([File: wallet.js])

### Summary
The AliasVault report describes a credential provider that resolved and returned a passkey response without fully validating the identity/origin of the calling app, letting an unauthorized caller obtain a credential for a site it did not own. The equivalent trust boundary in ocore is the wallet device-message handler that services `sign` requests coming from a paired device (`from_address`) over the hub. When the target address is hosted locally, `wallet.js` resolves it via `findAddress()` and, in the `ifLocal` callback, proceeds to process the signing request without verifying that the requesting device (`from_address`) is actually an authorized cosigner of that specific address/signing path — the only check that would enforce this is explicitly commented out.

### Finding Description
In the `"sign"` case of `handleMessageFromHub` in [1](#0-0) , the handler validates the shape of the unsigned unit and the signing path syntax, but the identity check that ties the request to an authorized signer is disabled: [2](#0-1) 

```
findAddress(body.address, body.signing_path, {
    ifError: callbacks.ifError,
    ifLocal: function(objAddress){
        // the commented check would make multilateral signing impossible
        //db.query("SELECT 1 FROM extended_pubkeys WHERE wallet=? AND device_address=?", [row.wallet, from_address], function(sender_rows){
        //    if (sender_rows.length !== 1)
        //        return callbacks.ifError("sender is not cosigner of this address");
            callbacks.ifOk();
            ...
```

`findAddress()` ( [3](#0-2) ) resolves `ifLocal` purely based on whether the *target address* (not the requester) is hosted on this device — it never inspects `from_address` at all for the local branch. Contrast this with the `ifRemote` branch a few lines below, which does check `other_device_addresses.includes(from_address)` before forwarding ( [4](#0-3) ). No equivalent origin check exists for the local branch.

As a result, any device that is merely paired/correspondent with the user (paired for chat, or added via any legitimate pairing flow — see `handlePairingMessage` at [5](#0-4) , which only requires knowledge of a `pairing_secret`) can send a `"sign"` device message naming *any* of the user's own addresses and *any* signing path, and the wallet will accept it, build the to-be-signed unit, validate it against the DAG (`network.handleOnlineJoint`), and raise a `signing_request` UI event — all without ever confirming that this particular correspondent is one of the wallet's legitimate cosigning devices for that address. The address/signing-path ownership check (multi-device wallet cosigner or arbiter/prosaic contract counterparty) that the comment references was intentionally removed to keep "multilateral signing" (use case 2 in the code comment) working, but this collapses the origin-authentication boundary entirely onto the end-user's manual approval of the resulting popup, with no cryptographic or identity binding of "who is allowed to request a signature for this key."

### Impact Explanation
This mirrors the CVE root cause precisely: incomplete validation of the calling party's identity/origin before granting access to a sensitive credential-like operation (here, soliciting a signature over an arbitrary attacker-supplied transaction). A malicious paired correspondent (which the user may have added for an unrelated purpose, e.g., a merchant bot, chatbot, or third-party service) can repeatedly send crafted `sign` requests for the victim's own single- or multi-sig addresses, disguising a malicious payment as a routine confirmation prompt. If the user approves — a realistic outcome given confirmation-fatigue and the request appearing to originate from the wallet's own resolved address/definition — funds are sent under attacker control. This is a direct path to unauthorized spending of the user's private/base-asset outputs, satisfying the "concrete unauthorized spending" impact bar in the same class as the AliasVault issue (a legitimate-looking prompt approving an operation the requester was never authorized to trigger).

### Likelihood Explanation
Exploitation requires (1) the attacker's device be a paired correspondent of the victim (a low bar — pairing secrets are exchanged casually via QR/links per [6](#0-5) ), and (2) the victim approves the resulting confirmation dialog, matching the CVSS `UI:R` vector of the original CVE. No consensus-level or cryptographic protection currently narrows the set of devices allowed to request a signature for a given address/path — the sole mitigating control is the human confirmation step, which is fragile in phishing/social-engineering conditions.

### Recommendation
Reinstate (in an updated, non-breaking form) verification in the `ifLocal` branch that `from_address` is actually an authorized cosigning device for `body.address`/`body.signing_path` (e.g., check `wallet_signing_paths`/`shared_address_signing_paths`/known contract counterparties) before emitting `signing_request`, or at minimum surface the requester's authorization status prominently in the `signing_request` payload/UI so the confirmation dialog can warn when an unauthorized device is soliciting a signature. For legitimate multilateral-signing flows, restrict the exemption to addresses/paths that are actually part of a known shared address or contract with that specific correspondent, rather than granting a blanket bypass for all local addresses.

### Proof of Concept
1. Attacker pairs with victim's wallet using any (even purpose-limited) pairing exchange, becoming an entry in `correspondent_devices`.
2. Attacker crafts an unsigned unit paying attacker's address from victim's own address (`body.address` = one of victim's `my_addresses`), sets `body.signing_path` = `"r"` (or a valid multi-sig path), and sends a `"sign"` hub message: `{subject: "sign", body: {address: victimAddress, signing_path: "r", unsigned_unit: {...attacker-controlled outputs...}}}`.
3. `handleMessageFromHub` → `case "sign"` passes the structural checks ( [7](#0-6) ), then `findAddress` resolves `ifLocal` because the address is hosted locally — `from_address` is never checked ( [2](#0-1) , [3](#0-2) ).
4. The wallet validates the unit via `network.handleOnlineJoint` and fires `signing_request` to the UI layer, which displays a confirmation dialog to the victim; if approved, the attacker's spend is signed and broadcast.

**Note on confidence**: This analog was derived from static review of `wallet.js` and `device.js` in the indexed snapshot; I could not execute the flow end-to-end (no runtime/test harness access here), so the exact UI-layer wording shown to the user (which affects real-world exploitability/likelihood) is not verified — a Devin session with full repo/test access would be needed to confirm the exact confirmation-dialog content and any additional client-side guards that might exist outside `ocore` (e.g., in wallet GUI repos not present here).

### Citations

**File:** wallet.js (L251-330)
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
				if ("private_payloads" in body){
					if (!isNonemptyObject(assocPrivatePayloads))
						return callbacks.ifError("bad private payloads");
					if (!ValidationUtils.isNonemptyArray(objUnit.messages))
						return callbacks.ifError("private payloads require messages");
					const sent_pp_hashes = Object.keys(assocPrivatePayloads).sort();
					const expected_pp_hashes = objUnit.messages.filter(m => m.payload_location === "none" && m.app === "payment").map(m => m.payload_hash).sort();
					if (!_.isEqual(sent_pp_hashes, expected_pp_hashes))
						return callbacks.ifError("private payloads are not the same as in the messages");
					for (var payload_hash in assocPrivatePayloads){
						try {
							const payload = assocPrivatePayloads[payload_hash];
							if (!ValidationUtils.isNonemptyArray(payload.outputs) || !payload.outputs.every(o => ValidationUtils.isValidAddress(o.address) && ValidationUtils.isNonemptyString(o.blinding) && ValidationUtils.isPositiveInteger(o.amount)))
								return callbacks.ifError("bad private payload outputs");
							if (!ValidationUtils.isNonemptyArray(payload.inputs) || !payload.inputs.every(i => ("type" in i) || (ValidationUtils.isNonemptyString(i.unit) && ValidationUtils.isNonnegativeInteger(i.message_index) && ValidationUtils.isNonnegativeInteger(i.output_index))))
								return callbacks.ifError("bad private payload inputs");
							const hidden_payload = _.cloneDeep(payload);
							if (payload.denomination) { // indivisible asset.  In this case, payload hash is calculated based on output_hash rather than address and blinding
								if (!payload.outputs.every(o => o.output_hash === objectHash.getBase64Hash({ address: o.address, blinding: o.blinding })))
									return callbacks.ifError("output hash mismatch");
								hidden_payload.outputs.forEach(function (o) {
									delete o.address;
									delete o.blinding;
								});
							}
							var calculated_payload_hash = objectHash.getBase64Hash(hidden_payload, bJsonBased);
						}
						catch (e) {
							return callbacks.ifError("hidden payload hash failed: " + e.toString());
						}
						if (payload_hash !== calculated_payload_hash)
							return callbacks.ifError("private payload hash does not match");
						if (objUnit.messages.filter(function(objMessage){ return (objMessage && objMessage.payload_hash === payload_hash); }).length !== 1)
							return callbacks.ifError("no such payload hash in the messages");
					}
				}
				if (("messages" in objUnit) + ("signed_message" in objUnit) !== 1)
					return callbacks.ifError("either messages or signed_message must be present, but not both");
				if ("messages" in objUnit){
					const validation = require('./validation.js');
					if (!validation.hasValidPayloadHashes({ unit: objUnit }))
						return callbacks.ifError("invalid payload hashes");
					if (!objUnit.messages.find(m => m.app === 'payment'))
						return callbacks.ifError("no payment messages");
					for (let m of objUnit.messages) {
						if (m.app !== 'payment' || m.payload_location !== 'inline') continue;
						if (!ValidationUtils.isNonemptyArray(m.payload.outputs) || !m.payload.outputs.every(o => ValidationUtils.isValidAddress(o.address) && ValidationUtils.isPositiveInteger(o.amount)))
							return callbacks.ifError("invalid payment outputs");
						if (!ValidationUtils.isNonemptyArray(m.payload.inputs) || !m.payload.inputs.every(i => ("type" in i) || (ValidationUtils.isNonemptyString(i.unit) && ValidationUtils.isNonnegativeInteger(i.message_index) && ValidationUtils.isNonnegativeInteger(i.output_index))))
							return callbacks.ifError("invalid payment inputs");
					}
				}
```

**File:** wallet.js (L332-349)
```javascript
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

**File:** wallet.js (L1233-1259)
```javascript
function findAddress(address, signing_path, callbacks, fallbackInfo){
	db.query(
		"SELECT wallet, account, is_change, address_index, full_approval_date, device_address \n\
		FROM my_addresses JOIN wallets USING(wallet) JOIN wallet_signing_paths USING(wallet) \n\
		WHERE address=? AND signing_path=?",
		[address, signing_path],
		async function(rows){
			if (rows.length > 1)
				throw Error("more than 1 address found");
			if (rows.length === 1){
				var row = rows[0];
				if (!row.full_approval_date)
					return callbacks.ifError("wallet of address "+address+" not approved");
				if (row.device_address !== device.getMyDeviceAddress()) {
					const other_rows = await db.query("SELECT DISTINCT device_address FROM wallet_signing_paths WHERE wallet=? AND device_address!=?", [row.wallet, row.device_address]);
					const other_device_addresses = other_rows.map(r => r.device_address);
					return callbacks.ifRemote(row.device_address, other_device_addresses);
				}
				var objAddress = {
					address: address,
					wallet: row.wallet,
					account: row.account,
					is_change: row.is_change,
					address_index: row.address_index
				};
				callbacks.ifLocal(objAddress);
				return;
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
