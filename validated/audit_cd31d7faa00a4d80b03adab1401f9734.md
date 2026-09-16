### Title
Disabled indirect-correspondent restriction lets uninvited "indirect" devices exercise full wallet trust including sign requests and shared-address auto-creation - (File: wallet.js)

### Summary
`wallet.js` handles all `hub/message` traffic in `handleMessageFromHub`. It contains a scoping check meant to restrict messages from `is_indirect` correspondents (devices auto-registered as correspondents merely because they were named as co-signers in a shared-address message, never explicitly paired by the user) to a small safe subset of subjects. This check is commented out, so indirect correspondents are treated with the same trust as fully paired correspondents for every subject, including `sign`, `new_shared_address`, `create_new_shared_address`, and private-payment forwarding. This mirrors the OpenClaw bug class (CWE-863): an identity that is only valid in a narrow trust context (auto-introduced/indirect pairing, analogous to BlueBubbles' DM pairing-store) is silently accepted for a broader trust decision (full correspondent/group-level operations) because the scope-restricting composition was never enforced.

### Finding Description
`device.js` distinguishes two correspondent trust levels in `correspondent_devices`:
- Directly paired/confirmed correspondents (`is_confirmed=1`), added only after a `pairing` handshake via `handlePairingMessage` [1](#0-0) .
- "Indirect" correspondents, added automatically via `addIndirectCorrespondents` whenever another correspondent's message names "other cosigners" of a shared/multisig address — no pairing secret, no user confirmation, just a claim in an incoming device message [2](#0-1) .

When a message arrives from the hub, `device.js` looks up the sender in `correspondent_devices` and passes `rows[0].is_indirect` through to the wallet layer as `bIndirectCorrespondent` [3](#0-2) .

`wallet.js`'s `handleMessageFromHub` is supposed to restrict indirect correspondents to only `cancel_new_wallet`, `my_xpubkey`, `new_wallet_address`, but that gate is commented out: [4](#0-3) 

Because this check is disabled, an indirect correspondent — someone who was never paired by the user, only introduced as an alleged "other cosigner" — is authorized identically to a fully-paired device for every subject handled afterward in the same `switch`, including:
- `sign` — requests the user's wallet to sign arbitrary units for addresses the user controls [5](#0-4) .
- `new_shared_address` — auto-registers a new shared/multisig address that may include the victim's own address, via `handleNewSharedAddress` → `determineIfIncludesMeAndRewriteDeviceAddress`, which matches signer addresses against the victim's own `my_addresses`/`shared_addresses` and silently rewrites device ownership without any confirmation dialog [6](#0-5) [7](#0-6) .
- `create_new_shared_address` — triggers a UI event for creating a new shared address using unrestricted template data from the sender [8](#0-7) .

This is the same bug class as the OpenClaw advisory: an authorization tier meant to be a strict subset (`dmPolicy=pairing` / here "indirect correspondent") ends up composed into the full-trust tier (`groupPolicy=allowlist` / here "confirmed correspondent") because the code path that would keep the two separate was removed/disabled rather than centrally enforced.

### Impact Explanation
An attacker who is a legitimate paired correspondent of a victim can unilaterally introduce arbitrary attacker-controlled "indirect" device addresses into the victim's `correspondent_devices` table by naming them as co-signers in a `new_shared_address`/related message (`addIndirectCorrespondents`). Those indirect devices, which the victim never paired with or confirmed, can then send:
- `new_shared_address` messages that reference the victim's real, public on-chain address, causing the wallet to silently create/accept a new shared (multisig) address record naming the victim as a signer without any user confirmation.
- `sign` requests, prompting or programmatically attempting signature flows for units affecting addresses the victim controls, since `findAddress` binds the request to any address matching the victim's wallet, not gated by whether the sender was actually invited into that multisig relationship.

This can lead to unauthorized/spoofed multisig relationships being registered against the victim's wallet, private-payment chains being routed through unintended devices, and social-engineering-amplified signature requests, all with a trust level equivalent to a fully paired correspondent despite the sender never having been paired — matching the impact class of "unauthorized spending" / "wallet fund loss" risk paths.

### Likelihood Explanation
Likelihood is moderate: it requires the attacker to first be (or become) a correspondent capable of sending any device message to the victim (an existing pairing, or a permanent pairing secret) and to craft a shared-address-style message naming an "other cosigner" device address they control, which is auto-inserted as an indirect correspondent with no further confirmation (`addIndirectCorrespondents` performs no validation against the victim's actual definitions). Once inserted, the disabled check means every subsequent message from that device is processed with full trust, with no code path currently limiting it as originally designed.

### Recommendation
Re-enable and properly enforce the indirect-correspondent restriction in `wallet.js`'s `handleMessageFromHub`, centralizing the subject-allowlist check so it cannot be silently bypassed by comment-out or per-callsite recomposition (mirroring the OpenClaw fix's centralized-resolver approach). Additionally, validate in `addIndirectCorrespondents` and `determineIfIncludesMeAndRewriteDeviceAddress` that a claimed "other cosigner" is genuinely part of a definition the victim has agreed to, rather than trusting sender-supplied address/device-address pairs at face value.

### Proof of Concept
1. Attacker (paired correspondent A) sends the victim a `new_shared_address`/related message that lists a second device address `B` (attacker-controlled) as an "other cosigner" via the co-signer forwarding path, causing `device.js`'s `addIndirectCorrespondents` to insert `B` into `correspondent_devices` with `is_indirect=1`, `is_confirmed=0` [9](#0-8) .
2. Device `B` then sends the victim a `hub/message` with `subject: "sign"` (or `new_shared_address` naming the victim's real address as a co-signer).
3. In `device.js`, `B` is found in `correspondent_devices` (`rows.length > 0`), so `handleMessage(rows[0].is_indirect)` is called with `bIndirectCorrespondent=true` and passed to `wallet.js` [10](#0-9) .
4. In `wallet.js`, because the indirect-correspondent gate is commented out, the `sign`/`new_shared_address` case executes exactly as if `B` were a fully paired, confirmed correspondent [11](#0-10) , letting `B` register a shared address entry referencing the victim's address or trigger sign-request handling reserved for trusted correspondents.

### Citations

**File:** device.js (L204-221)
```javascript
			db.query("SELECT hub, is_indirect FROM correspondent_devices WHERE device_address=?", [from_address], function(rows){
				if (rows.length > 0){
					if (json.device_hub && typeof json.device_hub === 'string' && json.device_hub.length <= 200 && network.isValidWsUrl(conf.WS_PROTOCOL + json.device_hub) && json.device_hub !== rows[0].hub) // update correspondent's home address if necessary
						db.query("UPDATE correspondent_devices SET hub=? WHERE device_address=?", [json.device_hub, from_address], function(){
							handleMessage(rows[0].is_indirect);
						});
					else
						handleMessage(rows[0].is_indirect);
				}
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

**File:** device.js (L798-848)
```javascript
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

**File:** device.js (L906-920)
```javascript
function addIndirectCorrespondents(arrOtherCosigners, onDone){
	async.eachSeries(arrOtherCosigners, function(correspondent, cb){
		if (correspondent.device_address === my_device_address)
			return cb();
		if (!ValidationUtils.isNonemptyString(correspondent.hub) || !network.isValidWsUrl(conf.WS_PROTOCOL + correspondent.hub))
			return cb(); // ignore silently and continue eachSeries
		db.query(
			"INSERT "+db.getIgnore()+" INTO correspondent_devices (device_address, hub, name, pubkey, is_indirect) VALUES(?,?,?,?,1)", 
			[correspondent.device_address, correspondent.hub, correspondent.name, correspondent.pubkey],
			function(){
				cb();
			}
		);
	}, onDone);
}
```

**File:** wallet.js (L84-95)
```javascript
	function doHandle() {

		var subject = json.subject;
		var body = json.body;
		if (!subject || typeof body == "undefined" || body === null)
			return callbacks.ifError("no subject or body");
		if (typeof subject !== "string")
			return callbacks.ifError("subject is not a string");
		//if (bIndirectCorrespondent && ["cancel_new_wallet", "my_xpubkey", "new_wallet_address"].indexOf(subject) === -1)
		//    return callbacks.ifError("you're indirect correspondent, cannot trust "+subject+" from you");
		var from_address = objectHash.getDeviceAddress(device_pubkey);
		
```

**File:** wallet.js (L197-212)
```javascript
			case "create_new_shared_address":
				// {address_definition_template: [...]}
				if (!ValidationUtils.isArrayOfLength(body.address_definition_template, 2))
					return callbacks.ifError("no address definition template");
				walletDefinedByAddresses.validateAddressDefinitionTemplate(
					body.address_definition_template, from_address, 
					function(err, assocMemberDeviceAddressesBySigningPaths){
						if (err)
							return callbacks.ifError(err);
						// this event should trigger a confirmatin dialog, user needs to approve creation of the shared address and choose his 
						// own address that is to become a member of the shared address
						eventBus.emit("create_new_shared_address", body.address_definition_template, assocMemberDeviceAddressesBySigningPaths);
						callbacks.ifOk();
					}
				);
				break;
```

**File:** wallet.js (L251-260)
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
```

**File:** wallet_defined_by_addresses.js (L279-315)
```javascript
// Checks if any of my payment addresses is mentioned.
// It is possible that my device address is not mentioned in the definition if I'm a member of multisig address, one of my cosigners is mentioned instead
function determineIfIncludesMeAndRewriteDeviceAddress(assocSignersByPath, handleResult){
	var assocMemberAddresses = {};
	var bHasMyDeviceAddress = false;
	for (var signing_path in assocSignersByPath){
		var signerInfo = assocSignersByPath[signing_path];
		if (signerInfo.device_address === device.getMyDeviceAddress())
			bHasMyDeviceAddress = true;
		if (signerInfo.address)
			assocMemberAddresses[signerInfo.address] = true;
	}
	var arrMemberAddresses = Object.keys(assocMemberAddresses);
	if (arrMemberAddresses.length === 0)
		return handleResult("no member addresses?");
	db.query(
		"SELECT address, 'my' AS type FROM my_addresses WHERE address IN(?) \n\
		UNION \n\
		SELECT shared_address AS address, 'shared' AS type FROM shared_addresses WHERE shared_address IN(?)", 
		[arrMemberAddresses, arrMemberAddresses],
		function(rows){
		//	handleResult(rows.length === arrMyMemberAddresses.length ? null : "Some of my member addresses not found");
			if (rows.length === 0)
				return handleResult("I am not a member of this shared address");
			var arrMyMemberAddresses = rows.filter(function(row){ return (row.type === 'my'); }).map(function(row){ return row.address; });
			// rewrite device address for my addresses
			if (!bHasMyDeviceAddress){
				for (var signing_path in assocSignersByPath){
					var signerInfo = assocSignersByPath[signing_path];
					if (signerInfo.address && arrMyMemberAddresses.indexOf(signerInfo.address) >= 0)
						signerInfo.device_address = device.getMyDeviceAddress();
				}
			}
			handleResult();
		}
	);
}
```

**File:** wallet_defined_by_addresses.js (L378-415)
```javascript
function handleNewSharedAddress(body, callbacks){
	if (!ValidationUtils.isArrayOfLength(body.definition, 2))
		return callbacks.ifError("invalid definition");
	if (typeof body.signers !== "object" || Object.keys(body.signers).length === 0)
		return callbacks.ifError("invalid signers");
	try {
		var addr = objectHash.getChash160(body.definition);
	}
	catch (e) {
		return callbacks.ifError("invalid definition: " + e);
	}
	if (body.address !== addr)
		return callbacks.ifError("definition doesn't match its c-hash");
	for (var signing_path in body.signers){
		var signerInfo = body.signers[signing_path];
		if (signerInfo.address && signerInfo.address !== 'secret' && !ValidationUtils.isValidAddress(signerInfo.address))
			return callbacks.ifError("invalid member address: " + JSON.stringify(signerInfo.address));
	}
	const assocDefinitionAddresses = extractAddressPathsFromDefinition(body.definition);
	for (let signing_path in body.signers) {
		const signerInfo = body.signers[signing_path];
		if (assocDefinitionAddresses[signing_path] !== signerInfo.address)
			return callbacks.ifError("signer address at path " + signing_path + " doesn't match definition");
	}
	for (let def_path in assocDefinitionAddresses) {
		if (!body.signers[def_path])
			return callbacks.ifError("no signer for definition address at path " + def_path);
	}
	determineIfIncludesMeAndRewriteDeviceAddress(body.signers, function(err){
		if (err)
			return callbacks.ifError(err);
		validateAddressDefinition(body.definition, function(err){
			if (err)
				return callbacks.ifError(err);
			addNewSharedAddress(body.address, body.definition, body.signers, body.forwarded, callbacks.ifOk);
		});
	});
}
```
