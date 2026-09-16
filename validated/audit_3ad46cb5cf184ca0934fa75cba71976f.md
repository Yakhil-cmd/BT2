### Title
Unauthenticated `new_shared_address` device message lets a paired device silently register a spoofed "shared address" that embeds the victim's own address, bypassing the confirm/approve flow - ([File: wallet_defined_by_addresses.js])

### Summary
This maps the "callback trusts unauthenticated caller-supplied identity" root cause of the SlowMist DEX incident onto ocore's wallet device-message handler. `handleNewSharedAddress()` in `wallet_defined_by_addresses.js` accepts a `new_shared_address` message from any paired device and inserts a shared-address definition into local storage after checking only *internal structural consistency* of the attacker-supplied payload - never that the message actually originated from the create/approve flow or that the sender is entitled to introduce this definition.

### Finding Description
The proper way to create a shared address goes through a consent flow: `create_new_shared_address` → user confirmation → `approve_new_shared_address`, and `validateAddressDefinitionTemplate` explicitly checks `arrDeviceAddresses.indexOf(from_address) === -1` to ensure the sender is actually a party to the definition template [1](#0-0) .

However, `handleNewSharedAddress`, reachable directly via the `new_shared_address` device-message subject [2](#0-1) , never receives or checks `from_address` at all: [3](#0-2) 

It only verifies that:
1. `body.address` is the correct chash of `body.definition` (self-consistency, trivially satisfiable by the attacker who crafts both).
2. Each `signers[path].address` matches the `['address', ...]` leaf at the same path in the definition (again self-consistency).
3. `determineIfIncludesMeAndRewriteDeviceAddress` — which, if one of the addresses in the definition happens to be one of *my* own wallet addresses, silently rewrites that signer's `device_address` to my own device, without any confirmation [4](#0-3) .
4. `validateAddressDefinition` — a purely structural/complexity check (`Definition.validateDefinition`) that does not verify signatures or that any specific party actually agreed to being part of it [5](#0-4) .

`addNewSharedAddress` then commits the shared address and its signing paths straight into the DB and fires `new_address` events with no user prompt [6](#0-5) .

This is directly analogous to the reported bug class: just as the fake pool contract only needed to satisfy the router's superficial `uniswapV3SwapCallback` checks (self-consistent calldata) rather than being a genuine, previously-agreed-upon pool, an attacker's crafted `new_shared_address` payload only needs to be internally self-consistent to be accepted as a genuine, previously-agreed multi-party address — no proof that the local device or its owner ever participated in creating this address is required.

A concrete abuse: attacker learns one of the victim's addresses (e.g. shared during a chat, a one-time payment address, or from any prior on-chain interaction), then crafts a definition such as `['or', [['address', VICTIM_ADDR], ['address', ATTACKER_ADDR]]]` and sends `new_shared_address` directly (skipping `create_new_shared_address`/`approve_new_shared_address`). `handleNewSharedAddress` accepts it, `determineIfIncludesMeAndRewriteDeviceAddress` recognizes `VICTIM_ADDR` as one of the victim's own addresses and marks the victim's wallet as a legitimate cosigner of this "shared address," and it gets silently inserted as a `shared_addresses` record the wallet subsequently treats as valid.

### Impact Explanation
Because the definition is an `or` (attacker alone can satisfy it), any funds that end up at this address (via later confused private-payment forwarding, wallet display logic treating it as a wallet-owned shared address, or a victim being led to route funds "back to their own shared address") can be unilaterally spent by the attacker, who holds the other branch of the `or`. This is a concrete fund-loss vector reachable purely by an already-paired device sending one unsolicited message, bypassing the two-step consent/approval design that the codebase itself implements for the legitimate flow (`create_new_shared_address`/`approve_new_shared_address` with `from_address` membership checks). It also enables spoofed shared-address bookkeeping (private-chain forwarding treats these fabricated addresses as genuine members, per `forwardPrivateChainsToOtherMembersOfSharedAddresses`), leaking or misdirecting private-payment data to attacker-controlled cosigner slots.

### Likelihood Explanation
Likelihood is Medium: it requires the attacker to be a paired correspondent of the victim device (easily achieved via pairing links/QR codes/textcoins, which ocore treats as a low-trust bar) and to learn one existing address of the victim (often exposed in normal use, e.g. one-time payment addresses shared over chat). No cryptographic signature or explicit user approval is required to complete the attack, unlike the legitimate shared-address creation flow.

### Recommendation
In `handleNewSharedAddress`, require and verify `from_address` exactly as `validateAddressDefinitionTemplate` does for the legitimate flow: reject the message unless `from_address` is one of the device addresses referenced by the definition's signing paths, and require that a corresponding `pending_shared_addresses`/`approve_new_shared_address` record exists (i.e., that the local user previously agreed to this definition) before calling `addNewSharedAddress`. Do not allow `determineIfIncludesMeAndRewriteDeviceAddress` to silently attach the local device as a cosigner without an explicit UI confirmation step, mirroring the confirmation dialog already used in `create_new_shared_address`.

### Proof of Concept
Not directly executable without live pairing infrastructure and a UI, but the exploit path is:
1. Attacker pairs with the victim's device via a lightweight pairing flow (chat/QR/textcoin), which ocore permits via `arrSubjectsAllowedFromNoncorrespondents` and `handlePairingMessage` [7](#0-6) .
2. Attacker learns `VICTIM_ADDR` (any exposed victim wallet address).
3. Attacker crafts `arrDefinition = ['or', [['address', VICTIM_ADDR], ['address', ATTACKER_ADDR]]]`, computes `address = chash160(arrDefinition)`, and constructs `signers = {'r.0': {address: VICTIM_ADDR}, 'r.1': {address: ATTACKER_ADDR, device_address: ATTACKER_DEVICE}}`.
4. Attacker sends a `new_shared_address` device message with `{address, definition: arrDefinition, signers}` directly to the victim [8](#0-7) .
5. `handleNewSharedAddress` passes all its checks (steps 1–4 above) and calls `addNewSharedAddress`, inserting the shared address with the victim's own address as a legitimate member — without the victim ever approving creation of this address [3](#0-2) .
6. Any bytes/assets later paid into `address` can be spent unilaterally by the attacker through the `or` branch, while the victim's wallet believes it jointly (or exclusively) controls that address.

### Citations

**File:** wallet_defined_by_addresses.js (L45-49)
```javascript
function sendNewSharedAddress(device_address, address, arrDefinition, assocSignersByPath, bForwarded){
	device.sendMessageToDevice(device_address, "new_shared_address", {
		address: address, definition: arrDefinition, signers: assocSignersByPath, forwarded: bForwarded
	});
}
```

**File:** wallet_defined_by_addresses.js (L239-268)
```javascript
function addNewSharedAddress(address, arrDefinition, assocSignersByPath, bForwarded, onDone){
//	network.addWatchedAddress(address);
	db.query(
		"INSERT "+db.getIgnore()+" INTO shared_addresses (shared_address, definition) VALUES (?,?)", 
		[address, JSON.stringify(arrDefinition)], 
		function(){
			var arrQueries = [];
			for (var signing_path in assocSignersByPath){
				var signerInfo = assocSignersByPath[signing_path];
				db.addQuery(arrQueries, 
					"INSERT "+db.getIgnore()+" INTO shared_address_signing_paths \n\
					(shared_address, address, signing_path, member_signing_path, device_address) VALUES (?,?,?,?,?)", 
					[address, signerInfo.address, signing_path, signerInfo.member_signing_path, signerInfo.device_address]);
			}
			async.series(arrQueries, function(){
				console.log('added new shared address '+address);
				eventBus.emit("new_address-"+address);
				eventBus.emit("new_address", address);

				if (conf.bLight){
					db.query("INSERT " + db.getIgnore() + " INTO unprocessed_addresses (address) VALUES (?)", [address], onDone);
				} else if (onDone)
					onDone();
				if (!bForwarded)
					forwardNewSharedAddressToCosignersOfMyMemberAddresses(address, arrDefinition, assocSignersByPath);
			
			});
		}
	);
}
```

**File:** wallet_defined_by_addresses.js (L281-315)
```javascript
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

**File:** wallet_defined_by_addresses.js (L377-415)
```javascript
// {address: "BASE32", definition: [...], signers: {...}}
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

**File:** wallet_defined_by_addresses.js (L481-495)
```javascript
function validateAddressDefinitionTemplate(arrDefinitionTemplate, from_address, handleResult){
	try{
		var assocMemberDeviceAddressesBySigningPaths = getMemberDeviceAddressesBySigningPaths(arrDefinitionTemplate);
	}
	catch (e) {
		return handleResult("failed to get member device addresses of new shared address: " + e.toString());
	}
	var arrDeviceAddresses = _.uniq(_.values(assocMemberDeviceAddressesBySigningPaths));
	if (arrDeviceAddresses.length < 2)
		return handleResult("less than 2 member devices");
	if (arrDeviceAddresses.indexOf(device.getMyDeviceAddress()) === - 1)
		return handleResult("my device address not mentioned in the definition");
	if (arrDeviceAddresses.indexOf(from_address) === - 1)
		return handleResult("sender device address not mentioned in the definition");
	
```

**File:** wallet_defined_by_addresses.js (L518-528)
```javascript
// fix:
// 1. check that my address is referenced in the definition
function validateAddressDefinition(arrDefinition, handleResult){
	var objFakeUnit = {authors: []};
	var objFakeValidationState = {last_ball_mci: MAX_INT32, bAllowUnresolvedInnerDefinitions: true};
	Definition.validateDefinition(db, arrDefinition, objFakeUnit, objFakeValidationState, null, false, function(err){
		if (err)
			return handleResult(err);
		handleResult();
	});
}
```

**File:** wallet.js (L236-245)
```javascript
			case "new_shared_address":
				// {address: "BASE32", definition: [...], signers: {...}}
				walletDefinedByAddresses.handleNewSharedAddress(body, {
					ifError: callbacks.ifError,
					ifOk: function(){
						callbacks.ifOk();
						eventBus.emit('maybe_new_transactions');
					}
				});
				break;
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
