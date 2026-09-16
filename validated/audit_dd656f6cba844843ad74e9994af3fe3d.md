Confirmed: `handleNewSharedAddress` in `wallet_defined_by_addresses.js` accepts and silently installs a new "shared address" record whenever a paired correspondent sends the `new_shared_address` message, without ever checking that the receiving device went through the `create_new_shared_address` → user-confirmation → `approve_new_shared_address` handshake that the code's own comments say should happen. This is the exact analog of the Plone bug class: a "member" (here, a cosigner relationship binding the victim's already-known address into a new multi-party address) is registered without acknowledgment from the address owner.

### Title
Unauthorized silent registration of shared (multisig) addresses without owner acknowledgment - (File: wallet_defined_by_addresses.js)

### Summary
`wallet.js`'s `handleMessageFromHub` dispatches the `new_shared_address` subject directly to `walletDefinedByAddresses.handleNewSharedAddress`, which structurally validates the message and then calls `addNewSharedAddress` unconditionally — with no requirement that the recipient device ever agreed to be part of that specific address, unlike the parallel `create_new_shared_address`/`approve_new_shared_address` flow that explicitly requires an interactive user-confirmation dialog.

### Finding Description
The normal, safe flow for creating a shared (multisig-like) address is: the initiator sends `create_new_shared_address` (`wallet.js:197-212`), which triggers an event explicitly documented to "trigger a confirmation dialog, user needs to approve creation of the shared address and choose his own address" [1](#0-0) . Only after the user approves via UI does `approve_new_shared_address` get sent back and processed by `approvePendingSharedAddress`, which finally inserts into `shared_addresses` [2](#0-1) .

However, any paired correspondent can bypass this entire acknowledgment step by sending the `new_shared_address` message directly. `wallet.js` routes it straight to `handleNewSharedAddress`: [3](#0-2) 

`handleNewSharedAddress` only checks internal structural consistency of the message — that the definition hashes to the claimed address, that signer addresses referenced in the definition are syntactically valid addresses, and that every path in the definition has a matching signer entry: [4](#0-3) 

It then calls `determineIfIncludesMeAndRewriteDeviceAddress`, whose only real gatekeeping check is that at least one of the addresses named in the definition is already an address the victim owns (`my_addresses`) or already knows (`shared_addresses`): [5](#0-4) 

Since a victim's payment addresses are public (visible in past unit outputs on the DAG), any correspondent can learn one, then craft an arbitrary address definition — e.g. `["or", [["address", victim_addr], ["address", attacker_addr]]]` — and send it as `new_shared_address`. Because the check only requires that the *victim's* address is referenced somewhere, and never verifies that the victim's device previously initiated/approved *this particular* address or definition, `addNewSharedAddress` will silently persist the record into `shared_addresses` / `shared_address_signing_paths` and even auto-forward it further to other cosigners of the victim's own addresses via `forwardNewSharedAddressToCosignersOfMyMemberAddresses`: [6](#0-5) [7](#0-6) 

`validateAddressDefinition` only checks the definition is a well-formed address-definition script (signature-presence, complexity limits, etc.) — it does not check who controls which branch of an `or`/`weighted and`: [8](#0-7) 

The net effect is that the wallet silently records an address as "one I have a stake in" (appears in the user's shared-address/cosigner UI, `readSharedAddressCosigners`, `readAllControlAddresses`, receives forwarded private-payment chains, etc.) even though the actual on-chain definition may give the attacker sole, unilateral spending rights over that address (via `or`), with no cosignature from the victim ever required — all without any acknowledgment dialog, contrary to the documented intended design that requires explicit user approval before any shared address is added.

### Impact Explanation
If the victim later trusts this UI-listed "shared address" and directs funds to it (assuming it is protected like other cosigned addresses shown in their wallet), the attacker — who alone satisfies the `or` branch — can unilaterally spend/drain those funds without any signature from the victim. This is unauthorized spending/fund loss stemming purely from a bypass of the required ownership-acknowledgment step, matching the impact class of unauthorized fund loss from an authorization bypass.

### Likelihood Explanation
Requires the attacker to already be a paired correspondent of the victim (a normal, low-barrier social/contact relationship in ocore, not a privileged position), and the victim's public payment address (visible from any past transaction). No cryptographic bypass, no privileged access, and no additional user interaction is needed — the message is processed automatically by `handleMessageFromHub`, making exploitation straightforward once contacts are established (CVSS AC:H analog corresponds to needing correspondent status + reconnaissance of an address, both readily attainable).

### Recommendation
`handleNewSharedAddress` should not persist an unsolicited shared address definition. It should require that the definition/address (or its `definition_template_chash`) matches an entry the receiving device itself previously created via `createNewSharedAddressByTemplate`/`pending_shared_addresses`, or otherwise require an explicit user-confirmation event (mirroring `create_new_shared_address`) before calling `addNewSharedAddress`, instead of auto-accepting any structurally valid definition that merely references one of the victim's known addresses.

### Proof of Concept
1. Attacker pairs with victim (normal pairing flow), and separately observes victim's known address `V` from any prior unit on the DAG.
2. Attacker builds `arrDefinition = ["or", [["address", "V"], ["address", "A"]]]` (A = attacker's own address), computes `address = getChash160(arrDefinition)`, and constructs `signers = {"r.0": {address: "V", device_address: victim_device_address}, "r.1": {address: "A", device_address: attacker_device_address}}`.
3. Attacker sends device message `{subject: "new_shared_address", body: {address, definition: arrDefinition, signers}}` to victim.
4. Victim's `handleMessageFromHub` → `handleNewSharedAddress` passes all structural checks (definition hashes correctly, `V` is a known/owned address) and silently calls `addNewSharedAddress`, inserting the new address into `shared_addresses`/`shared_address_signing_paths` with no dialog or approval shown to the victim.
5. If the victim (seeing this address surfaced in their wallet's shared-address list) sends funds to `address`, the attacker can spend them alone via the `or` branch, without any cosignature.

### Citations

**File:** wallet.js (L197-211)
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

**File:** wallet_defined_by_addresses.js (L148-227)
```javascript
// unused
// received approval from co-signer address
function approvePendingSharedAddress(address_definition_template_chash, from_address, address, assocDeviceAddressesByRelativeSigningPaths){
	db.query( // may update several rows if the device is referenced multiple times from the definition template
		"UPDATE pending_shared_address_signing_paths SET address=?, device_addresses_by_relative_signing_paths=?, approval_date="+db.getNow()+" \n\
		WHERE definition_template_chash=? AND device_address=?", 
		[address, JSON.stringify(assocDeviceAddressesByRelativeSigningPaths), address_definition_template_chash, from_address], 
		function(){
			// check if this is the last required approval
			db.query(
				"SELECT device_address, signing_path, address, device_addresses_by_relative_signing_paths \n\
				FROM pending_shared_address_signing_paths \n\
				WHERE definition_template_chash=?",
				[address_definition_template_chash],
				function(rows){
					if (rows.length === 0) // another device rejected the address at the same time
						return;
					if (rows.some(function(row){ return !row.address; })) // some devices haven't approved yet
						return;
					// all approvals received
					var params = {};
					rows.forEach(function(row){ // the same device_address can be mentioned in several rows
						params['address@'+row.device_address] = row.address;
					});
					db.query(
						"SELECT definition_template FROM pending_shared_addresses WHERE definition_template_chash=?", 
						[address_definition_template_chash],
						function(templ_rows){
							if (templ_rows.length !== 1)
								throw Error("template not found");
							var arrAddressDefinitionTemplate = JSON.parse(templ_rows[0].definition_template);
							var arrDefinition = Definition.replaceInTemplate(arrAddressDefinitionTemplate, params);
							var shared_address = objectHash.getChash160(arrDefinition);
							db.query(
								"INSERT INTO shared_addresses (shared_address, definition) VALUES (?,?)", 
								[shared_address, JSON.stringify(arrDefinition)], 
								function(){
									var arrQueries = [];
									var assocSignersByPath = {};
									rows.forEach(function(row){
										var assocDeviceAddressesByRelativeSigningPaths = JSON.parse(row.device_addresses_by_relative_signing_paths);
										for (var member_signing_path in assocDeviceAddressesByRelativeSigningPaths){
											var signing_device_address = assocDeviceAddressesByRelativeSigningPaths[member_signing_path];
											// this is full signing path, from root of shared address (not from root of member address)
											var full_signing_path = row.signing_path + member_signing_path.substring(1);
											// note that we are inserting row.device_address (the device we requested approval from), not signing_device_address 
											// (the actual signer), because signing_device_address might not be our correspondent. When we need to sign, we'll
											// send unsigned unit to row.device_address and it'll forward the request to signing_device_address (subject to 
											// row.device_address being online)
											db.addQuery(arrQueries, 
												"INSERT INTO shared_address_signing_paths \n\
												(shared_address, address, signing_path, member_signing_path, device_address) VALUES(?,?,?,?,?)", 
												[shared_address, row.address, full_signing_path, member_signing_path, row.device_address]);
											assocSignersByPath[full_signing_path] = {
												device_address: row.device_address, 
												address: row.address, 
												member_signing_path: member_signing_path
											};
										}
									});
									async.series(arrQueries, function(){
										deletePendingSharedAddress(address_definition_template_chash);
										// notify all other member-devices about the new shared address they are a part of
										rows.forEach(function(row){
											if (row.device_address !== device.getMyDeviceAddress())
												sendNewSharedAddress(row.device_address, shared_address, arrDefinition, assocSignersByPath);
										});
										forwardNewSharedAddressToCosignersOfMyMemberAddresses(shared_address, arrDefinition, assocSignersByPath);
										if (conf.bLight)
											network.addLightWatchedAddress(shared_address);
									});
								}
							);
						}
					);
				}
			);
		}
	);
}
```

**File:** wallet_defined_by_addresses.js (L239-267)
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

**File:** wallet_defined_by_addresses.js (L317-336)
```javascript
function forwardNewSharedAddressToCosignersOfMyMemberAddresses(address, arrDefinition, assocSignersByPath){
	var assocMyMemberAddresses = {};
	for (var signing_path in assocSignersByPath){
		var signerInfo = assocSignersByPath[signing_path];
		if (signerInfo.device_address === device.getMyDeviceAddress() && signerInfo.address)
			assocMyMemberAddresses[signerInfo.address] = true;
	}
	var arrMyMemberAddresses = Object.keys(assocMyMemberAddresses);
	if (arrMyMemberAddresses.length === 0)
		return console.log("forwardNewSharedAddressToCosignersOfMyMemberAddresses: my member addresses not found for shared address " + address, arrDefinition, assocSignersByPath);
	db.query(
		"SELECT DISTINCT device_address FROM my_addresses JOIN wallet_signing_paths USING(wallet) WHERE address IN(?) AND device_address!=?", 
		[arrMyMemberAddresses, device.getMyDeviceAddress()],
		function(rows){
			rows.forEach(function(row){
				sendNewSharedAddress(row.device_address, address, arrDefinition, assocSignersByPath, true);
			});
		}
	);
}
```

**File:** wallet_defined_by_addresses.js (L377-405)
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
