### Title
Unsolicited `new_shared_address` Device Message Forces Local Wallet into Shared-Address Membership Without Prior Offer/Approval Handshake - (File: wallet_defined_by_addresses.js / wallet.js)

### Summary
Chamilo's bug allowed an authenticated user to directly call the friend-request AJAX endpoint and force a friendship relationship, completely bypassing the normal request→accept handshake. In `ocore`, the analogous logic exists in the shared/multisig-address workflow: the correct protocol is `create_new_shared_address` → user reviews and approves → `approve_new_shared_address`/`reject_new_shared_address`. However, the `new_shared_address` device-message handler skips this entire request/approval workflow and directly writes the shared address to the recipient's wallet database as soon as it receives the message, exactly like the Chamilo endpoint that let an attacker "add a friend" by calling the terminal state-changing action directly instead of going through the offer/accept flow.

### Finding Description
`wallet.js` routes an incoming `"new_shared_address"` device message straight into `walletDefinedByAddresses.handleNewSharedAddress`, without checking whether the sender had ever been offered participation in this address, or whether the local device had previously approved anything: [1](#0-0) 

`handleNewSharedAddress` performs only cryptographic/self-consistency checks (definition matches its c-hash, signer addresses look like valid addresses, signer addresses match paths declared in the definition) and a membership check that only requires *some* signing path in the message to reference an address the local device already knows about (`my_addresses` or `shared_addresses`): [2](#0-1) 

The membership check itself, `determineIfIncludesMeAndRewriteDeviceAddress`, does not verify that this shared address was ever requested/offered by the local user; it only confirms one of the addresses mentioned in the attacker-supplied `signers` map happens to belong to the victim: [3](#0-2) 

Once these checks pass, `addNewSharedAddress` unconditionally inserts the address into `shared_addresses` and `shared_address_signing_paths`, and even forwards the fabricated relationship to the victim's other cosigner devices, permanently registering the multisig relationship in the victim's wallet without any confirmation dialog or prior handshake step (contrast with the "commented-out"/reference `create_new_shared_address` → `approve_new_shared_address` flow, which is explicitly designed to require mutual consent before a shared address is finalized): [4](#0-3) [5](#0-4) 

This mirrors the Chamilo flaw precisely: the intended state machine has a "propose" step (`create_new_shared_address`) and an "accept" step (`approve_new_shared_address`), but a third message (`new_shared_address`) exists that lets any correspondent jump straight to the finalized state on the victim's device, bypassing the offer/accept logic entirely.

### Impact Explanation
Any device that is (or can become, e.g. via the low-friction `pairing` handshake) a correspondent of the victim can silently register the victim's real address as a member of an attacker-controlled multisig/shared address definition, without the victim ever seeing or approving a "create shared address" request. This corrupts the victim wallet's local view of address relationships (`shared_addresses`, `shared_address_signing_paths`), can be used to solicit spurious `sign` requests against the victim's key under a shared-address pretext the victim never agreed to, and pollutes wallet state that downstream code (e.g., `readAllControlAddresses`, `forwardPrivateChainsToOtherMembersOfAddresses`) treats as trusted membership data. While a full fund-loss requires the victim to also sign a spend, the unauthorized state injection itself breaks the access-control/consent model of the shared-address subsystem and can be leveraged for social-engineering attacks that trick the user into thinking they already co-own an address, in the same spirit as the Chamilo report where non-existent/unwanted relationships were forcibly created.

### Likelihood Explanation
Exploitation requires only that the attacker be a correspondent of the victim (a state reachable via the ordinary pairing flow, which any device address can initiate) and send a single crafted `new_shared_address` justsaying message; no prior `create_new_shared_address` exchange, no privileged access, and no unit posting to the DAG is needed, making this straightforward for any unprivileged correspondent to trigger.

### Recommendation
Require that a `new_shared_address` message correspond to a shared address the local device actually offered or was offered via a prior `create_new_shared_address`/`pending_shared_addresses` record (or otherwise track an explicit "pending" state keyed by device+definition hash) before calling `addNewSharedAddress`, and prompt the user for an explicit approval `eventBus` event instead of silently persisting the relationship. At minimum, cross-check the sender's device_address against an existing pending-approval or a whitelist of addresses the user has explicitly opted into.

### Proof of Concept
1. Victim device V pairs with attacker device A through the normal pairing flow (trivially attacker-initiated).
2. Attacker crafts a definition `["sig", {pubkey: V_pubkey}]` combined with attacker's own address such that V's device address appears in `assocDefinitionAddresses`/`signers` (e.g., `["and", [["address", V_address], ["address", A_address]]]`), computes `addr = objectHash.getChash160(definition)`.
3. Attacker sends V the device message:
   `{subject: "new_shared_address", body: {address: addr, definition: [...], signers: {"r.0": {address: V_address, device_address: V_device_address}, "r.1": {address: A_address, device_address: A_device_address}}}}`
4. On V's device, `wallet.js` dispatches to `handleNewSharedAddress` [1](#0-0) , which passes all checks in `handleNewSharedAddress`/`determineIfIncludesMeAndRewriteDeviceAddress` since `V_address` is a real `my_addresses` entry, and calls `addNewSharedAddress`, permanently registering the shared address in V's wallet without any approval prompt [4](#0-3) .

### Citations

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

**File:** wallet_defined_by_addresses.js (L150-227)
```javascript
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
