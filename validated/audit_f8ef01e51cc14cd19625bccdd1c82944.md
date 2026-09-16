## Title
Unauthenticated `device_address` binding in shared/multisig address negotiation allows signing-request misdirection and fund freezing — (File: `wallet_defined_by_addresses.js`)

### Summary
The KDE Connect CVE (CVE-2025-66270) stems from the protocol failing to correlate the device identity asserted in one packet with the device identity established/verified in a related packet, letting an attacker substitute a different device identity mid-protocol. `ocore`'s device-message layer (`device.js`) correctly binds `from_address` to the signing pubkey for every incoming message, but this binding is not propagated into the *content* of multi-party wallet-setup messages. In `wallet_defined_by_addresses.js`, the `device_address` values that map a multisig/shared-address signing path to "which device should be contacted to obtain that signature" are taken verbatim from the message body and are never correlated against any authenticated identity for the corresponding cryptographic address.

### Finding Description
When a shared (multisig) address is being negotiated, cosigners exchange `approve_new_shared_address` and `new_shared_address` device messages whose bodies carry a `device_addresses_by_relative_signing_paths` / `signers` map of `signing_path -> { address, device_address }`.

- `handleNewSharedAddress` in `wallet_defined_by_addresses.js` validates that `signerInfo.address` is a syntactically valid address and matches the definition c-hash, but never validates `signerInfo.device_address` against anything — not against the sender's verified `from_address`, not against prior pairing state, not against any previously-established binding for that `address`: [1](#0-0) 

- The unchecked `device_address` is persisted directly into `shared_address_signing_paths`, which is the table used later to decide where to route signing requests for that address/path: [2](#0-1) 

- The same pattern exists on the approval side: `approvePendingSharedAddress` stores the caller-supplied `device_addresses_by_relative_signing_paths` keyed only by the (already-authenticated) `from_address` of the *sender*, but the values inside that map — the device addresses of *other* signing paths — are never cross-checked against the real owners of those paths: [3](#0-2) 

- The message-level validation in `wallet.js` for these subjects only checks types/shape, not device-identity correlation: [4](#0-3) 

This is the direct analog of the CVE's root cause: one packet establishes a cryptographically-verified device identity (`from_address` derived from the signing pubkey in `device.js`), while a second, related packet asserts a *different* device identity (the `device_address` field embedded in the JSON body) for use in future routing/trust decisions, and the two are never correlated.

### Impact Explanation
A malicious cosigner participating in setting up a shared/multisig address (a role reachable simply by being invited to or joining a multi-device wallet — no hub/network privileges required) can supply an attacker-controlled `device_address` for another legitimate cosigner's signing path. Once persisted in `shared_address_signing_paths`, all future signing requests for that path (i.e., "please sign this unit to spend from the shared address") are routed to the attacker's device instead of the legitimate cosigner's device. Because the legitimate cosigner never receives the signing request, the multisig address can never collect the required signature set, permanently freezing any funds sent to that shared address (a wallet whose spending threshold now can never be met from that node's perspective). This matches the accepted "AA/shared-address fund freezing" impact class and also creates persistent node disagreement about who the valid remote signer for the address is.

### Likelihood Explanation
The negotiation path (`new_shared_address` / `approve_new_shared_address`) is reachable by any device already invited into a shared-address setup (a normal, expected multi-party wallet flow), and no additional privilege besides being a participating cosigner is required to poison the `device_address` mapping for other cosigners' paths. The lack of any correlation check makes exploitation deterministic and reliable once the attacker is included as one signer in a shared/multisig address definition.

### Recommendation
Bind `device_address` values embedded in `new_shared_address` / `approve_new_shared_address` bodies to the message's own authenticated `from_address` for the path(s) the sender legitimately controls, and require that `device_address` entries for other paths be corroborated (e.g., only accepted from the device that is itself the owner of that path, or validated against existing `correspondent_devices`/pairing records) rather than trusted purely from body content supplied by a third-party cosigner.

### Proof of Concept
1. Attacker device `A` is one of 3 cosigners being set up for a shared address alongside legitimate devices `B` (victim) and `C` (initiator).
2. During negotiation, `A` sends `approve_new_shared_address` (or is the one relaying `new_shared_address`) with `device_addresses_by_relative_signing_paths`/`signers` containing `B`'s real `address` (chash) but a `device_address` value equal to `A`'s own device address instead of `B`'s.
3. `approvePendingSharedAddress`/`handleNewSharedAddress` accept and persist this mapping unchecked into `shared_address_signing_paths` [5](#0-4) .
4. When `C` (or any node) later needs `B`'s signature to spend from the shared address, the signing request is sent to `A` (per the poisoned `device_address`) instead of `B`, so `B` never signs and the funds at the shared address become permanently unspendable.

### Citations

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

**File:** wallet.js (L214-226)
```javascript
			case "approve_new_shared_address":
				// {address_definition_template_chash: "BASE32", address: "BASE32", device_addresses_by_relative_signing_paths: {...}}
				if (!ValidationUtils.isValidAddress(body.address_definition_template_chash))
					return callbacks.ifError("invalid addr def c-hash");
				if (!ValidationUtils.isValidAddress(body.address))
					return callbacks.ifError("invalid address");
				if (typeof body.device_addresses_by_relative_signing_paths !== "object" 
						|| Object.keys(body.device_addresses_by_relative_signing_paths).length === 0)
					return callbacks.ifError("invalid device_addresses_by_relative_signing_paths");
				walletDefinedByAddresses.approvePendingSharedAddress(body.address_definition_template_chash, from_address, 
					body.address, body.device_addresses_by_relative_signing_paths);
				callbacks.ifOk();
				break;
```
