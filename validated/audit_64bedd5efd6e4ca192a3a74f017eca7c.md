### Title
Unvalidated `new_shared_address` device message allows a paired correspondent to plant a shared-address definition that fully compromises the victim's funds - ([File: wallet_defined_by_addresses.js])

### Summary
The `handle_message_from_hub` dispatcher in `wallet.js` accepts a `new_shared_address` message from any already-paired correspondent device and forwards its raw body directly into `walletDefinedByAddresses.handleNewSharedAddress()` with no check that the sender is actually a party who negotiated this address (unlike the `approve_new_shared_address` flow, which is tied to a locally-created `pending_shared_addresses` record). [1](#0-0)  `handleNewSharedAddress` only checks internal consistency of the attacker-supplied `definition`/`signers` (hash match, address validity, definition validity) — it never verifies that the message originated from the device that is supposed to control the non-local signer paths. [2](#0-1) 

### Finding Description
This is the same access-control-gap bug class as the Chainlink report: a function that is only meant to be invoked as a step in a specific, previously-authorized protocol flow (there `Gateway.sol`→`ChainlinkLightClient`, here "my wallet completed a shared-address negotiation with these specific cosigners" → `handleNewSharedAddress`) has no verification of who is actually calling it.

Concretely:
- `wallet.js`'s `new_shared_address` case takes `body = {address, definition, signers}` straight from the just-saying device message and calls `handleNewSharedAddress(body, ...)` — it does not use `from_address` at all. [1](#0-0) 
- `handleNewSharedAddress` validates that `definition` hashes to `address`, that each `signers[path].address` is well-formed and matches an `["address", ...]` leaf of `definition`, and that `Definition.validateAddressDefinition` accepts the definition — but performs no check that `from_address` (the actual sender) is one of the parties in `signers`. [2](#0-1) 
- It then calls `determineIfIncludesMeAndRewriteDeviceAddress`, which only checks whether one of the addresses referenced in `signers` belongs to the victim's own `my_addresses`/`shared_addresses` — it does not verify the sender's legitimacy, only that the victim happens to be a "member". [3](#0-2) 
- `addNewSharedAddress` then unconditionally inserts the attacker-chosen `definition` into `shared_addresses` and `shared_address_signing_paths`, and re-broadcasts it to the victim's other cosigner devices. [4](#0-3) 

By contrast, the legitimate flow (`create_new_shared_address` → `approve_new_shared_address`) is anchored to a `pending_shared_address_signing_paths` row keyed by `(definition_template_chash, device_address)`, so a completed shared address can only be finalized from parties who were actually invited. [5](#0-4)  The `new_shared_address` message has no equivalent binding, so any already-paired correspondent can skip the negotiation entirely and inject an arbitrary "completed" shared address.

### Impact Explanation
Because the victim's own address can appear inside an `"or"` combinator alongside an attacker-controlled address (e.g. `["or", [["address", "<victim>"], ["address", "<attacker>"]]]`), the attacker satisfies `determineIfIncludesMeAndRewriteDeviceAddress`'s "I am a member" check while retaining sole, unilateral spending authority (an `"or"` condition is satisfied by either signer alone). The wallet stores this as a legitimate "shared address" the user believes is co-controlled, and if the user (or the attacker, via social engineering, since they already share a pairing) is induced to fund that address, the attacker can spend the entire balance alone — this is unauthorized spending / theft of funds, matching the accepted impact classes (concrete unauthorized spending / AA-equivalent fund loss for a device-wallet victim).

### Likelihood Explanation
The only prerequisite is that attacker and victim are already paired correspondent devices (a normal, common relationship in Obyte wallets, e.g. established for chat, multi-device, or prior legitimate shared-address use) — pairing is required because `new_shared_address` is not in the whitelist of subjects allowed from non-correspondents. [6](#0-5)  Given pairing, the attack requires no additional user interaction beyond the victim depositing funds to what they believe is a jointly-controlled address, making this readily reachable and directly analogous to the "wrong data can easily be stored" concern in the reference report.

### Recommendation
Bind acceptance of a `new_shared_address` message to a prior locally-initiated negotiation, mirroring the `approve_new_shared_address` design:
- Require that the shared address (or its `definition_template_chash`) correspond to an existing `pending_shared_addresses`/already-approved record before calling `addNewSharedAddress`, or
- Verify that `from_address` matches the `device_address` recorded for the corresponding signing path(s) in a prior handshake, rejecting unsolicited `new_shared_address` messages with no matching pending negotiation.
- Additionally, warn/reject definitions where the victim's own address is combined with unknown addresses via `"or"`/similarly permissive combinators without prior explicit user consent, since such definitions defeat the "shared" custody model.

### Proof of Concept
1. Attacker `D_A` is a paired correspondent of victim `D_V` (owns address `Addr_V`, publicly known/observable on-chain).
2. `D_A` picks its own address `Addr_A` and builds `arrDefinition = ["or", [["address","Addr_V"], ["address","Addr_A"]]]`, computes `address = chash160(arrDefinition)`.
3. `D_A` sends a `hub/message`/direct device message with `subject: "new_shared_address"`, `body: {address, definition: arrDefinition, signers: {"r.0": {address: "Addr_V"}, "r.1": {address: "Addr_A", device_address: D_A}}}`.
4. `D_V`'s `handleMessageFromHub` dispatches to `handleNewSharedAddress(body, ...)` with no check on `from_address`. [1](#0-0) 
5. Validation passes (hash matches, addresses well-formed, definition is a valid `"or"` structure), `determineIfIncludesMeAndRewriteDeviceAddress` finds `Addr_V` in `my_addresses`, and `addNewSharedAddress` inserts the shared address into `D_V`'s local DB. [7](#0-6) 
6. `D_V`'s wallet UI now shows `address` as a shared address it believes requires cooperation; once bytes/assets are sent to `address`, `D_A` alone can sign and spend them (its own `"address"` branch of the `"or"` is independently sufficient), resulting in unilateral theft.

**Uncertainty note:** I could not fully verify from the indexed code what UI-level warnings (if any) exist when a wallet displays or funds a shared address whose definition uses an `"or"` of two independent addresses — this may partially mitigate real-world exploitability depending on client behavior not visible in the indexed files. A Devin session with full repository/UI access would be needed to confirm whether any such warning exists.

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

**File:** wallet_defined_by_addresses.js (L239-315)
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

function includesMyDeviceAddress(assocSignersByPath){
	for (var signing_path in assocSignersByPath){
		var signerInfo = assocSignersByPath[signing_path];
		if (signerInfo.device_address === device.getMyDeviceAddress())
			return true;
	}
	return false;
}

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

**File:** device.js (L213-220)
```javascript
				else{ // correspondent not known
					var arrSubjectsAllowedFromNoncorrespondents = ["pairing", "my_xpubkey", "wallet_fully_approved"];
					if (arrSubjectsAllowedFromNoncorrespondents.indexOf(json.subject) === -1){
						respondWithError("correspondent not known and not whitelisted subject");
						return;
					}
					handleMessage(false);
				}
```
