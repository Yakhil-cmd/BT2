## Title
Missing Authorization on `new_shared_address` Device-Message Handler Allows Any Paired Device to Register Forged Multisig Addresses as Wallet-Owned — Enabling Theft of Funds Sent There ([File: wallet_defined_by_addresses.js])

### Summary
The Anchor CMS CVE describes a class of bug where a privileged state-changing endpoint (`admin/users/add`, `admin/users/edit`) is reachable by any authenticated low-privilege actor because the handler never verifies that the caller actually went through the expected authorization workflow before it is allowed to mutate sensitive account/membership state. `ocore`'s wallet-pairing subsystem has an analogous flaw: the network message handler for `new_shared_address`, reachable from any paired correspondent device, persists a new "shared address" membership record for the local wallet without ever verifying that the local device actually participated in the expected `create_new_shared_address` → `approve_new_shared_address` handshake for that specific address.

### Finding Description
In `wallet.js`, the case `"new_shared_address"` dispatches directly to `wallet_defined_by_addresses.js`'s `handleNewSharedAddress()` for any correspondent device message, without any confirmation step: [1](#0-0) 

`handleNewSharedAddress()` only performs syntactic checks: that the definition hashes to the claimed address, that declared signer addresses are syntactically valid, and that signer paths match addresses extracted from the definition: [2](#0-1) 

The only "ownership" check performed is `determineIfIncludesMeAndRewriteDeviceAddress()`, which merely confirms that *some* address referenced anywhere in the definition is already known to the local device (in `my_addresses` or `shared_addresses`): [3](#0-2) 

Crucially, there is no check that this specific shared address went through the intended creation/approval workflow (`createNewSharedAddressByTemplate` → `pending_shared_addresses` / `pending_shared_address_signing_paths` → `approvePendingSharedAddress`), which is the normal, human-confirmed path for creating a shared address: [4](#0-3) [5](#0-4) 

Because `Definition.validateDefinition()` (invoked from `validateAddressDefinition()`) only checks structural validity of the oscript definition, not the good faith of the participants, an attacker (any paired correspondent device) can craft an arbitrary definition such as `["or", [["address", VICTIM_REAL_ADDRESS], ["sig", {pubkey: ATTACKER_PUBKEY}]]]`, listing the victim's own already-known address as one signer: [6](#0-5) 

`determineIfIncludesMeAndRewriteDeviceAddress` will find the victim's real address in `my_addresses` and pass the check, even though the "or" structure means the victim's cooperation is not actually required to spend from the crafted address. `handleNewSharedAddress()` then calls `addNewSharedAddress()`, which unconditionally inserts the forged address into `shared_addresses` / `shared_address_signing_paths` and — critically — **automatically forwards the forged shared address to the victim's other cosigner devices** via `forwardNewSharedAddressToCosignersOfMyMemberAddresses()`, propagating the false trust: [7](#0-6) [8](#0-7) 

No user confirmation dialog is required at any point in this path (contrast with `create_new_shared_address`, which does emit a confirmation event for the user before creating anything).

### Impact Explanation
Once the forged shared address is silently registered, it is indistinguishable in the local database from a legitimately negotiated multisig address bound to the victim's real key. If the victim (or any of their genuine cosigner devices, which received the forwarded forged definition) later sends funds to this address believing it requires the victim's cooperation to spend, the attacker can unilaterally drain the funds using only their own signature via the "or" branch — this is concrete unauthorized spending of the victim's/counterparties' funds, achieved purely through a device message with no cryptographic or economic cost to the attacker, matching the "missing authorization on user-management/membership endpoint" bug class in the source CVE.

### Likelihood Explanation
Any device that is a paired correspondent of the victim (a very low bar — pairing is done for ordinary chat/wallet interactions) can send this message at will; no prior wallet or multisig relationship is required beyond having previously observed one of the victim's addresses (addresses are frequently shared for receiving payments). The check bypassed is purely structural, so crafting a valid definition and matching `signers` map is straightforward.

### Recommendation
`handleNewSharedAddress()` must verify that the receiving device actually initiated or approved this specific shared address through the `pending_shared_addresses`/`pending_shared_address_signing_paths` workflow (or require explicit user confirmation) before persisting it, rather than accepting any device-supplied definition that merely happens to reference one of the local wallet's known addresses. Additionally, `determineIfIncludesMeAndRewriteDeviceAddress` should reject definitions where the local address only appears inside a disjunctive (`or`) branch that is not actually required for spending, or the UI/back end should clearly flag and require explicit confirmation before treating any newly received shared address as usable/displayable for receiving funds.

### Proof of Concept
1. Attacker device `D_A` pairs with victim device `D_V` (ordinary correspondent pairing).
2. `D_A` learns victim's real address `ADDR_V` (e.g., from a prior payment).
3. `D_A` builds `arrDefinition = ["or", [["address", ADDR_V], ["sig", {pubkey: ATTACKER_PUBKEY}]]]`, computes `addr = objectHash.getChash160(arrDefinition)`, and sends device message:
```
{ subject: "new_shared_address",
  body: { address: addr, definition: arrDefinition,
          signers: { "r.0": {address: ADDR_V}, "r.1": {address: "secret"} } } }
```
4. `D_V`'s `handleMessageFromHub` routes to `wallet_defined_by_addresses.handleNewSharedAddress` (`wallet.js:236-245`), which passes all checks (`wallet_defined_by_addresses.js:377-415`) because `ADDR_V` is a known `my_addresses` entry, and inserts `addr` into `shared_addresses`, forwarding it to `D_V`'s other cosigner devices.
5. Any third party who later pays to `addr` (believing it requires `ADDR_V`'s cooperation) has their funds immediately spendable by `D_A` alone via the `sig` branch.

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

**File:** wallet_defined_by_addresses.js (L106-146)
```javascript
function createNewSharedAddressByTemplate(arrAddressDefinitionTemplate, my_address, assocMyDeviceAddressesByRelativeSigningPaths){
	validateAddressDefinitionTemplate(arrAddressDefinitionTemplate, device.getMyDeviceAddress(), function(err, assocMemberDeviceAddressesBySigningPaths){
		if(err) {
			throw Error(err);
		}

		// assocMemberDeviceAddressesBySigningPaths are keyed by paths from root to member addresses (not all the way to signing keys)
		var arrMemberSigningPaths = Object.keys(assocMemberDeviceAddressesBySigningPaths);
		var address_definition_template_chash = objectHash.getChash160(arrAddressDefinitionTemplate);
		db.query(
			"INSERT INTO pending_shared_addresses (definition_template_chash, definition_template) VALUES(?,?)", 
			[address_definition_template_chash, JSON.stringify(arrAddressDefinitionTemplate)],
			function(){
				async.eachSeries(
					arrMemberSigningPaths, 
					function(signing_path, cb){
						var device_address = assocMemberDeviceAddressesBySigningPaths[signing_path];
						var fields = "definition_template_chash, device_address, signing_path";
						var values = "?,?,?";
						var arrParams = [address_definition_template_chash, device_address, signing_path];
						if (device_address === device.getMyDeviceAddress()){
							fields += ", address, device_addresses_by_relative_signing_paths, approval_date";
							values += ",?,?,"+db.getNow();
							arrParams.push(my_address, JSON.stringify(assocMyDeviceAddressesByRelativeSigningPaths));
						}
						db.query("INSERT INTO pending_shared_address_signing_paths ("+fields+") VALUES("+values+")", arrParams, function(){
							cb();
						});
					},
					function(){
						var arrMemberDeviceAddresses = _.uniq(_.values(assocMemberDeviceAddressesBySigningPaths));
						arrMemberDeviceAddresses.forEach(function(device_address){
							if (device_address !== device.getMyDeviceAddress())
								sendOfferToCreateNewSharedAddress(device_address, arrAddressDefinitionTemplate);
						})
					}
				);
			}
		);
	});
}
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
