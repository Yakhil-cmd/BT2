Confirmed: the `"new_shared_address"` handler in `wallet.js` never checks that `from_address` (the authenticated sender) is actually one of the device addresses referenced inside the definition/signers it is asked to register.### Title
Unauthorized registration of shared-address membership via unauthenticated `new_shared_address` device message - ([File: wallet_defined_by_addresses.js])

### Summary
The `"new_shared_address"` message handler accepts and permanently stores a multisig/shared-address definition and its member `signers` map from *any* paired correspondent device, without ever verifying that the sending device (`from_address`) is actually one of the device addresses referenced as a party/cosigner inside the definition it is submitting. This mirrors the Mattermost flaw where membership in a referenced entity (a team) was never validated before the server trusted/processed the submitted reference (a channel mention) and leaked information about it.

### Finding Description
In `wallet.js`, the `"new_shared_address"` case dispatches directly to `walletDefinedByAddresses.handleNewSharedAddress(body, ...)` with no check that `from_address` participates in `body.signers`: [1](#0-0) 

`handleNewSharedAddress` then validates only the internal structural consistency of the message (definition hashes, signer addresses match definition paths), and delegates membership acceptance to `determineIfIncludesMeAndRewriteDeviceAddress`, followed by generic definition-syntax validation and unconditional insertion into `shared_addresses`/`shared_address_signing_paths`: [2](#0-1) 

`determineIfIncludesMeAndRewriteDeviceAddress` only checks whether one of the addresses listed in the *signers* map matches one of *my own* addresses (`my_addresses`) or a shared address I already track — it never checks that the *sending device* is one of the device addresses embedded in that same signers map: [3](#0-2) 

Because a device pairing (having `from_address` as an authenticated correspondent) is easy to obtain and my wallet address is often disclosed to counterparties during normal use, an attacker-controlled correspondent device can unilaterally submit a `new_shared_address` message naming my real address as a signer alongside arbitrary attacker-chosen device addresses for other signing paths. The check in `determineIfIncludesMeAndRewriteDeviceAddress` will pass (my address is present), `validateAddressDefinition` only checks oscript syntax validity — not who actually agreed to it — and the record is inserted via `addNewSharedAddress`: [4](#0-3) 

The compare point in the advisory is the missing membership validation before trusting attacker-supplied "membership" data (channel_mentions/team names vs. here, shared_address definitions/signers) that gets persisted and later acted upon.

### Impact Explanation
Once such a bogus `shared_addresses`/`shared_address_signing_paths` record is planted, later private-payment flows treat the attacker's device address as a legitimate cosigner of that shared address. `forwardPrivateChainsToOtherMembersOfAddresses` forwards private payment chains to every `device_address` found in `shared_address_signing_paths` for the address (excluding self), with no re-verification of genuine cosigner status: [5](#0-4) 

This lets an attacker who merely knows the victim's public wallet address register themselves as a "cosigner" and subsequently receive forwarded private-chain data for payments involving that address — an information-disclosure/authorization-bypass matching CWE-862 in the advisory. It can also corrupt the victim's local view of which addresses are shared/multisig, and its notion of cosigner device addresses, which drives further protocol behavior (`readAllControlAddresses`, `sendToPeerAllSharedAddressesHavingUnspentOutputs`) that operate on the polluted data: [6](#0-5) [7](#0-6) 

### Likelihood Explanation
Exploitation requires only: (1) an existing device pairing/correspondence with the victim (a routine, low-privilege prerequisite for any wallet chat correspondent), and (2) knowledge of one of the victim's real addresses (frequently shared during normal payment negotiation). No cryptographic signatures, no actual multi-party agreement, and no additional authorization are required to have the message accepted — likelihood is Medium given the widespread and legitimate use of shared/multisig addresses in ocore-based wallets and the ease of learning a correspondent's address.

### Recommendation
Before accepting a `new_shared_address` message, verify that `from_address` corresponds to one of the `device_address` values present in `body.signers` (i.e., the sender must genuinely be a party referenced in the definition it is proposing), in addition to the existing checks that *my* address participates. This should be enforced inside `handleNewSharedAddress` prior to calling `addNewSharedAddress`, mirroring the sender-membership check already present in `validateAddressDefinitionTemplate` (`"sender device address not mentioned in the definition"`) which is applied only to the template-creation flow but missing from the final `new_shared_address` acceptance flow.

### Proof of Concept
1. Attacker device A is a paired correspondent of victim V (normal chat/wallet pairing).
2. A learns V's real address `Addr_V` (e.g., shared for a routine payment).
3. A sends V a `"new_shared_address"` message:
   ```
   {
     address: chash160(definitionArr),
     definition: ["and", [["address", "Addr_V"], ["address", "$device_A_placeholder-resolved-to-Attacker-address"]]] // structurally valid 2-of-2 style definition
     signers: {
       "r.0": {address: "Addr_V", device_address: "<V's device address>"},
       "r.1": {address: "Attacker_Addr", device_address: "<Attacker device address>"}
     }
   }
   ```
4. `handleNewSharedAddress` validates hash/structure only; `determineIfIncludesMeAndRewriteDeviceAddress` finds `Addr_V` in `my_addresses` and accepts.
5. V's node inserts the shared address and signing paths, believing Attacker is a legitimate cosigner device.
6. Later, if V sends a private payment involving this "shared address," `forwardPrivateChainsToOtherMembersOfAddresses` forwards the private chain data to Attacker's device address, disclosing private transaction details the attacker was never legitimately entitled to. [1](#0-0) [2](#0-1) [3](#0-2) [5](#0-4)

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

**File:** wallet_defined_by_addresses.js (L52-68)
```javascript
function sendToPeerAllSharedAddressesHavingUnspentOutputs(device_address, asset, callbacks){
	var asset_filter = !asset || asset == "base" ? " AND outputs.asset IS NULL " : " AND outputs.asset="+db.escape(asset);
	db.query(
		"SELECT DISTINCT shared_address FROM shared_address_signing_paths CROSS JOIN outputs ON shared_address_signing_paths.shared_address=outputs.address\n\
		 WHERE device_address=? AND outputs.is_spent=0" + asset_filter, [device_address], function(rows){
			if (rows.length === 0)
				return callbacks.ifNoFundedSharedAddress();
			rows.forEach(function(row){
				sendSharedAddressToPeer(device_address, row.shared_address, function(err){
					if (err)
						return console.log(err)
					console.log("Definition for " + row.shared_address + " will be sent to " + device_address);
				});
			});
				return callbacks.ifFundedSharedAddress(rows.length);
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

**File:** wallet_defined_by_addresses.js (L378-414)
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
```

**File:** wallet_defined_by_addresses.js (L531-543)
```javascript
function forwardPrivateChainsToOtherMembersOfAddresses(arrChains, arrAddresses, bForwarded, conn, onSaved){
	conn = conn || db;
	conn.query(
		"SELECT device_address FROM shared_address_signing_paths \n\
		JOIN correspondent_devices USING(device_address) WHERE shared_address IN(?) AND device_address!=?", 
		[arrAddresses, device.getMyDeviceAddress()], 
		function(rows){
			console.log("shared address devices: "+rows.length);
			var arrDeviceAddresses = rows.map(function(row){ return row.device_address; });
			walletGeneral.forwardPrivateChainsToDevices(arrDeviceAddresses, arrChains, bForwarded, conn, onSaved);
		}
	);
}
```

**File:** wallet_defined_by_addresses.js (L545-561)
```javascript
function readAllControlAddresses(conn, arrAddresses, handleLists){
	conn = conn || db;
	conn.query(
		"SELECT DISTINCT address, shared_address_signing_paths.device_address, (correspondent_devices.device_address IS NOT NULL) AS have_correspondent \n\
		FROM shared_address_signing_paths LEFT JOIN correspondent_devices USING(device_address) WHERE shared_address IN(?)", 
		[arrAddresses], 
		function(rows){
			if (rows.length === 0)
				return handleLists([], []);
			var arrControlAddresses = rows.map(function(row){ return row.address; });
			var arrControlDeviceAddresses = rows.filter(function(row){ return row.have_correspondent; }).map(function(row){ return row.device_address; });
			readAllControlAddresses(conn, arrControlAddresses, function(arrControlAddresses2, arrControlDeviceAddresses2){
				handleLists(_.union(arrControlAddresses, arrControlAddresses2), _.union(arrControlDeviceAddresses, arrControlDeviceAddresses2));
			});
		}
	);
}
```
