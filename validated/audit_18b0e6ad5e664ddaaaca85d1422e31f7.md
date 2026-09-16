### Title
Unauthenticated device-address claims in shared address protocol allow unauthorized parties to receive private payment data - ([File: wallet_defined_by_addresses.js])

### Summary
`handleNewSharedAddress()` in `wallet_defined_by_addresses.js` accepts a `signers` map from any already-paired correspondent device and stores the claimed `device_address` for every signing path of a shared address into `shared_address_signing_paths`, without verifying that the claimed device actually controls or is entitled to that signing path/address. This data is later used, unconditionally, to decide who receives forwarded private payment chains (addresses, amounts, blinding factors), so an attacker-controlled or falsely-named device can be granted visibility into private transaction data of a shared address it should have no legitimate claim to.

### Finding Description
When a device receives a `new_shared_address` message, `handleNewSharedAddress` performs only structural checks:
- that `body.definition` hashes to `body.address` [1](#0-0) 
- that each `signerInfo.address` in `body.signers` is a syntactically valid address [2](#0-1) 
- that the address named at each signing path matches the address referenced at that path in the definition [3](#0-2) 

It then calls `determineIfIncludesMeAndRewriteDeviceAddress`, which only verifies/rewrites the `device_address` for paths where the address is *my own* address; for every other signing path, the attacker-supplied `device_address` is trusted verbatim [4](#0-3) .

`addNewSharedAddress` then persists all of `assocSignersByPath` (i.e., `body.signers`) into `shared_address_signing_paths`, including the unauthenticated `device_address` values for non-local members: [5](#0-4) 

This table is later trusted as the authoritative list of "who is allowed to see private payment data for this address." Both `forwardPrivateChainsToOtherMembersOfAddresses` [6](#0-5)  and the recursive `readAllControlAddresses` used from `forwardPrivateChainsToOtherMembersOfSharedAddresses` [7](#0-6)  query `shared_address_signing_paths` and forward the full private payment chain (recipient/cosigner addresses, amounts, blinding factors) to every listed `device_address`, without any additional authorization or proof that the recipient device genuinely controls the corresponding signing key.

Because the `device_address` field is attacker-controlled data accepted from a normal correspondent-level message (not signed proof of key ownership), a malicious but already-paired device can name itself (or a third, uninvolved correspondent) as the controller of a signing path in a shared-address definition that a victim will later validate as containing one of the victim's genuine addresses. The victim's own address membership check only requires that *some* leaf of the definition matches one of the victim's own addresses/shared addresses; it does not validate the legitimacy of the `device_address` claims made for the other leaves.

### Impact Explanation
This is an access-control failure (CWE-284) analogous to the Oro advisory: a party who should have no rights to view certain private information is nonetheless granted visibility because the system fails to verify the identity/authorization claim before disclosing sensitive data. Here, the disclosed data is private on-chain payment information (recipient addresses, transferred amounts, and blinding factors used to correlate outputs) that the Obyte private-payment model is specifically designed to keep from non-parties. Any private payment later sent to the compromised shared address is forwarded to the attacker's device automatically as soon as the victim processes the chain, resulting in unauthorized disclosure of confidential transaction details (medium severity, no funds theft, but a clear confidentiality/ACL violation matching the CWE-284 classification of the referenced advisory).

### Likelihood Explanation
The attack requires only that the attacker's device already be a paired correspondent of the victim (a normal, low-privilege state many wallets reach through routine pairing) and that the victim accept a proposed shared address (a standard multisig/arbiter-contract workflow) whose definition happens to include one of the victim's genuine addresses alongside an attacker-fabricated leaf/device-address pairing. No signature over the `device_address` claim is required, making the manipulation straightforward for any correspondent willing to craft such a definition.

### Recommendation
When processing `new_shared_address` / `handleNewSharedAddress`, do not blindly trust the `device_address` supplied by the remote sender for signing paths that are not the local device. Only forward private payment data to a `device_address` after independently verifying (e.g., via the address' own correspondents/pairing records, or via out-of-band confirmation) that the device genuinely controls the signing key for the associated address/path, rather than persisting and trusting attacker-supplied `device_address` associations directly into `shared_address_signing_paths`.

### Proof of Concept
1. Attacker device pairs normally with Victim device (ordinary correspondent).
2. Attacker crafts a shared-address definition combining one of Victim's real addresses (`victim_addr`) with an attacker-chosen path/address, e.g. `["and", [["address", "victim_addr"], ["address", "some_addr"]]]`, and sends `new_shared_address` with `signers` mapping the `victim_addr` path correctly, but mapping the other path's `device_address` to a third, uninvolved correspondent device (or itself).
3. Victim's `handleNewSharedAddress` passes structural checks, recognizes `victim_addr` as its own, and stores the shared address plus the attacker-declared `device_address` for the other leaf into `shared_address_signing_paths` (wallet_defined_by_addresses.js:239-268).
4. When Victim later sends/receives a private payment involving this shared address, `forwardPrivateChainsToOtherMembersOfSharedAddresses`/`forwardPrivateChainsToOtherMembersOfAddresses` looks up all `device_address` entries for the shared address and forwards the full private payment chain — including amounts and addresses — to the attacker-named device, which never legitimately controlled any signing key for the address.

### Citations

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

**File:** wallet_defined_by_addresses.js (L383-390)
```javascript
	try {
		var addr = objectHash.getChash160(body.definition);
	}
	catch (e) {
		return callbacks.ifError("invalid definition: " + e);
	}
	if (body.address !== addr)
		return callbacks.ifError("definition doesn't match its c-hash");
```

**File:** wallet_defined_by_addresses.js (L391-395)
```javascript
	for (var signing_path in body.signers){
		var signerInfo = body.signers[signing_path];
		if (signerInfo.address && signerInfo.address !== 'secret' && !ValidationUtils.isValidAddress(signerInfo.address))
			return callbacks.ifError("invalid member address: " + JSON.stringify(signerInfo.address));
	}
```

**File:** wallet_defined_by_addresses.js (L396-405)
```javascript
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

**File:** wallet.js (L2520-2533)
```javascript
function forwardPrivateChainsToOtherMembersOfSharedAddresses(arrChainsOfCosignerPrivateElements, arrPayingAddresses, excluded_device_address, bForwarded, conn, onDone){
	walletDefinedByAddresses.readAllControlAddresses(conn, arrPayingAddresses, function(arrControlAddresses, arrControlDeviceAddresses){
		arrControlDeviceAddresses = arrControlDeviceAddresses.filter(function(device_address) {
			return (device_address !== device.getMyDeviceAddress() && device_address !== excluded_device_address);
		});
		walletDefinedByKeys.readDeviceAddressesControllingPaymentAddresses(conn, arrControlAddresses, function(arrMultisigDeviceAddresses){
			arrMultisigDeviceAddresses = _.difference(arrMultisigDeviceAddresses, arrControlDeviceAddresses);
			// counterparties on shared addresses must forward further, that's why bForwarded=false
			walletGeneral.forwardPrivateChainsToDevices(arrControlDeviceAddresses, arrChainsOfCosignerPrivateElements, bForwarded, conn, function(){
				walletGeneral.forwardPrivateChainsToDevices(arrMultisigDeviceAddresses, arrChainsOfCosignerPrivateElements, true, conn, onDone);
			});
		});
	});
}
```
