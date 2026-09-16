### Title
IDOR in shared-address definition sync lets an attacker device hijack private-payment forwarding for a victim's address - ([File: wallet_defined_by_addresses.js])

### Summary
`handleNewSharedAddress()` accepts a peer-supplied `body.signers` map that binds arbitrary `device_address` values to member `address` values of a shared/multisig address definition. The function validates the *definition hash* and that each signer's `address` matches the corresponding leaf in the definition, but it never verifies that the claimed `device_address` is actually the device that controls the referenced member `address`. That unverified `(address, device_address)` pair is persisted verbatim into `shared_address_signing_paths`, and this table is later used as the authoritative routing table for forwarding private-payment chains to "cosigners" of a shared address.

### Finding Description
`handleNewSharedAddress(body, callbacks)` in `wallet_defined_by_addresses.js:377-415`: [1](#0-0) 
validates:
- `body.definition` hashes to `body.address` (c-hash check)
- every `signerInfo.address` in `body.signers` is a valid address string
- every signer's `address` matches the `["address", ...]` leaf at the same path in the definition (`extractAddressPathsFromDefinition`)

It never checks that `signerInfo.device_address` corresponds to a device that actually owns/controls `signerInfo.address`. `determineIfIncludesMeAndRewriteDeviceAddress()` (`wallet_defined_by_addresses.js:281-315`) only rewrites `device_address` for entries whose `address` is found in *my own* `my_addresses`/`shared_addresses` tables; for every other member address (i.e., addresses belonging to other, non-local parties) the attacker-supplied `device_address` is trusted as-is and written into `shared_address_signing_paths` via `addNewSharedAddress()` (`wallet_defined_by_addresses.js:239-268`).

This is the same bug class as the OpenProject IDOR: a caller writes a foreign-resource identifier (there: `project_folder_id` referencing another project's folder; here: `device_address` referencing another party's routing endpoint) into a record it controls (there: its own `Storages::ProjectStorage` row; here: the shared-address definition it is submitting), without validating that the identifier is bound to the correct owner. A background process later trusts that stored reference to perform a privileged action against the wrong principal.

The privileged downstream action here is private-payment forwarding: `forwardPrivateChainsToOtherMembersOfAddresses()` (`wallet_defined_by_addresses.js:531-543`) and `forwardPrivateChainsToOtherMembersOfSharedAddresses()` (`wallet.js:2520-2533`) query `shared_address_signing_paths` purely by `shared_address` to decide which `device_address` values should receive the decrypted private-payment chain (`walletGeneral.forwardPrivateChainsToDevices`, `wallet_general.js:30-40` → `sendPrivatePayments`, `wallet_general.js:19-28`). Neither function re-validates that the stored `device_address` genuinely controls the member `address`; they trust the table populated by `handleNewSharedAddress`.

### Impact Explanation
An attacker who is one signer of a shared/multisig address (or who can get a victim to accept a crafted `new_shared_address` offer where the attacker is one legitimate member and other members are addresses belonging to a different device) can submit `signers` entries claiming an attacker-controlled `device_address` for a co-signer's `address`. Once this poisoned mapping is stored in `shared_address_signing_paths`, any subsequent private payment (private/indivisible asset, e.g. blackbytes) sent to or through that shared address will be forwarded via `forwardPrivateChainsToOtherMembersOfAddresses`/`forwardPrivateChainsToOtherMembersOfSharedAddresses` to the attacker's device instead of (or in addition to) the legitimate co-signer's device, leaking the full decrypted private-payment chain (amounts, blinding factors, addresses) to an unauthorized party. This is a confidentiality breach of private payment data routed through a shared address whose membership the victim did not fully control — a cross-tenant/cross-party unauthorized-access analog of the reported IDOR, though impact here is data disclosure of private payment contents rather than fund loss.

### Likelihood Explanation
Reachable from a single `new_shared_address` / signer-approval message sent by an untrusted paired device (an ordinary wallet peer, no special privilege required), matching the "any AA/unit/device-message poster" reachability bar. The victim's own client only performs c-hash and definition-structural checks; it does not cross-check `device_address` ownership for addresses that are not locally controlled, so the malicious mapping is silently accepted and persisted into the routing table used for future private-payment forwarding.

### Recommendation
When processing `body.signers` in `handleNewSharedAddress`/`approvePendingSharedAddress`, do not trust caller-supplied `device_address` for member addresses that are not locally owned. Either (a) resolve the correct routing device for a given member address only via data that address's own device asserts about itself (e.g., only accept device_address for an address from that address's own signing session, not from a third party's offer), or (b) require independent confirmation/attestation from the addressed device before adding/overwriting entries in `shared_address_signing_paths`, and treat existing rows as authoritative over conflicting new claims from other members.

### Proof of Concept
1. Attacker device A and victim device B, plus a third victim device C, agree (or attacker fabricates) a shared-address definition `["and", [["address","$address@A"], ["address","$address@B"]]]` where the `B` slot is meant to resolve to victim device C's address.
2. Attacker sends `new_shared_address` to device B with `body.signers` where the signing path for `B`'s member address carries `device_address = A` (attacker's own device) instead of `C`.
3. Device B's `handleNewSharedAddress` verifies only the c-hash and that `signerInfo.address` matches the definition leaf — it accepts the mapping and stores `(shared_address, address=C's address, device_address=A)` into `shared_address_signing_paths`.
4. Later, a private (blackbytes) payment is sent to/through the shared address; `forwardPrivateChainsToOtherMembersOfAddresses`/`forwardPrivateChainsToOtherMembersOfSharedAddresses` looks up `shared_address_signing_paths` and forwards the decrypted private-payment chain to device A, leaking C's private payment data to the attacker. [2](#0-1) [3](#0-2) [4](#0-3)

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

**File:** wallet_general.js (L19-40)
```javascript
function sendPrivatePayments(device_address, arrChains, bForwarded, conn, onSaved){
	var body = {chains: arrChains};
	if (bForwarded)
		body.forwarded = true;
	device.sendMessageToDevice(device_address, "private_payments", body, {
		ifOk: function(){},
		ifError: function(){},
		onSaved: onSaved
	}, conn);
}

function forwardPrivateChainsToDevices(arrDeviceAddresses, arrChains, bForwarded, conn, onSaved){
	console.log("devices: "+arrDeviceAddresses);
	async.eachSeries(
		arrDeviceAddresses,
		function(device_address, cb){
			console.log("forwarding to device "+device_address);
			sendPrivatePayments(device_address, arrChains, bForwarded, conn, cb);
		},
		onSaved
	);
}
```
