### Title
Malicious paired device can register itself as a cosigner of a victim's shared address, causing private payment chains to be forwarded to it - ([File: wallet_defined_by_addresses.js])

### Summary
The `"new_shared_address"` device-message handler trusts the sender-supplied `signers` map to register `shared_address_signing_paths` entries locally, without verifying that the sending device is actually authorized to claim a signing role in that shared address. This mirrors the TypeBot flaw: an authenticated principal (a paired correspondent device, analogous to TypeBot's authenticated OAuth-callback user) supplies self-describing state (`address`, `definition`, `signers`) that is internally consistent (definition hashes to the address, signer addresses match paths in the definition) but is never checked against the *sender's* actual right to be inserted as `device_address` for those signing paths.

### Finding Description
`wallet.js` dispatches the `"new_shared_address"` subject straight to `walletDefinedByAddresses.handleNewSharedAddress(body, callbacks)` without passing `from_address` at all: [1](#0-0) 

`handleNewSharedAddress` only validates internal self-consistency of the attacker-supplied body — that `body.address` hashes from `body.definition`, that `signerInfo.address` values are syntactically valid addresses, and that they match the paths extracted from the definition — then calls `determineIfIncludesMeAndRewriteDeviceAddress` and finally persists the entry via `addNewSharedAddress`: [2](#0-1) 

`determineIfIncludesMeAndRewriteDeviceAddress` only checks that *some* member address in the payload is one of the receiver's own `my_addresses`/`shared_addresses` — i.e., that the victim really owns one address referenced in the definition. It never checks that the `from_address` (sender device) corresponds to the `device_address` fields the sender is asserting for the *other* signing paths: [3](#0-2) 

`addNewSharedAddress` then blindly inserts every `signing_path -> device_address` mapping from `assocSignersByPath` (fully attacker-controlled for non-owned paths) into `shared_address_signing_paths`: [4](#0-3) 

This table is later used, without any additional authorization check, to decide which devices are legitimate cosigners entitled to receive forwarded private payment data for that address: [5](#0-4) [6](#0-5) [7](#0-6) 

Contrast this with the legitimate multi-party approval flow (`createNewSharedAddressByTemplate` / `approvePendingSharedAddress`), where the shared address is only finalized after collecting cryptographically-tied approvals from every device referenced by the pre-agreed `arrAddressDefinitionTemplate`, and `validateAddressDefinitionTemplate` explicitly checks `arrDeviceAddresses.indexOf(from_address) === -1` to make sure the sender is one of the actual template members: [8](#0-7) 
No equivalent verification exists in the direct `"new_shared_address"` inbound path used by `createNewSharedAddress`/`handleNewSharedAddress`, which is exactly the code path reachable unauthenticated-with-respect-to-authorization by any paired device.

### Impact Explanation
A malicious paired device (correspondent) can craft a `"new_shared_address"` message containing:
- a `definition` referencing one address genuinely owned by the victim (so `determineIfIncludesMeAndRewriteDeviceAddress` accepts it), combined with
- other signing paths whose `device_address` is the attacker's own device address.

The victim's wallet will persist a `shared_addresses`/`shared_address_signing_paths` record it never agreed to. From that point, any future private payment (indivisible or divisible asset) sent to or spent from that address will be forwarded via `forwardPrivateChainsToOtherMembersOfAddresses` / `forwardPrivateChainsToOtherMembersOfSharedAddresses` to the attacker's device, because the code trusts the `device_address` column populated purely from the untrusted message. This discloses private-payment details (amounts, addresses, blinding factors) — confidentiality loss of a private payment chain — to a party with no real cryptographic right to it. It can also pollute the victim's signing-request routing table, causing `findAddress`/`sign` flows to treat the attacker's device as a legitimate cosigner for future multisig operations tied to that "shared" address.

### Likelihood Explanation
Any device that has ever been paired with the victim (a normal wallet-to-wallet correspondent relationship, no special privilege) can send this message; `handleMessageFromHub` for the `"new_shared_address"` subject requires only that sender be a paired correspondent, and the checks performed (definition c-hash consistency, address-format validity) are trivially satisfiable by an attacker who knows one real address of the victim (learned from any prior interaction, e.g. receiving a payment). No additional user confirmation dialog gates this particular path (unlike the offer/approval-based `create_new_shared_address` flow), making exploitation straightforward for any already-paired malicious counterparty.

### Recommendation
In `handleNewSharedAddress` (or in the `"new_shared_address"` case of `wallet.js`), require that the sender's `from_address` be present as one of the `device_address` values inside `body.signers` for a signing path whose member `address` is *not* one of the receiver's own addresses — i.e., verify the message is only accepted from a device that legitimately owns (or is asserting itself for) a role in the shared address, similar to the `arrDeviceAddresses.indexOf(from_address) === -1` check already used in `validateAddressDefinitionTemplate`. At minimum, do not let an untrusted third party dictate `device_address` values for signing paths that are not their own; only trust the mapping for the path(s) the sender is entitled to claim, and require independent confirmation/approval before adding new `device_address` entries to `shared_address_signing_paths` that affect private-payment forwarding for addresses the local wallet already controls.

### Proof of Concept
1. Attacker device A pairs normally with victim device V (standard pairing flow).
2. Attacker learns one of V's real payment addresses `addrV` (e.g., from any past payment).
3. Attacker crafts `arrDefinition = ["and", [["address", addrV], ["address", A_placeholder]]]` such that `objectHash.getChash160(arrDefinition) = shared_address`, and builds `signers = { "r.0": {address: addrV}, "r.1": {address: attacker_address, device_address: A} }` matching `extractAddressPathsFromDefinition`.
4. Attacker sends device message `{subject: "new_shared_address", body: {address: shared_address, definition: arrDefinition, signers: signers}}` to V.
5. `handleNewSharedAddress` passes all self-consistency checks; `determineIfIncludesMeAndRewriteDeviceAddress` succeeds because `addrV` is one of V's own addresses; `addNewSharedAddress` inserts a `shared_address_signing_paths` row mapping `r.1 -> attacker_address, device_address=A`.
6. Any future private payment involving `shared_address` triggers `forwardPrivateChainsToOtherMembersOfAddresses`, which queries `shared_address_signing_paths` and sends the private payment chain (via `walletGeneral.forwardPrivateChainsToDevices`) to device A — leaking private payment data to the attacker without V's consent.

Note: I was not able to trace every downstream UI-level confirmation dialog that might exist purely on the client side (outside this repo), so if a wallet UI independently gates persistence of `shared_addresses` behind explicit user approval, actual exploitability would depend on that missing layer; this could not be verified from the indexed backend code alone.

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

**File:** wallet.js (L1082-1116)
```javascript
function forwardPrivateChainsToOtherMembersOfOutputAddresses(arrChains, bForwarded, conn, onSaved){
	console.log("forwardPrivateChainsToOtherMembersOfOutputAddresses", arrChains);
	var assocOutputAddresses = {};
	arrChains.forEach(function(arrPrivateElements){
		var objHeadPrivateElement = arrPrivateElements[0];
		var payload = objHeadPrivateElement.payload;
		payload.outputs.forEach(function(output){
			if (output.address)
				assocOutputAddresses[output.address] = true;
		});
		if (objHeadPrivateElement.output && objHeadPrivateElement.output.address)
			assocOutputAddresses[objHeadPrivateElement.output.address] = true;
	});
	var arrOutputAddresses = Object.keys(assocOutputAddresses);
	console.log("output addresses", arrOutputAddresses);
	conn = conn || db;
	if (!onSaved)
		onSaved = function(){};
	readWalletsByAddresses(conn, arrOutputAddresses, function(arrWallets){
		if (arrWallets.length === 0){
		//	breadcrumbs.add("forwardPrivateChainsToOtherMembersOfOutputAddresses: " + JSON.stringify(arrChains)); // remove in livenet
		//	eventBus.emit('nonfatal_error', "not my wallet? output addresses: "+arrOutputAddresses.join(', '), new Error());
		//	throw Error("not my wallet? output addresses: "+arrOutputAddresses.join(', '));
		}
		var arrFuncs = [];
		if (arrWallets.length > 0)
			arrFuncs.push(function(cb){
				walletDefinedByKeys.forwardPrivateChainsToOtherMembersOfWallets(arrChains, arrWallets, bForwarded, conn, cb);
			});
		arrFuncs.push(function(cb){
			walletDefinedByAddresses.forwardPrivateChainsToOtherMembersOfAddresses(arrChains, arrOutputAddresses, bForwarded, conn, cb);
		});
		async.series(arrFuncs, onSaved);
	});
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
