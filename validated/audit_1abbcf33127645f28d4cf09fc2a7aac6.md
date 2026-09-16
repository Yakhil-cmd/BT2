### Title
Forged `new_shared_address` device message lets any paired correspondent register itself as an unverified cosigner on a victim's addresses - (File: `wallet_defined_by_addresses.js`)

### Summary
The device-message handler for `new_shared_address` accepts a shared-address definition and a `signers` map from any paired correspondent device and persists them into the `shared_addresses` / `shared_address_signing_paths` tables without ever verifying that the sending device is authorized to speak for the `device_address` values it claims for the various signing paths. This mirrors the phpMyFAQ bug class: the code checks that the caller is a known, authenticated party (a paired correspondent, per `device.js`), but never checks that the caller is *authorized* to perform this specific privileged action (asserting cosigner/device bindings for a multisig address that includes the victim's own address).

### Finding Description
`handleNewSharedAddress` is invoked directly from the `new_shared_address` case in the device-message dispatcher, with no `from_address` argument at all: [1](#0-0) 

The handler itself only performs *content-consistency* checks — that the definition hashes to the claimed address, that signer addresses are valid, and that every `["address", ...]` leaf in the definition has a matching entry in `body.signers` — but it never checks that the message sender (`from_address`) corresponds to any of the `device_address` values asserted in `body.signers`: [2](#0-1) 

The only "authorization" performed is `determineIfIncludesMeAndRewriteDeviceAddress`, which merely checks whether *any* address in the definition happens to already exist in the local `my_addresses`/`shared_addresses` tables (i.e., that the victim owns one of the mentioned addresses) — it does not check who sent the message or verify any prior offer/approval handshake for this specific shared address: [3](#0-2) 

Because Obyte payment addresses are public (visible in any prior on-DAG payment), an attacker only needs to observe one of the victim's addresses to satisfy this check. The attacker can then fabricate a definition (e.g., `["and"/"or", [["address", VICTIM_ADDR], ["address", ATTACKER_ADDR]]]`), compute its `chash160`, and set arbitrary `device_address` values for every signing path except the victim's own address — none of which are validated against `from_address` or against any legitimate offer/approval exchange (`create_new_shared_address` / `approve_new_shared_address`). `addNewSharedAddress` then blindly inserts these rows: [4](#0-3) 

The precondition for reaching this handler is only that the attacker be a "correspondent" device — i.e., merely paired, which is not in the whitelist for non-correspondents (`pairing`, `my_xpubkey`, `wallet_fully_approved`), but pairing itself is a low-privilege, self-service action (`handlePairingMessage` accepts any device presenting a valid pairing secret), so this is reachable from an unprivileged "paired device" attacker as covered by the reachable-analog list.

### Impact Explanation
A forged shared address that silently binds the victim's real address into an attacker-controlled multisig/"OR" definition can be leveraged to corrupt the victim node's view of which addresses it jointly controls and with whom. Downstream flows (`readSharedAddressDefinition`, `forwardNewSharedAddressToCosignersOfMyMemberAddresses`, cosigning/dispatch logic in `wallet.js`'s `sign` case and `arbiter_contract.js`) trust the `shared_addresses`/`shared_address_signing_paths` tables as the record of legitimate cosigning relationships. An attacker who successfully injects a bogus shared-address record can misdirect private-payment forwarding, misrepresent cosigner relationships to the user's UI, or attempt to solicit victim cosignatures for transactions the victim believes were negotiated through a real shared-address offer/approval flow — undermining the integrity of the multisig trust model without any real negotiation ever having taken place.

### Likelihood Explanation
Medium: the attacker needs only to be a paired correspondent (a low-privilege, self-initiated relationship) and to know one on-DAG address belonging to the victim, both of which are easy to obtain. No signature, offer, or approval step is required to make the handler accept and persist the forged shared-address record.

### Recommendation
In `handleNewSharedAddress`, require and verify `from_address` against the `signers` map: reject the message unless `from_address` matches the `device_address` claimed for at least one signing path that is *not* the local device, and cross-check that the shared address was actually the subject of a prior `create_new_shared_address`/`approve_new_shared_address` handshake (via `pending_shared_addresses` / `pending_shared_address_signing_paths`) rather than accepting an unsolicited, fully-formed shared address from any correspondent.

### Proof of Concept
1. Attacker pairs with victim's device (self-service, no special privilege).
2. Attacker observes any on-DAG unit authored by the victim to learn `VICTIM_ADDR`.
3. Attacker builds `arrDefinition = ["and", [["address","VICTIM_ADDR"],["address","ATTACKER_ADDR"]]]`, computes `address = chash160(arrDefinition)`.
4. Attacker sends device message:
```
{
  subject: "new_shared_address",
  body: {
    address: "<computed address>",
    definition: arrDefinition,
    signers: {
      "r.0": { address: "VICTIM_ADDR", member_signing_path: "r" },
      "r.1": { address: "ATTACKER_ADDR", member_signing_path: "r", device_address: "ATTACKER_DEVICE_ADDR" }
    }
  }
}
```
5. Victim's `handleNewSharedAddress` accepts and persists the record because `VICTIM_ADDR` is found in `my_addresses`, with no check that the attacker (the actual sender) was ever authorized to establish this shared address on the victim's behalf.

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

**File:** wallet_defined_by_addresses.js (L378-415)
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
}
```
