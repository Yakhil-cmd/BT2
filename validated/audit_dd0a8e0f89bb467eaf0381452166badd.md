## Title
Missing Authorization on `new_shared_address` Network Message Allows Attacker to Register as a Fraudulent Cosigner of a Victim's Address, Leaking Private Payment Data - (File: wallet_defined_by_addresses.js)

### Summary
`handleNewSharedAddress` (invoked from the `"new_shared_address"` case in `wallet.js`) accepts an unsolicited, attacker-supplied shared-address `definition` and `signers` map from any paired correspondent device and inserts it into `shared_addresses` / `shared_address_signing_paths` as long as (a) the definition hashes to the claimed address and (b) at least one address in the definition happens to already belong to the victim (`my_addresses`) or be a known `shared_addresses` entry. There is no check that the sending device (`from_address`) is actually one of the intended, mutually-agreed cosigners of that address, nor any cryptographic proof that the other claimed signers agreed to this composition.

### Finding Description
The message handler in `wallet.js` for the `"new_shared_address"` subject passes the raw peer-supplied body straight to `walletDefinedByAddresses.handleNewSharedAddress`: [1](#0-0) 

`handleNewSharedAddress` performs only structural checks: that `definition` hashes to `address`, that referenced member addresses are syntactically valid, and that every `["address", ...]` leaf in the definition has a matching entry in `body.signers`: [2](#0-1) 

It never verifies that `from_address` (the actual sender of the message) is one of the addresses/devices named in the definition, nor that the *other* named cosigner devices actually proposed or consented to this address composition (there is no signature-request/approval round-trip enforced on receipt — that flow, `approvePendingSharedAddress`/`pending_shared_addresses`, is explicitly marked "unused" and bypassed by direct `new_shared_address` messages).

The only "authorization" gate is `determineIfIncludesMeAndRewriteDeviceAddress`, which merely checks that *some* address in the attacker-crafted definition is already one of the victim's own addresses (`my_addresses`) or an already-known shared address: [3](#0-2) 

Because the victim's real address is a legitimate leaf (e.g. `["and", [["address","VICTIM_ADDR"], ["address","ATTACKER_ADDR"]]]`), this check passes trivially — it does not establish that the victim agreed to share anything with the attacker; it only confirms the victim owns *one* of the addresses baked into the attacker's crafted definition.

`addNewSharedAddress` then unconditionally writes rows into `shared_address_signing_paths` for every signing path in the attacker-supplied `assocSignersByPath`, including the attacker's own device address as a registered cosigner of the new "shared address": [4](#0-3) 

Once this fraudulent shared-address record exists, `shared_address_signing_paths` (which is the sole authority the wallet uses to decide who is a legitimate cosigner) treats the attacker's device as a peer for that address. This table subsequently drives:
- `readSharedAddressCosigners`, used to decide who receives private-payment forwarding, and
- `forwardPrivateChainsToOtherMembersOfAddresses`, which forwards private payment chain data (spend proofs, amounts, blinding factors, addresses) to every device address found in `shared_address_signing_paths` for the affected address: [5](#0-4) [6](#0-5) 

Because there is no proof that the attacker was ever actually a party to a jointly-defined address, an attacker who is merely a paired correspondent of the victim can unilaterally cause their own device address to be inserted into `shared_address_signing_paths` for an address the victim controls, causing subsequent private-payment traffic involving that address to be forwarded to the attacker.

### Impact Explanation
This is a missing-authorization vulnerability analogous to the Bitwarden `POST /providers/{providerId}/clients/existing` bug: an unprivileged remote party can, without ever having been legitimately included in a definition-approval handshake, cause the victim node to record them as an authorized cosigner/member of an existing address. In ocore terms this results in unauthorized disclosure of confidential private-payment data (spend proofs, amounts, blinding factors) that is normally supposed to be restricted to actual jointly-controlling cosigners. It does not directly authorize spending (spending still requires the real private key/signature over the definition's `sig`/`hash` leaves), but it breaks the confidentiality guarantee of the private-asset system by granting an unauthorized device visibility into private payment chains touching the victim's address — the private-payment confidentiality model is explicitly in scope per the rules ("private payment chains").

### Likelihood Explanation
The `"new_shared_address"` message is accepted from any device that is already paired/correspondent with the victim (no special privilege required beyond being a paired chat correspondent, which is a low bar in ocore's wallet/chat model). The attacker only needs to know one of the victim's real addresses (addresses are not secret — they are routinely shared to receive payments) to craft a definition embedding it. No cryptographic proof of the victim's consent to the specific multi-party definition is required by the receiving code before it commits the shared-address record.

### Recommendation
- Require that a `new_shared_address` message only be processed if it corresponds to a `pending_shared_addresses`/`pending_shared_address_signing_paths` entry that the local device itself initiated or explicitly approved (i.e., enforce the currently-unused `create_new_shared_address` → `approve_new_shared_address` handshake instead of accepting unsolicited `new_shared_address` messages as authoritative).
- Additionally verify that `from_address` in `handleNewSharedAddress` is itself one of the addresses/devices referenced in `body.signers`, and require a matching prior local approval record before persisting `shared_address_signing_paths` rows, so that an address cannot become "shared" with a party the victim never explicitly approved.

### Proof of Concept
1. Attacker pairs with victim's device as a normal correspondent.
2. Attacker learns victim's existing address `VICTIM_ADDR` (e.g., an address the victim publishes for payments).
3. Attacker crafts `arrDefinition = ["and", [["address","VICTIM_ADDR"], ["address","ATTACKER_ADDR"]]]`, computes `address = chash160(arrDefinition)`, and builds `signers = { "r.0": {address: "VICTIM_ADDR", device_address: <victim_device_placeholder>}, "r.1": {address:"ATTACKER_ADDR", device_address: <attacker_device_address>} }`.
4. Attacker sends `{subject: "new_shared_address", body: {address, definition: arrDefinition, signers}}` to the victim's device.
5. `handleNewSharedAddress` passes all structural checks (hash matches, signer addresses match definition leaves), `determineIfIncludesMeAndRewriteDeviceAddress` succeeds because `VICTIM_ADDR` is in `my_addresses`, and `addNewSharedAddress` inserts `shared_address_signing_paths` rows including the attacker's device address as cosigner of the new shared address, without any prior local approval or proof of consent.
6. Any future private payment chain touching this shared address (or the victim's own address as recognized member) is now forwarded to the attacker's device via `forwardPrivateChainsToOtherMembersOfAddresses`, leaking private payment details to an unauthorized party.

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

**File:** wallet_defined_by_addresses.js (L591-606)
```javascript
// returns information about cosigner devices
function readSharedAddressCosigners(shared_address, handleCosigners){
	db.query(
		"SELECT DISTINCT shared_address_signing_paths.device_address, name, "+db.getUnixTimestamp("shared_addresses.creation_date")+" AS creation_ts \n\
		FROM shared_address_signing_paths \n\
		JOIN shared_addresses USING(shared_address) \n\
		LEFT JOIN correspondent_devices USING(device_address) \n\
		WHERE shared_address=? AND device_address!=?",
		[shared_address, device.getMyDeviceAddress()],
		function(rows){
			if (rows.length === 0)
				throw Error("no cosigners found for shared address "+shared_address);
			handleCosigners(rows);
		}
	);
}
```
