## Title
Unverified device_address in shared-address signer info allows misdirection of private payment chains - (File: wallet_defined_by_addresses.js)

### Summary
`handleNewSharedAddress()` in `wallet_defined_by_addresses.js` accepts a `signers` map from a peer device message where each entry binds a `signing_path` to a member `address` **and** a `device_address`. The code validates that the claimed member `address` matches the address actually present at that path in the definition (`assocDefinitionAddresses[signing_path] !== signerInfo.address`), but it never verifies that the `device_address` supplied for a *co-signer's* path is the device that actually controls/owns that member address. This is directly analogous to the referenced CVE class: an identifier used for a sensitive communication/notification channel (there: unverified e-mail; here: `device_address`) is accepted and persisted without verifying that it truly belongs to the party it is claimed to represent. [1](#0-0) 

### Finding Description
When a shared (multisig) address is created, participants exchange a `new_shared_address` device message whose body is processed by `handleNewSharedAddress`:

- The definition hash is checked against `body.address`.
- For every signing path, the code checks `signerInfo.address` is a valid address and matches the address embedded in the definition at that path.
- Nothing checks that `signerInfo.device_address` — the device that is supposed to receive private data for that signing path — is genuinely associated with `signerInfo.address`. [2](#0-1) 

The only device-address “ownership” check performed is `determineIfIncludesMeAndRewriteDeviceAddress`, which rewrites the device address **only for addresses that belong to the local node** (`my_addresses`/`shared_addresses`); it does nothing to validate device addresses claimed for *other* members' addresses. [3](#0-2) 

The unverified `(address, device_address)` pairs are then written verbatim into `shared_address_signing_paths` via `addNewSharedAddress`: [4](#0-3) 

This table is later used to decide who receives forwarded private payment chains whenever a private-asset payment involving the shared address occurs: [5](#0-4) 

Because the `device_address` for a co-signer's path is taken at face value from a message sent by any correspondent participating in the shared-address setup, a malicious participant in a multi-party shared address can bind another cosigner's `address` to a `device_address` that they control (their own device, or a device they operate). When a private payment (e.g., indivisible/divisible private asset transfer) later touches that shared address, `forwardPrivateChainsToOtherMembersOfAddresses`/`forwardPrivateChainsToDevices` will forward the confidential private-payment chain to the attacker-controlled device instead of (or in addition to) the legitimate owner’s device.

### Impact Explanation
Private payment chains contain the full chain of previous private-payment units needed to prove ownership/validity of a private (indivisible or divisible) asset unit — this is exactly the information a legitimate recipient needs to later spend the output. If this data is misdirected to an attacker-controlled device:
- The attacker gains knowledge of otherwise-confidential private-asset payment details of another party (fund/plan disclosure, private payment metadata).
- Because the same `shared_address_signing_paths` rows are also used elsewhere for cosigner discovery and forwarding of new-shared-address and pending signature requests, an attacker who controls the recorded `device_address` for a cosigner's path may also be included in cosigning/notification workflows that were not intended for them, which can leak sensitive information or facilitate confusion about who is expected to counter-sign, potentially freezing legitimate spends of the shared address if signature requests are also routed to the wrong device instead of the real cosigner.

This maps to the "private payment chains" and "wallet and contract message handling" categories explicitly in-scope.

### Likelihood Explanation
Likelihood is Medium-High for a targeted attack: any device that is one of the participants agreeing to form a shared (multisig) address can send a crafted `new_shared_address` message (or, if acting as the initiator, directly construct `assocSignersByPath`) that assigns another cosigner's legitimate `address` to the attacker's own `device_address`. No signature, proof-of-control, or additional out-of-band verification of the `device_address` binding is required — the check only enforces that the `address` field matches the definition, not that `device_address` is authorized for that address. This is reachable purely through the normal “paired device” shared-address setup flow described in scope.

### Recommendation
- Require that any `device_address` supplied for a signing path corresponding to a *foreign* member address be corroborated independently (e.g., only trust the `device_address` supplied by the correspondent that itself owns that address, or require the owning device to confirm/attest its own `device_address` binding directly, rather than accepting it second-hand from another participant).
- Alternatively, when forwarding private chains or signature requests, only send to a `device_address` that the recipient's own device previously and directly asserted as belonging to that address, and treat third-party-asserted device/address bindings as unauthenticated hints requiring explicit confirmation.
- Add an audit/verification step in `handleNewSharedAddress`/`addNewSharedAddress` analogous to the missing "verify before trusting" step that CVE-2020-13276 required for notification emails.

### Proof of Concept
1. Attacker device `D_A` and victim device `D_V` (and possibly others) agree to build a shared/multisig address with member addresses `A_attacker` (owned by `D_A`) and `A_victim` (owned by `D_V`).
2. As part of the `new_shared_address` exchange, `D_A` sends (or, if it is the coordinating initiator, composes) a `signers` map where the entry for `A_victim`'s signing path sets `device_address = D_A` (attacker's own device) instead of `D_V`.
3. `handleNewSharedAddress` validates only that `A_victim` matches the definition at that path; it accepts the attacker-supplied `device_address` unchanged and stores it in `shared_address_signing_paths` via `addNewSharedAddress`.
4. Later, someone sends a private-asset payment involving the shared address. `forwardPrivateChainsToOtherMembersOfAddresses` queries `shared_address_signing_paths JOIN correspondent_devices` and forwards the private payment chain to `D_A` (attacker) believing it is forwarding to the device controlling `A_victim`.
5. The attacker's device `D_A` now possesses the private payment chain intended for the victim's cosigner device, without ever having proven control of `A_victim`.

Uncertainty: I could not fully trace, within the remaining time, how `wallet.js`'s device-message dispatcher validates the sender before calling `handleNewSharedAddress`, nor every downstream consumer of `shared_address_signing_paths.device_address` (e.g., signature-request routing in `wallet_defined_by_addresses.js`/`wallet.js`), so the exact set of all workflows affected by this unverified binding (beyond private-chain forwarding) is not fully enumerated here.

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
