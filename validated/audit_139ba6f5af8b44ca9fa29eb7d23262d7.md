### Title
Missing authorization check when accepting `new_shared_address` device messages allows spoofing shared/multisig address membership - (File: wallet_defined_by_addresses.js)

### Summary
The device-message handler for the `new_shared_address` subject inserts a fully-formed shared (multisig) address definition into the recipient's wallet database without ever verifying that the sender of the message (`from_address`) is actually one of the cosigners named in that definition. This mirrors the Nextcloud Deck flaw, where the server accepted a foreign-key parameter (`stackId`) supplied by the client without checking it belonged to the acting user; here the analogous "foreign key" is the `device_address` associated with each signing path of a shared address, which is taken verbatim from the message body and stored as authoritative cosigner information.

### Finding Description
`wallet.js` routes the `new_shared_address` message straight into `walletDefinedByAddresses.handleNewSharedAddress(body, ...)` with no ownership check on the sender: [1](#0-0) 

`handleNewSharedAddress` validates only *structural* properties of the message: that the definition hashes to `body.address`, that member addresses referenced in the definition are syntactically valid addresses, that each `signers[path].address` matches the address extracted from the same path in the definition, and — via `determineIfIncludesMeAndRewriteDeviceAddress` — that at least one of the referenced member addresses is owned by the recipient (or is a shared address the recipient already belongs to): [2](#0-1) 

Nowhere in this path is `from_address` (the actual device that sent the message, verified by `device.js`'s signature/hash checks) cross-checked against `body.signers` to confirm the sender is legitimately one of the parties to the shared address. Compare this with sibling handlers in the same file/module that *do* perform this check, e.g. `validateAddressDefinitionTemplate` explicitly requires `arrDeviceAddresses.indexOf(from_address) !== -1`: [3](#0-2) 

and `prosaic_contract_shared` in `wallet.js` explicitly joins `my_addresses`/`wallet_signing_paths` on the sender's `from_address` before accepting contract data: [4](#0-3) 

No equivalent check exists for `new_shared_address`. Once accepted, `addNewSharedAddress` blindly writes every entry of `body.signers` — including attacker-chosen `device_address` values for other signing paths — into `shared_addresses` and `shared_address_signing_paths`: [5](#0-4) 

Because `determineIfIncludesMeAndRewriteDeviceAddress` only requires that *one* member address in the definition be locally owned (my own address, or a shared address I already participate in), any paired correspondent who knows one of the victim's payment addresses can fabricate an `and`/`or` definition that combines that address with an address the attacker chose, then claim (via `body.signers`) that some other, unrelated `device_address` is the cosigner for that path. The recipient's wallet will silently record this as a legitimate shared/multisig address and cosigner list, exactly as the Deck bug silently pollutes another user's stack via an unchecked `stackId`.

### Impact Explanation
This lets a single unprivileged paired device (a correspondent who does not need to be a real party to the address, only needs to know one of the victim's public addresses) inject a spoofed shared/multisig address and cosigner set into the victim's wallet. The victim's UI, `readSharedAddressCosigners`, and future payment/signing flows treat this poisoned data as ground truth, deceiving the user about which device(s)/keys are supposed to co-sign a payment address. If the victim is later convinced to send funds to the shared address (believing it requires legitimate cosigners), while the attacker actually controls all necessary signing paths (by naming attacker-controlled device addresses for every other path in the definition, satisfying the "and"/"r of set" definition's threshold), the attacker can unilaterally spend those funds — i.e., unauthorized spending/fund theft, which meets the required impact bar (concrete unauthorized spending) for this scan.

### Likelihood Explanation
Likelihood is moderate to high: the attacker only needs to be an existing correspondent (paired device) of the victim — a normal, low-privilege relationship established e.g. by exchanging a pairing code for chat/payment purposes — and to know at least one of the victim's real payment addresses (routinely shared during any transaction). No cryptographic secret of the victim's needs to be broken; the message passes all signature/hash checks in `device.js` because it is legitimately signed by the attacker's own device key. The missing check is a simple omission, not a cryptographic weakness, making exploitation straightforward once the precondition (attacker knows one victim address) is met.

### Recommendation
In `handleNewSharedAddress` (or in the `new_shared_address` case in `wallet.js`), require that `from_address` be included among the `device_address` values referenced by `body.signers`/the definition before accepting and persisting the shared address, mirroring the checks already performed in `validateAddressDefinitionTemplate` and the `prosaic_contract_shared` handler. Additionally, consider requiring explicit user confirmation before writing an unsolicited shared address definition (as is done for `create_new_shared_address`/`approve_new_shared_address` flows), rather than auto-accepting a fully-formed `new_shared_address` from any correspondent.

### Proof of Concept
1. Attacker device `D_a` pairs with victim device `D_v` as an ordinary correspondent (e.g., via a shared pairing code used for chat/payments) and learns one of the victim's real payment addresses `A_v` from a prior interaction.
2. Attacker crafts a shared-address definition `["and", [["address", "A_v"], ["address", "A_x"]]]` where `A_x` is an address `D_a` controls, computes `shared_address = chash160(definition)`, and picks `body.signers` such that the signing path for `A_v` maps to `device_address: D_v` (satisfying `determineIfIncludesMeAndRewriteDeviceAddress`) while the signing path for `A_x` maps to `device_address: D_other` — an arbitrary device address the attacker names (e.g., a known, trusted correspondent of the victim) instead of `D_a`.
3. `D_a` sends this as a `new_shared_address` device message to `D_v`.
4. `handleMessageFromHub` → `handleNewSharedAddress` in `wallet_defined_by_addresses.js` accepts it: definition hash matches, `signers` addresses match the definition paths, and `D_v`'s own address `A_v` is found among the member addresses — all checks pass despite `from_address` (`D_a`) never appearing anywhere in `body.signers`.
5. `addNewSharedAddress` writes `shared_addresses` and `shared_address_signing_paths` rows claiming `D_other` (not the real attacker `D_a`) co-controls the new shared address alongside the victim, poisoning the victim's wallet state with a spoofed multisig relationship that can later be leveraged to misdirect payments.

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

**File:** wallet.js (L483-501)
```javascript
			case 'prosaic_contract_shared':
				if (!body.title || !body.text || !body.creation_date)
					return callbacks.ifError("not all contract fields submitted");
				if (!ValidationUtils.isValidAddress(body.peer_address) || !ValidationUtils.isValidAddress(body.my_address))
					return callbacks.ifError("either peer_address or address is not valid in contract");
				if (body.hash !== prosaic_contract.getHash(body))
					return callbacks.ifError("wrong contract hash");
				if (!/^\d{4}\-\d{2}\-\d{2} \d{2}:\d{2}:\d{2}$/.test(body.creation_date))
					return callbacks.ifError("wrong contract creation date");
				db.query("SELECT 1 FROM my_addresses \n\
						JOIN wallet_signing_paths USING(wallet)\n\
						WHERE my_addresses.address=? AND wallet_signing_paths.device_address=?",[body.my_address, from_address],
					function(rows) {
						if (!rows.length)
							return callbacks.ifError("contract does not contain my address shared with your device");
						prosaic_contract.store(body);
						callbacks.ifOk();
					}
				);
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

**File:** wallet_defined_by_addresses.js (L491-494)
```javascript
	if (arrDeviceAddresses.indexOf(device.getMyDeviceAddress()) === - 1)
		return handleResult("my device address not mentioned in the definition");
	if (arrDeviceAddresses.indexOf(from_address) === - 1)
		return handleResult("sender device address not mentioned in the definition");
```
