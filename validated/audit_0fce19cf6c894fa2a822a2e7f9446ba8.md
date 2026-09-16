### Title
Missing verification that own address is referenced in shared address definition allows a malicious peer to register attacker-controlled "shared addresses" as owned - ([File: wallet_defined_by_addresses.js])

### Summary
`handleNewSharedAddress()` in `wallet_defined_by_addresses.js` processes the `new_shared_address` device message and registers a new entry in `shared_addresses` / `shared_address_signing_paths` without ever checking that the recipient's own device/address is actually one of the signers required by the submitted definition. This is the direct analog of the reported `setApprovalForAll` issue: a state-changing operation that grants "membership"/control-relationship over an address is accepted purely on the say-so of the counterparty, without validating that the accepting party genuinely holds a stake in it.

### Finding Description
`handleNewSharedAddress` is reachable from any paired device via the `new_shared_address` message handled in `wallet.js`: [1](#0-0) 

The handler performs structural checks (definition hashes to the given address, signer addresses referenced in the definition are valid, every definition leaf has a matching signer entry) but never checks that the local device's own address participates in the definition: [2](#0-1) 

Compare this with the sibling function `validateAddressDefinitionTemplate`, used for the (unused/legacy) template-based flow, which explicitly enforces `arrDeviceAddresses.indexOf(device.getMyDeviceAddress()) === -1` before accepting a definition: [3](#0-2) 

`validateAddressDefinition`, which `handleNewSharedAddress` actually calls, only runs generic `Definition.validateDefinition` sanity checks and carries a code comment explicitly documenting the missing fix: [4](#0-3) 

Because this check is absent, any correspondent device can send a `new_shared_address` message whose definition does not actually reference the victim's address/keys at all (e.g. `["sig", {pubkey: attacker_pubkey}]` wrapped in an `or`/`and` with dummy paths satisfying the structural checks, or a definition where the "signer" entries are cosmetically valid but the victim holds no real signing path). `addNewSharedAddress()` will unconditionally persist it: [5](#0-4) 

and, for light wallets, add it as a watched address and treat it as if it were a genuine multisig relationship the user is party to: [6](#0-5) 

### Impact Explanation
The victim's wallet now believes it "controls" (fully or partially) an address it has no actual signing rights over. This mirrors the `setApprovalForAll` bug class: the entity granted control was never actually authorized by verifying that the accepting party's key material is part of the definition. Consequences:
- A user might be induced to deposit or route funds to what they believe is a shared/multisig address they co-own, but which is fully spendable by the attacker alone, resulting in fund loss.
- The wallet may surface this address in balance/UI flows as an owned shared address, misleading downstream signing/co-signing logic (e.g., `forwardNewSharedAddressToCosignersOfMyMemberAddresses`, `readAllControlAddresses`) that assumes membership implies actual authority.

This is a medium-severity issue: it does not itself move funds, but it creates a state where a victim can be tricked into treating an attacker-controlled address as jointly owned, directly analogous to the unrestricted-approval bug class (granting the illusion of shared control without validating the grantee's actual stake).

### Likelihood Explanation
Any paired correspondent device can trigger this by simply sending a crafted `new_shared_address` message — no privileged network role, no hub/peer trust exploitation, and no elevated protocol position is required, only an existing device pairing (which is a normal precondition for using shared addresses/wallets in ocore).

### Recommendation
In `handleNewSharedAddress` (and/or `validateAddressDefinition`), before persisting the shared address, extract all `["address", ...]` leaves of the submitted definition (as `extractAddressPathsFromDefinition` already does) and verify that at least one leaf corresponds to an address genuinely controlled by the local device (present in `my_addresses`/`wallet_signing_paths`), analogous to the check already performed in `validateAddressDefinitionTemplate`.

### Proof of Concept
1. Device A pairs with victim device B.
2. Device A crafts a definition, e.g. `["sig", {pubkey: A_pubkey}]`, computes `address = getChash160(definition)`, and builds a `signers` map with a plausible-looking (but not actually B-controlled) entry.
3. Device A sends `new_shared_address` `{address, definition, signers}` to B.
4. `handleNewSharedAddress` passes all structural checks (hash matches, signer entries match definition leaves) and calls `addNewSharedAddress`, which inserts the row into `shared_addresses` on B's wallet — despite B holding no signing path in the definition at all.
5. B's wallet now treats `address` as one of its shared addresses (watched, event `new_address` emitted), while only A can ever sign for it.

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

**File:** wallet_defined_by_addresses.js (L239-267)
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

**File:** wallet_defined_by_addresses.js (L488-495)
```javascript
	var arrDeviceAddresses = _.uniq(_.values(assocMemberDeviceAddressesBySigningPaths));
	if (arrDeviceAddresses.length < 2)
		return handleResult("less than 2 member devices");
	if (arrDeviceAddresses.indexOf(device.getMyDeviceAddress()) === - 1)
		return handleResult("my device address not mentioned in the definition");
	if (arrDeviceAddresses.indexOf(from_address) === - 1)
		return handleResult("sender device address not mentioned in the definition");
	
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
