## Finding [1](#0-0) 

The `new_shared_address` device-message handler dispatches directly into `walletDefinedByAddresses.handleNewSharedAddress(body, ...)` with no check that `from_address` (the authenticated sender of the paired-device message) is actually a party to the shared-address definition being installed: [2](#0-1) 

Contrast this with the sibling function used for the *proposal* stage (`create_new_shared_address` → `validateAddressDefinitionTemplate`), which explicitly enforces `arrDeviceAddresses.indexOf(from_address) === -1` → `"sender device address not mentioned in the definition"`: [3](#0-2) 

`handleNewSharedAddress` only checks: (1) the definition hash matches, (2) `signers` paths match addresses in the definition, and (3) via `determineIfIncludesMeAndRewriteDeviceAddress` that *some* address in `body.signers` belongs to the recipient's own `my_addresses`/`shared_addresses`: [4](#0-3) 

It never verifies that the sender of the message (`from_address`) is one of the device addresses referenced in `body.signers`/the definition. Any paired correspondent (who only needs to know one of the victim's real payment addresses, commonly exchanged over chat/contracts) can therefore forge a `new_shared_address` message combining that known address with an attacker-controlled address via an `"and"`/`"or"`/`"r of set"` definition, and the victim's wallet will silently insert it into `shared_addresses` and even forward it on to the victim's other correspondents via `forwardNewSharedAddressToCosignersOfMyMemberAddresses`: [5](#0-4) [6](#0-5) 

This is the same bug class as the reported advisory: a message-dispatch path (`GROUP`/`new_shared_address`) that is supposed to be gated by verifying the sender's membership/authorization, but the check is missing, letting an unauthorized sender's message be processed as if it came from a legitimate party.

### Title
Missing sender-membership check in `new_shared_address` handler allows unauthorized shared-address injection - (File: wallet_defined_by_addresses.js)

### Summary
`handleNewSharedAddress()` (invoked directly by the `new_shared_address` device-message case in `wallet.js`) never validates that the message sender (`from_address`) is actually one of the device addresses referenced in the shared-address definition/signers it is asked to install, unlike the analogous `validateAddressDefinitionTemplate()` used earlier in the (optional) proposal flow.

### Finding Description
The normal shared-address creation flow is: `create_new_shared_address` (checked against `from_address`) → user confirmation → `approve_new_shared_address` → once all parties approve, `new_shared_address` is sent to finalize. However, nothing prevents a device from sending `new_shared_address` directly, skipping the proposal/approval steps. `handleNewSharedAddress` accepts any `{address, definition, signers}` triple as long as the hash matches and one of the `signers` addresses is locally known (`my_addresses`/`shared_addresses`), then calls `addNewSharedAddress`, which stores the address and notifies (forwards) it to the victim's other correspondents who are cosigners of the referenced member addresses.

### Impact Explanation
A correspondent device (an "unprivileged" already-paired device, per the allowed threat surface for wallet/contract message handling) can trick a victim's wallet into recording an attacker-crafted address as a legitimate shared/multisig address containing the victim's real address. Because this record is then also forwarded to the victim's other correspondents that co-own the referenced address, it can propagate a false multisig relationship across a wallet's contacts, potentially leading users to send funds to, or expect signing cooperation from, an address that does not represent the agreed-upon multisig arrangement (fund loss/misdirection or freezing when the victim believes co-signers can approve spends that the attacker actually controls).

### Likelihood Explanation
Likelihood is straightforward: exploitation only requires being an already-paired correspondent device (no special privilege) and knowing one of the victim's real addresses — information routinely exchanged during normal wallet interactions such as contracts, payments, or shared-address setup dialogs.

### Recommendation
In `handleNewSharedAddress`, before installing the shared address, verify that `from_address` corresponds to one of the `device_address` values in `body.signers` (mirroring the existing check performed in `validateAddressDefinitionTemplate`). Reject the message otherwise.

### Proof of Concept
1. Attacker pairs with victim's device (or is already a correspondent).
2. Attacker learns one of victim's real addresses `V` (e.g., via a shared payment request).
3. Attacker crafts a 2-of-2 `"and"`/`"or"` definition combining `V` and attacker's own address `A`, computes its chash as `address`, and builds a `signers` map: `{"r.0": {address: V, device_address: <victim_device>}, "r.1": {address: A, device_address: <attacker_device>}}`.
4. Attacker sends `{subject: "new_shared_address", body: {address, definition, signers}}` directly to the victim's device.
5. Victim's `handleNewSharedAddress` inserts the shared address (since `V` is in `my_addresses`) with no verification that the *sender* of this message is authorized to declare such a relationship, and forwards it to other cosigners of `V`.

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

**File:** wallet_defined_by_addresses.js (L481-494)
```javascript
function validateAddressDefinitionTemplate(arrDefinitionTemplate, from_address, handleResult){
	try{
		var assocMemberDeviceAddressesBySigningPaths = getMemberDeviceAddressesBySigningPaths(arrDefinitionTemplate);
	}
	catch (e) {
		return handleResult("failed to get member device addresses of new shared address: " + e.toString());
	}
	var arrDeviceAddresses = _.uniq(_.values(assocMemberDeviceAddressesBySigningPaths));
	if (arrDeviceAddresses.length < 2)
		return handleResult("less than 2 member devices");
	if (arrDeviceAddresses.indexOf(device.getMyDeviceAddress()) === - 1)
		return handleResult("my device address not mentioned in the definition");
	if (arrDeviceAddresses.indexOf(from_address) === - 1)
		return handleResult("sender device address not mentioned in the definition");
```
