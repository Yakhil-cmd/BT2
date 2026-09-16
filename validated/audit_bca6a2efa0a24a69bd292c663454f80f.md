Based on my investigation, I found a solid analog. The `new_shared_address` message handler in `wallet_defined_by_addresses.js` accepts an attacker-supplied address definition and signer map from **any existing correspondent** without any interactive user-approval step (unlike the legitimate `create_new_shared_address` → `approve_new_shared_address` flow), and this silently wires the attacker's device into `shared_address_signing_paths`. That table is later used by the private-payment forwarding logic to decide who transparently receives forwarded private-payment chain data — mirroring the Discourse bug where users are silently, transparently added as participants able to see private message/content they never consented to.

### Title
Unauthorized peer can silently register itself as co-signer of a shared address and receive forwarded private payment data - (File: `wallet_defined_by_addresses.js`)

### Summary
The device-message handler for subject `new_shared_address` (`wallet.js` case `'new_shared_address'`, dispatching to `handleNewSharedAddress` in `wallet_defined_by_addresses.js:377-415`) accepts an attacker-crafted address `definition` and `signers` map from any paired correspondent and inserts it directly into `shared_addresses` / `shared_address_signing_paths` via `addNewSharedAddress` (`wallet_defined_by_addresses.js:239-268`), with **no interactive user confirmation**, unlike the legitimate wallet-creation flow (`create_new_shared_address` → `eventBus.emit("create_new_shared_address", ...)` → explicit user approval, `wallet.js:197-226`).

### Finding Description
`handleNewSharedAddress` only checks that:
1. `body.definition` hashes to `body.address` [1](#0-0) 
2. signer addresses are syntactically valid and match the paths extracted from the definition [2](#0-1) 
3. `determineIfIncludesMeAndRewriteDeviceAddress` confirms one of the addresses referenced in the definition belongs to the local wallet (`my_addresses`/`shared_addresses`) [3](#0-2) 
4. `validateAddressDefinition` only checks the definition is *syntactically* well formed [4](#0-3) 

Crucially, none of these checks verify that the *sender* (`from_address`) of the message is actually supposed to be a party to this shared address, nor does the dispatcher in `wallet.js` even pass `from_address` into the call [5](#0-4) . Since a victim's own single-sig address is public (learned from any prior interaction), any correspondent can construct a new definition (e.g. an `or` of the victim's real address and the attacker's own address) whose chash160 becomes a brand-new "shared address," and send it as `new_shared_address`. Because the victim's real address is referenced somewhere in the definition, `determineIfIncludesMeAndRewriteDeviceAddress` passes, and `addNewSharedAddress` silently persists `shared_address_signing_paths` rows mapping that new shared address to the attacker's own `device_address` — all without any UI confirmation dialog.

This poisoned `shared_address_signing_paths` entry is exactly what the private-payment forwarding logic consults to decide which peer devices are legitimate "cosigners"/"members" entitled to receive forwarded private payment chains: `forwardPrivateChainsToOtherMembersOfAddresses` (`wallet_defined_by_addresses.js:531-543`) and `forwardPrivateChainsToOtherMembersOfSharedAddresses` (`wallet.js:2520-2533`) both join `shared_address_signing_paths` against `correspondent_devices` to build the forward list. Once the attacker's device is present there under the fabricated shared address, any subsequent private divisible/indivisible asset payment whose output lands on that shared address will be transparently forwarded to the attacker device via `forwardPrivateChainsToOtherMembersOfOutputAddresses` (`wallet.js:1082-1116`) — leaking amounts, blinding factors, and chain details to a party the victim never agreed to share the transaction with, without any notification to the victim.

### Impact Explanation
This is a private-data-leak / consent-bypass analogous to the Discourse advisory: a party who should have no visibility into a private conversation (here, a private payment chain) is transparently and silently made a "member" able to receive forwarded private payment content, entirely without the victim's knowledge or the interactive approval that the codebase's own comments (`wallet.js:206-208`, "user needs to approve creation of the shared address") indicate is required by design elsewhere.

### Likelihood Explanation
Any existing correspondent (a normal chat contact who is not necessarily a trusted multisig partner) can trigger this by sending one crafted `new_shared_address` device message referencing the victim's already-known address. `new_shared_address` is not in the noncorrespondent whitelist (`arrSubjectsAllowedFromNoncorrespondents` in `device.js:214`), so the attacker only needs to be a paired correspondent, which is a low bar to reach.

### Recommendation
- Require `from_address` to be checked and passed through in the `new_shared_address` handler, and confirm the sender is one of the `signers` for a path other than the victim's own, rather than silently trusting arbitrary signer/device mappings.
- Do not persist a new shared address / `shared_address_signing_paths` entry (nor use it to influence private-payment forwarding) without the same explicit user-approval flow used by `create_new_shared_address`/`approve_new_shared_address`.

### Proof of Concept
1. Attacker pairs with victim as a normal chat correspondent (or is already paired).
2. Attacker learns victim's real payment address `V` (e.g., from a previous payment).
3. Attacker builds `definition = ["or", [["address", V], ["address", A]]]` (A = attacker's own address) and computes `address = chash160(definition)`.
4. Attacker sends a `new_shared_address` device message: `{address, definition, signers: {"r.0": {address: V}, "r.1": {address: A, device_address: attackerDeviceAddr}}}`.
5. Victim's `handleNewSharedAddress` accepts it silently (`wallet_defined_by_addresses.js:377-415`), inserting `shared_address_signing_paths` rows including `device_address=attackerDeviceAddr`.
6. Anyone later sends a private asset payment whose output address is the fabricated shared address; when the victim's wallet processes/forwards this private chain, `forwardPrivateChainsToOtherMembersOfAddresses`/`forwardPrivateChainsToOtherMembersOfOutputAddresses` forwards the private payment data to the attacker's device automatically.

### Citations

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

**File:** wallet_defined_by_addresses.js (L391-405)
```javascript
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
```

**File:** wallet_defined_by_addresses.js (L520-528)
```javascript
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
