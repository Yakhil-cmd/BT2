### Title
Unauthenticated Peer-Initiated Shared-Address Registration Allows Silent Co-Signer Injection - (File: wallet_defined_by_addresses.js)

### Summary
The OpenEMR bug allowed an authenticated but unprivileged actor to bind an arbitrary, attacker-chosen identifier (`provider user ID`) to a security-sensitive artifact (a signature) without verifying that the caller actually owns/controls that identifier. The equivalent pattern exists in `ocore`'s multi-device wallet protocol: the `new_shared_address` device message handler accepts a fully attacker-supplied shared-address definition and a signer/device-address map and persists it as a trusted local "shared address" for the recipient, without ever verifying that the sending correspondent is entitled to bind the recipient's own address into that construct, and without any local user-approval step.

### Finding Description
When a paired device sends a `new_shared_address` message, `wallet.js` forwards the body straight into `wallet_defined_by_addresses.handleNewSharedAddress` with no check that `from_address` corresponds to any of the `device_address` values in `body.signers`: [1](#0-0) 

`handleNewSharedAddress` only checks that (a) the definition hashes to the claimed address, (b) member addresses referenced in the definition are syntactically valid, and (c) the `signers` map is internally consistent with paths extracted from the definition: [2](#0-1) 

It then calls `determineIfIncludesMeAndRewriteDeviceAddress`, which merely checks whether any of the addresses in the attacker-supplied definition happen to already belong to the local wallet (`my_addresses`/`shared_addresses`) — it does not require any explicit local approval, nor does it validate that the *other* signer identities in the definition are real, reachable, or consented to: [3](#0-2) 

If satisfied, `addNewSharedAddress` unconditionally inserts the shared address and its full `shared_address_signing_paths` (including attacker-chosen `device_address` values for every signing path) into local storage and fires `new_address` events, causing the wallet UI/back end to begin treating the address as a legitimate (partially-owned) address: [4](#0-3) 

Because the attacker fully controls `body.definition`, they can construct a definition such as `["or", [["address", "<my_address>"], ["address", "<attacker_address>"]]]`. This is a syntactically valid definition whose c-hash they compute themselves, so it passes the `addr === objectHash.getChash160(body.definition)` check. The victim's wallet will register this as a "shared address" that appears to involve the victim, while in reality the `or` branch lets the attacker unilaterally satisfy the spending condition with only their own signature — no cooperation or approval from the victim is required to spend from it.

This mirrors the OpenEMR flaw's root cause: a security-relevant identity/ownership binding (which addresses/devices participate in and control funds sent to a construct) is created purely from client-supplied identifiers, with no verification that the initiating party is authorized to establish that binding for the victim.

### Impact Explanation
Once the forged shared address is silently registered, the victim's node treats it as a known/relevant address (via `eventBus.emit("new_address", address)` and, for light clients, addition to `unprocessed_addresses`/watched addresses). Any funds sent to this address — e.g., because the victim shared it as a receiving address believing it to be an honest multisig they participate in, or because it is surfaced through wallet UI as "shared" — can be spent unilaterally by the attacker through the `or` branch, with no requirement for the victim's signature. This is direct unauthorized spending / fund loss, without requiring any prior compromise of the victim's keys.

### Likelihood Explanation
The attack only requires being a paired correspondent device of the victim (a normal, low-privilege relationship established via standard pairing), and sending a single crafted `new_shared_address` message. No malicious hub, network-level attack, or private key leakage is required — this fits the "paired device" actor type explicitly in scope.

### Recommendation
- Require that shared-address registration only proceed after the local user (or an equivalent policy check) explicitly reviews and approves the full definition, rather than auto-registering on receipt of `new_shared_address`.
- Reject `or`-type definitions (or any construct where a subset of signers is address-sufficient without the local key) unless the local wallet initiated the shared-address creation itself and tracked which paths were mutually agreed via the existing `pending_shared_addresses` / `approvePendingSharedAddress` flow.
- Verify that `from_address` is bound to one of the claimed `device_address` values in `body.signers` and that the local address(es) referenced were previously offered/consented to (e.g., matched against a `pending_shared_addresses` record initiated locally) before calling `addNewSharedAddress`.

### Proof of Concept
1. Attacker device pairs normally with the victim device (standard `pairing` flow).
2. Attacker computes `arrDefinition = ["or", [["address", "<victim_address>"], ["address", "<attacker_address>"]]]` and `shared_address = getChash160(arrDefinition)`.
3. Attacker sends a `new_shared_address` device message: `{address: shared_address, definition: arrDefinition, signers: {"r.0": {address: victim_address, device_address: victim_device_address}, "r.1": {address: attacker_address, device_address: attacker_device_address}}}`.
4. Victim's `handleNewSharedAddress` passes all checks (hash matches, signer addresses match definition paths) and calls `addNewSharedAddress`, registering the address locally without any approval prompt.
5. Third parties who see this address (e.g., shared by the victim as a "shared" receiving address) send funds to it.
6. Attacker independently signs and broadcasts a spend from `shared_address` using only the `r.1` (`attacker_address`) branch of the `or` definition, unilaterally draining the funds.

Note: I was not able to execute this end-to-end in a live network to confirm runtime behavior (e.g., exact UI presentation of "shared addresses" to end users, since front-end wallet code is outside this repo's index); this assessment is based on the server-side (`ocore`) validation logic shown above, which does not appear to require prior mutual consent for registering a shared address pushed by a correspondent.

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
