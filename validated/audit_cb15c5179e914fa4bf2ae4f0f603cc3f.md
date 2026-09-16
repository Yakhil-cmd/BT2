### Title
Unsolicited `new_shared_address` Message Silently Accepted Without Verifying a Prior Shared-Address Negotiation - (File: wallet_defined_by_addresses.js)

### Summary
The multisig/"shared address" setup protocol in ocore is a multi-step handshake between paired devices: `create_new_shared_address` (offer) → `approve_new_shared_address` (approval) → `new_shared_address` (completion, sent by the initiator once all approvals are collected). The device-message handler for the final `new_shared_address` message, however, processes it unconditionally from any correspondent device and never checks that a corresponding negotiation (`pending_shared_addresses`/`pending_shared_address_signing_paths`) was ever started by the local device. It relies purely on content/identifier matching (definition c-hash, and presence of a recognized address in the signer map) rather than on any local "was I expecting this?" state, exactly the bug class described in the BLE `le_conn_rsp` report: a completion/response message is trusted solely because its fields line up, not because a matching outstanding request exists.

### Finding Description
`case "new_shared_address"` in `wallet.js` forwards any incoming message directly to `walletDefinedByAddresses.handleNewSharedAddress` with no precondition: [1](#0-0) 

`handleNewSharedAddress` only performs structural checks — that `body.definition` hashes to `body.address`, that declared signer addresses are syntactically valid, and that they match the leaves of the definition tree: [2](#0-1) 

It then calls `determineIfIncludesMeAndRewriteDeviceAddress`, whose only gate is whether *any* address listed in the attacker-supplied `signers` map is already known locally (`my_addresses` or `shared_addresses`): [3](#0-2) 

If that lookup succeeds, `addNewSharedAddress` unconditionally inserts the attacker-chosen definition into `shared_addresses`/`shared_address_signing_paths`, treats the sender's declared `device_address` values as legitimate cosigners, and re-forwards the (unverified) shared address to any other of the victim's own cosigner devices: [4](#0-3) [5](#0-4) 

Unlike the legitimate initiator path (`createNewSharedAddress`, which explicitly checks `includesMyDeviceAddress` before acting) and unlike the offer path (`create_new_shared_address`, which requires an explicit user-confirmation dialog via `eventBus.emit("create_new_shared_address", ...)`): [6](#0-5) [7](#0-6) 
the completion message `new_shared_address` is applied silently with no confirmation and no check that this device (or any of its cosigner devices) ever issued/approved a `create_new_shared_address`/`approve_new_shared_address` handshake for that specific `definition_template_chash`. There is no `pending_shared_addresses` correlation check at all in this code path — the only "authentication" is that the sender happens to name an address the wallet already recognizes as its own or as an already-known shared address, which an attacker learns simply by asking the victim for a receiving address (a completely normal, expected interaction) or by observing an already-shared address.

### Impact Explanation
Any paired device (a correspondent from a prior pairing, chat, bot, or arbiter/prosaic-contract counterparty) can unilaterally push a crafted `new_shared_address` message naming the victim's own known address (or an existing shared address) as one signer, together with an arbitrary attacker-controlled definition tree that nominally "includes" the victim but structurally allows the attacker to spend alone (e.g., an `or` branch). The victim's wallet will silently record this as a legitimate multisig/shared address (no dialog, no negotiation state check), display/track it as protected, and even propagate it to the victim's other cosigner devices. A victim (or one of their cosigners) who is subsequently induced to deposit funds into this bogus "shared" address — believing it enforces joint control — can have those funds spent unilaterally by the attacker, i.e., unauthorized spending / fund loss enabled purely by an out-of-context, unrequested "response" message.

### Likelihood Explanation
Exploitation requires only that the attacker be a paired device of the victim (a normal, low-bar relationship established via pairing codes, chat, or contract negotiation flows already built into the wallet) and knowledge of one address already known to the victim's wallet (trivially obtained by requesting a payment address, which is routine). No race condition, timing window, or privileged position is needed — the message is processed unconditionally whenever received.

### Recommendation
Before accepting a `new_shared_address` completion message, require and verify a matching outstanding negotiation state (e.g., a `pending_shared_addresses` row for the given `definition_template_chash` that the local device previously approved via `approve_new_shared_address`), analogous to how `network.js`'s `handleResponse` requires a matching `assocPendingRequests[tag]` before acting on a response. Additionally, gate silent acceptance behind explicit user confirmation (as already done for `create_new_shared_address`) rather than relying solely on definition/address matching.

### Proof of Concept
1. Attacker pairs with victim's device (or is already a correspondent/contract counterparty).
2. Attacker learns one of victim's addresses `A` (e.g., by requesting a payment address in chat).
3. Attacker crafts a definition `D` such that `chash160(D) = X` and `D` structurally includes `A` at some `signing_path` but also contains an `or` branch granting the attacker's own address sole spending authority.
4. Attacker sends `device.sendMessageToDevice(victim_device, "new_shared_address", {address: X, definition: D, signers: {...pathIncludingA..., ...pathGivingAttackerSoleControl...}})`.
5. Victim's `handleNewSharedAddress` (`wallet_defined_by_addresses.js:378`) validates only structure/c-hash, finds `A` in `my_addresses`, and silently calls `addNewSharedAddress`, registering `X` as a trusted shared address with no user prompt and no verification that any `create_new_shared_address`/`approve_new_shared_address` handshake preceded this message.
6. If the victim (or an informed cosigner, via `forwardNewSharedAddressToCosignersOfMyMemberAddresses`) is later led to deposit funds to `X` believing it is jointly controlled, the attacker can spend those funds unilaterally.

### Citations

**File:** wallet.js (L197-212)
```javascript
			case "create_new_shared_address":
				// {address_definition_template: [...]}
				if (!ValidationUtils.isArrayOfLength(body.address_definition_template, 2))
					return callbacks.ifError("no address definition template");
				walletDefinedByAddresses.validateAddressDefinitionTemplate(
					body.address_definition_template, from_address, 
					function(err, assocMemberDeviceAddressesBySigningPaths){
						if (err)
							return callbacks.ifError(err);
						// this event should trigger a confirmatin dialog, user needs to approve creation of the shared address and choose his 
						// own address that is to become a member of the shared address
						eventBus.emit("create_new_shared_address", body.address_definition_template, assocMemberDeviceAddressesBySigningPaths);
						callbacks.ifOk();
					}
				);
				break;
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

**File:** wallet_defined_by_addresses.js (L417-437)
```javascript
function createNewSharedAddress(arrDefinition, assocSignersByPath, callbacks){
	if (!includesMyDeviceAddress(assocSignersByPath))
		return callbacks.ifError("my device address not mentioned");
	var address = objectHash.getChash160(arrDefinition);
	handleNewSharedAddress({address: address, definition: arrDefinition, signers: assocSignersByPath}, {
		ifError: callbacks.ifError,
		ifOk: function(){
			// share the new address with all cosigners
			var arrDeviceAddresses = [];
			for (var signing_path in assocSignersByPath){
				var signerInfo = assocSignersByPath[signing_path];
				if (signerInfo.device_address !== device.getMyDeviceAddress() && arrDeviceAddresses.indexOf(signerInfo.device_address) === -1)
					arrDeviceAddresses.push(signerInfo.device_address);
			}
			arrDeviceAddresses.forEach(function(device_address){
				sendNewSharedAddress(device_address, address, arrDefinition, assocSignersByPath);
			});
			callbacks.ifOk(address);
		}
	});
}
```
