### Title
Missing Authorization on `new_shared_address` Device Message Allows Registration of Attacker-Controlled Shared Addresses - ([File: wallet_defined_by_addresses.js])

### Summary
The `new_shared_address` device-message handler (`handleNewSharedAddress` in `wallet_defined_by_addresses.js`) accepts and persists an arbitrary multi-signature address definition and its cosigner-to-device mapping from **any paired correspondent**, without verifying that the sending device (`from_address`) is actually one of the parties named in that definition. This mirrors the TREK bug class: a resource-management route (here, the "register a new shared/multisig address" operation) is missing an authorization check tying the caller to the resource being modified.

### Finding Description
In `wallet.js`, the `new_shared_address` subject is routed unconditionally to `walletDefinedByAddresses.handleNewSharedAddress`: [1](#0-0) 

`handleNewSharedAddress` performs several structural/consistency checks (definition hashes to the claimed address, signer addresses match the definition leaves, my own address must appear among the signers), but it never checks that `from_address` — the device that actually sent the message — is one of the `device_address` values inside `body.signers`: [2](#0-1) 

The only "ownership" check performed is `determineIfIncludesMeAndRewriteDeviceAddress`, which merely confirms that *some* address in the attacker-supplied definition matches one of the local wallet's existing `my_addresses` or `shared_addresses` — it does not verify that the correspondent sending the notification is entitled to notify about this particular shared address: [3](#0-2) 

Because the attacker fully controls `body.definition` and `body.signers`, they can craft a definition such as `["or", [["address", "<victim's real address>"], ["address", "<attacker address>"]]]`. This satisfies the "I am a member" check (the victim's real address is present), passes `validateAddressDefinition` (which only checks structural validity, not that the policy requires all parties' cooperation), and is then persisted via `addNewSharedAddress`: [4](#0-3) 

The resulting rows in `shared_addresses` / `shared_address_signing_paths` falsely represent the attacker's device as a legitimate cosigner/member device of the newly created address, and this data feeds directly into wallet logic (`findAddress`, `readAllControlAddresses`, `forwardPrivateChainsToOtherMembersOfSharedAddresses`) that decides which device to trust for spending permission and private-payment forwarding.

### Impact Explanation
Because the injected definition can use an `"or"` combinator rather than `"and"`, an attacker (any correspondent of the victim, without any legitimate multisig relationship) can register a *new* address that the victim's wallet displays/treats as "my shared address," while in reality the attacker alone can authorize spending from it. Funds directed to this fabricated shared address by a victim who believes it is a genuine cosigned/protected address can be spent unilaterally by the attacker — concrete unauthorized spending. Additionally, because the attacker controls which device addresses are listed as "members," they can cause private payment chains associated with that shared address to be forwarded to their own device via `forwardPrivateChainsToOtherMembersOfSharedAddresses`/`readAllControlAddresses`, leaking private-payment output/blinding data to an unauthorized party.

### Likelihood Explanation
The message can be sent by any paired device correspondent (the "new_shared_address" subject is processed for any known correspondent device in `handleMessageFromHub`), requires no special privileges, and only needs the target's real address (learnable from prior chat/payment interactions) to satisfy the sole ownership check. No unit needs to be posted to the DAG and no consensus/mining is involved — it is a pure device-messaging-layer flaw.

### Recommendation
In `handleNewSharedAddress`, require that `from_address` correspond to one of the `device_address` values declared in `body.signers` (or otherwise be a device that legitimately participated in constructing this specific shared address, e.g. via the existing `create_new_shared_address` / `approve_new_shared_address` handshake, or by cross-checking against `pending_shared_address_signing_paths`). Reject "new_shared_address" notifications whose sender is not among the claimed cosigner devices. Additionally, consider warning the user in the UI whenever an incoming shared-address definition offers unilateral (`"or"`) spend paths that do not require the local wallet's own signature, so users are not tricked into treating such addresses as safe multisig destinations.

### Proof of Concept
1. Attacker pairs with victim's device (a normal correspondent relationship).
2. Attacker learns one of victim's real payment addresses `V` (e.g., from a previous chat/payment).
3. Attacker computes `def = ["or", [["address","V"], ["address","A"]]]` where `A` is an address they control, and `shared_address = chash160(def)`.
4. Attacker sends a `new_shared_address` device message to the victim:
   ```
   {
     subject: "new_shared_address",
     body: {
       address: shared_address,
       definition: def,
       signers: {
         "r.0": { address: "V" },
         "r.1": { address: "A", device_address: "<attacker_device_address>" }
       }
     }
   }
   ```
5. `handleNewSharedAddress` accepts this (address `V` satisfies the "I am a member" check; structural validation passes) and inserts `shared_address` into the victim's `shared_addresses`/`shared_address_signing_paths` tables without ever verifying the sender is entitled to register this definition.
6. If the victim is induced (e.g., via wallet UI showing it as a legitimate shared address) to receive funds at `shared_address`, the attacker can spend those funds unilaterally by satisfying the `"address","A"` branch of the `"or"` definition — no cooperation from the victim is required.

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
