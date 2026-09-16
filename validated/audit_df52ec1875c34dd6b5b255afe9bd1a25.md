## Analysis

The reported Open WebUI bug is a classic **CWE-285 broken access control**: a handler that consumes attacker-controlled identifying data (a Tool ID) and returns/accepts sensitive resource data without verifying the caller is actually authorized for that specific resource.

The closest reachable analog in `ocore` is in the **shared/multisig address creation flow**, reachable directly from an unprivileged paired-device message (`new_shared_address`), which is processed by `wallet.js` and `wallet_defined_by_addresses.js`.

### Root cause

`wallet.js` routes the `new_shared_address` subject straight into `walletDefinedByAddresses.handleNewSharedAddress(body, callbacks)` — notably **without ever passing `from_address`**: [1](#0-0) 

`handleNewSharedAddress` validates that the definition hashes to the claimed address, that signer addresses are individually well-formed, and that signer paths match leaves of the definition — but it **never checks that the message's actual sender (`from_address`) is one of the device addresses referenced in `body.signers`**: [2](#0-1) 

`determineIfIncludesMeAndRewriteDeviceAddress` only checks that one of *my* addresses appears somewhere in the proposed definition — it does not verify that the sending device is a legitimate co-signer of that same definition: [3](#0-2) 

By contrast, the older/legacy "offer" flow (`validateAddressDefinitionTemplate`, used by `sendOfferToCreateNewSharedAddress`) explicitly enforces this check — proving the check is a known, intended security control that is missing from the `new_shared_address` path: [4](#0-3) 

Once accepted, `addNewSharedAddress` unconditionally inserts the attacker-supplied definition into `shared_addresses`/`shared_address_signing_paths` and starts watching it as the victim's own address: [5](#0-4) 

### Impact

A malicious paired correspondent can send a forged `new_shared_address` message naming the victim's real address as one signer leaf and an attacker-controlled address as another, combined with `'or'` at the root (e.g. `["or",[["address","ATTACKER"],["address","VICTIM"]]]`). Because `from_address` is never checked against the signer set, the victim's wallet accepts this as a legitimate jointly-controlled address, displays/tracks it as a "shared address," and creates the false impression that spending requires both parties. Since the actual spending condition permits the attacker's address alone, any funds later deposited into this "shared" address believing it requires multi-party cooperation can be unilaterally spent by the attacker — i.e., unauthorized spending of funds, directly rooted in a missing sender-authorization check analogous to the Tool Valves access-control gap.

### Title
Missing Sender Authorization in `new_shared_address` Handler Enables Spoofed Multisig Address Acceptance - (File: wallet_defined_by_addresses.js)

### Summary
The device-message handler for `new_shared_address` accepts and installs an arbitrary address-sharing definition supplied by any paired correspondent without verifying that the sender is actually one of the definition's authorized co-signers, unlike the equivalent legacy check in `validateAddressDefinitionTemplate`.

### Finding Description
`handleNewSharedAddress(body, callbacks)` in `wallet_defined_by_addresses.js:378-415` is invoked from `wallet.js:236-245` without the sender's `from_address` being passed at all. The function verifies structural consistency (definition hash matches claimed address, signer paths match definition leaves) and that one of the local wallet's own addresses is referenced somewhere in the definition (`determineIfIncludesMeAndRewriteDeviceAddress`, lines 281-315), but never checks that `from_address` corresponds to a device address that is actually a legitimate signer within that same definition. The parallel/legacy code path (`validateAddressDefinitionTemplate`, lines 481-494) explicitly performs this check (`arrDeviceAddresses.indexOf(from_address) === -1`), demonstrating that this authorization step is a recognized security control that was omitted from the `new_shared_address` path. Once accepted, `addNewSharedAddress` (lines 239-268) permanently registers the attacker-chosen definition as a shared address controlled by the victim.

### Impact Explanation
An attacker who is merely a paired correspondent (no special privilege) can construct a definition where the victim's real address appears as one signing branch of an `'or'` while the attacker's own address is another branch. The victim's wallet will silently accept and watch this address as a legitimate "shared" (multi-party) address. Any counterparties or the victim themselves who are led to believe the address requires cooperative signing (e.g., escrow-like use) and deposit funds into it can have those funds unilaterally withdrawn by the attacker, constituting unauthorized spending of deposited funds — directly analogous to the disclosed report's unauthorized access to a sensitive, supposedly protected resource.

### Likelihood Explanation
Requires the attacker to be an already-paired correspondent device of the victim (a common baseline achievable e.g. via normal pairing/chat invitations), and requires the victim (or a third party) to subsequently fund the spoofed shared address believing it to be securely multi-controlled. No hub, network, or node-level compromise is needed — the entire exploit is a single crafted device message.

### Recommendation
In `handleNewSharedAddress`, thread `from_address` through from `wallet.js` and require that `from_address` matches one of the device addresses referenced in `body.signers` for the corresponding definition leaf, mirroring the check already present in `validateAddressDefinitionTemplate`. Reject the message otherwise.

### Proof of Concept
1. Attacker pairs with Victim's device (normal pairing flow).
2. Attacker crafts `definition = ["or", [["address", ATTACKER_ADDR], ["address", VICTIM_ADDR]]]`, computes `address = chash160(definition)`, and builds `signers` mapping each leaf path to the respective address.
3. Attacker sends a `new_shared_address` device message with this body directly to Victim.
4. Victim's wallet, via `handleNewSharedAddress`, finds `VICTIM_ADDR` among the definition's addresses, passes `determineIfIncludesMeAndRewriteDeviceAddress`, and calls `addNewSharedAddress`, registering `address` as a shared address without ever confirming the message actually originated from a legitimate co-signer of that address.
5. Victim (or someone instructed by Victim) later sends funds to `address` believing both parties must cooperate to spend; Attacker spends unilaterally via the `ATTACKER_ADDR` branch.

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

**File:** wallet_defined_by_addresses.js (L491-494)
```javascript
	if (arrDeviceAddresses.indexOf(device.getMyDeviceAddress()) === - 1)
		return handleResult("my device address not mentioned in the definition");
	if (arrDeviceAddresses.indexOf(from_address) === - 1)
		return handleResult("sender device address not mentioned in the definition");
```
