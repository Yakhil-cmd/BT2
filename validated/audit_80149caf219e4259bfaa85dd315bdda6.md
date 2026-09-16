### Title
Unauthenticated `new_shared_address` device message lets an attacker hijack co-signer device mapping and hijack forwarding of private payment chains - ([File: wallet_defined_by_addresses.js])

### Summary
`handleNewSharedAddress()` accepts a `new_shared_address` wallet-to-wallet message and only validates that (a) the supplied definition hashes to the claimed address and (b) each `signer.address` in the `signers` map matches an `["address", …]` leaf actually present in the definition at that signing path. It never verifies that the `device_address` claimed for a co-signer's address is actually controlled/authorized by that co-signer, nor that the sender of the message has any right to declare device ownership for member addresses other than its own. `determineIfIncludesMeAndRewriteDeviceAddress()` only re-writes the device mapping for addresses that belong to *my own* wallet (`my_addresses`/`shared_addresses`); any other member address's claimed `device_address` is trusted verbatim and persisted into `shared_address_signing_paths`.

### Finding Description
The vulnerable flow:
1. `wallet.js` `case "new_shared_address"` (`wallet.js:236-245`) forwards the raw peer body straight into `walletDefinedByAddresses.handleNewSharedAddress(body, …)` with no additional authorization check on the sender (`from_address`).
2. `handleNewSharedAddress()` (`wallet_defined_by_addresses.js:377-415`) validates:
   - `objectHash.getChash160(body.definition) === body.address` (definition legitimately hashes to the address — this is public knowledge once the address has been used on-chain, so an attacker can reconstruct it),
   - for each `signing_path` in `body.signers`, `assocDefinitionAddresses[signing_path] === signerInfo.address` (the *address* claimed at a path must match the definition), but the **`device_address` field of `signerInfo` is never checked against anything** — it is accepted purely on the word of the sender. [1](#0-0) 
3. `determineIfIncludesMeAndRewriteDeviceAddress()` (`wallet_defined_by_addresses.js:281-315`) only forces `device_address = device.getMyDeviceAddress()` for signing paths whose `address` belongs to the local wallet (`my_addresses`/`shared_addresses`). Any signing path belonging to a *different* legitimate co-signer's address is left untouched, i.e. the attacker-supplied `device_address` for that co-signer is trusted as-is. [2](#0-1) 
4. `addNewSharedAddress()` (`wallet_defined_by_addresses.js:239-268`) then does `INSERT IGNORE` of `(shared_address, address, signing_path, member_signing_path, device_address)` into `shared_address_signing_paths`. Because the primary key is `(shared_address, signing_path)`, this insert only fails to overwrite an *already-known* signing path — but if the victim device has never seen this particular shared address/signing path before (a very common situation the very first time it learns about a shared/multisig address, e.g. after being introduced to it by any peer, or a "recovery" resend), the attacker's row for another member's signing path is accepted and stored. [3](#0-2) 
5. That table (`shared_address_signing_paths.device_address`) is exactly what `readAllControlAddresses()` / `forwardPrivateChainsToOtherMembersOfSharedAddresses()` use to decide which devices to forward **private payment chain** data to when a private (indivisible/divisible) asset payment touches this shared address: [4](#0-3) [5](#0-4) 

Because the attacker's forged `device_address` is now permanently recorded as "controlling" the shared address for that signing path, every subsequent private-payment chain (`handlePrivatePaymentChains` in `wallet.js:955-1079`, which calls `forwardPrivateChainsToOtherMembersOfSharedAddresses` at completion) that the victim relays or receives for this shared address will be forwarded to the attacker's device, revealing the private payment payload (addresses, amounts, blinding factors) that make up the private asset transfer/issue chain. [6](#0-5) 

This mirrors the Ghostwriter bug class precisely: an object reference (here, "which device controls signing_path X of shared_address Y") is accepted and persisted without validating that the claimant actually owns/controls that referenced resource, and the missing check leads to disclosure of another party's private, access-scoped content (private payment chains) to an unauthorized actor.

### Impact Explanation
An attacker who can pair with (or spoof messages to, if relay-authenticated only by device key and reachable as any correspondent) a victim's wallet can register themselves as the "device" for a co-signer's address on a shared/multisig address the victim participates in. From that point on, private payment chains destined for or passing through that shared address are automatically forwarded to the attacker, disclosing private transaction contents (private asset payment amounts, addresses, blinding secrets) that were never intended for the attacker. This is a confidentiality breach of private-payment data reachable purely from a wallet-protocol message sent by an unprivileged peer/paired device — no consensus-level compromise is required, but it satisfies the "AA/asset counterparty or paired device" reachable class and results in concrete unauthorized disclosure of private payment chain data.

### Likelihood Explanation
The attacker only needs to be a correspondent/paired device of the victim (a normal, low-privilege relationship in ocore's wallet layer) and to know the public definition of a shared address the victim is a member of (definitions become public once disclosed on the DAG, e.g. through the first authored unit). No cryptographic secret of the impersonated co-signer is required — only its already-public component address. The check that is missing (`device_address` ownership) is a simple oversight rather than a deep protocol flaw, making exploitation straightforward once the shared address's definition is known.

### Recommendation
- In `handleNewSharedAddress()`/`determineIfIncludesMeAndRewriteDeviceAddress()`, never trust a peer-supplied `device_address` for signing paths belonging to addresses that are not the message sender's own claimed identity; require some form of proof (e.g., signature from that device, or hub-mediated introduction) before recording a `device_address` mapping for a co-signer other than the local wallet's own address.
- Treat `shared_address_signing_paths` entries for foreign co-signers as provisional/unforwarded until the co-signer confirms their own device mapping directly (e.g., via `sendApprovalOfNewSharedAddress` flow) rather than accepting whatever the introducing peer claims.
- Add an explicit authorization/ownership check before forwarding private payment chains to any device_address that was learned solely from an unauthenticated `new_shared_address` message.

### Proof of Concept
1. Victim V holds member address `M_V` and is (or is about to become) part of shared/multisig address `S` together with a genuine co-signer whose member address is `M_C` (definition of `S` publicly known, e.g. `["and", [["address","M_V"], ["address","M_C"]]]`).
2. Attacker A, paired with V's wallet, sends a `new_shared_address` message:
   ```
   {
     address: S,
     definition: ["and", [["address","M_V"], ["address","M_C"]]],
     signers: {
       "r.0": { address: "M_V", device_address: V_DEVICE },
       "r.1": { address: "M_C", device_address: A_DEVICE }   // forged
     }
   }
   ```
3. `handleNewSharedAddress` validates hash + address-per-path matches and accepts it; `determineIfIncludesMeAndRewriteDeviceAddress` recognizes `M_V` as V's own address (leaves it as-is) but does not touch/verify the `M_C -> A_DEVICE` mapping.
4. `addNewSharedAddress` inserts `(S, M_C, "r.1", …, A_DEVICE)` into `shared_address_signing_paths` (first time V's wallet learns this path, so `INSERT IGNORE` succeeds).
5. Later, when V sends or forwards a private asset payment involving `S`, `forwardPrivateChainsToOtherMembersOfSharedAddresses` looks up `shared_address_signing_paths` for `S`, finds `A_DEVICE` as a "control device," and forwards the private payment chain (revealing amounts/addresses/blinding) to attacker A.

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

**File:** wallet.js (L1007-1016)
```javascript
		if (!body.forwarded){
			if (from_address) emitNewPrivatePaymentReceived(from_address, arrChains, current_message_counter);
			// note, this forwarding won't work if the user closes the wallet before validation of the private chains
			var arrUnits = arrChains.map(function(arrPrivateElements){ return arrPrivateElements[0].unit; });
			db.query("SELECT address FROM unit_authors WHERE unit IN(?)", [arrUnits], function(rows){
				var arrAuthorAddresses = rows.map(function(row){ return row.address; });
				// if the addresses are not shared, it doesn't forward anything
				forwardPrivateChainsToOtherMembersOfSharedAddresses(arrChains, arrAuthorAddresses, from_address, true);
			});
		}
```

**File:** wallet.js (L2520-2533)
```javascript
function forwardPrivateChainsToOtherMembersOfSharedAddresses(arrChainsOfCosignerPrivateElements, arrPayingAddresses, excluded_device_address, bForwarded, conn, onDone){
	walletDefinedByAddresses.readAllControlAddresses(conn, arrPayingAddresses, function(arrControlAddresses, arrControlDeviceAddresses){
		arrControlDeviceAddresses = arrControlDeviceAddresses.filter(function(device_address) {
			return (device_address !== device.getMyDeviceAddress() && device_address !== excluded_device_address);
		});
		walletDefinedByKeys.readDeviceAddressesControllingPaymentAddresses(conn, arrControlAddresses, function(arrMultisigDeviceAddresses){
			arrMultisigDeviceAddresses = _.difference(arrMultisigDeviceAddresses, arrControlDeviceAddresses);
			// counterparties on shared addresses must forward further, that's why bForwarded=false
			walletGeneral.forwardPrivateChainsToDevices(arrControlDeviceAddresses, arrChainsOfCosignerPrivateElements, bForwarded, conn, function(){
				walletGeneral.forwardPrivateChainsToDevices(arrMultisigDeviceAddresses, arrChainsOfCosignerPrivateElements, true, conn, onDone);
			});
		});
	});
}
```
