### Title
Unauthenticated `new_shared_address` device message lets any paired peer register itself as a signer/device for someone else's address - ([File: wallet_defined_by_addresses.js])

### Summary
`handleNewSharedAddress()` in `wallet_defined_by_addresses.js` (invoked directly from the `new_shared_address` device-message handler in `wallet.js`) accepts an attacker-controlled `signers` map and persists it verbatim, without ever verifying that the sending device is actually authorized to declare a `device_address` for the addresses referenced in the shared-address definition. This mirrors the Sentiment `openAccount(owner)` bug class: a privileged mapping (owner→account / address→device) is mutated using a caller-supplied identifier with no check that the caller actually controls that identifier.

### Finding Description
`wallet.js` routes any `new_shared_address` message from a paired correspondent straight into: [1](#0-0) 

`handleNewSharedAddress` validates only structural consistency of the message (definition hashes to the given address, and each signer's `address` field matches the corresponding leaf in the definition tree), but never checks that the `device_address` supplied for a given member `address` is the device that actually controls/owns that address: [2](#0-1) 

The only "ownership" check performed is `determineIfIncludesMeAndRewriteDeviceAddress`, which merely (a) verifies *my own* address/device is somewhere in the signer set, and (b) rewrites the device_address entry to my own device only for addresses I recognize as mine. It performs no validation of the device_address claimed for *other* (non-mine) member addresses — those are trusted as-is from the attacker's message: [3](#0-2) 

Consequently, `addNewSharedAddress` persists `shared_address_signing_paths` rows binding an arbitrary victim address to an attacker-chosen `device_address`, exactly as the Sentiment bug persisted an `inactiveAccountsOf[owner]` reactivation from an unauthorized caller: [4](#0-3) 

This `device_address` binding subsequently drives forwarding of private payment chains to "cosigners" of a shared address: [5](#0-4) 

An attacker (any node that is merely a paired correspondent — reachable without any special privilege, consistent with the "wallet and contract message handling" surface) can:
1. Take a real, previously-observed address of a victim (e.g., learned from a public unit) and build a definition such as `["and", [["address", victim_address], ["address", attacker_address]]]`, or embed the victim's address as one branch of an `"or"`.
2. Send `new_shared_address` with `signers` claiming `device_address: <attacker's device>` for the victim's address path.
3. The victim's own node is not necessarily involved at all — the attacker sends this message to a third node (e.g., his own second device, or any node he controls) which will happily store the association since none of the checks require the addressed victim's device to confirm anything.

### Impact Explanation
The concrete confirmable damage is a private-payment / metadata disclosure and node-state corruption issue: any node that processes such a message will believe the attacker's device is a legitimate co-signer/device for the victim's address inside this newly-declared shared address, and will subsequently forward private payment chains addressed to that shared address to the attacker's device (`forwardPrivateChainsToOtherMembersOfAddresses`). Because private-payment forwarding and definitions can affect what information (potentially including previously private amounts/asset chains) is disclosed to unauthorized parties, and because the mapping is persisted with no way for the victim to reject/detect it, this satisfies the "private payment chains" disclosure class the rules call out. It also causes durable node-state corruption analogous to the "account hijack" scenario in the source finding: a table (`shared_address_signing_paths`) meant to reflect consensual multi-party address definitions is populated with unverified, attacker-supplied bindings.

### Likelihood Explanation
Likelihood is high for triggering the flawed logic itself: the message handler is reachable by any paired device with no special privilege and requires only a definition array whose chash equals the declared address — trivially constructible using any already-known valid address as one leaf of an `"and"/"or"` definition. The main uncertainty (not fully verifiable from the indexed code alone) is exactly how far-reaching the practical fund-loss consequences are, since actually spending funds under `shared_addresses` still requires all real cosigners' valid signatures per the `definition.js` evaluation logic — so this analog is best characterized as unauthorized state mutation / private-data-forwarding, not unauthorized fund transfer.

### Recommendation
In `handleNewSharedAddress` (and `determineIfIncludesMeAndRewriteDeviceAddress`), do not accept unauthenticated claims about `device_address` for addresses that are not the local wallet's own. At minimum:
- Require an explicit, signed approval flow (similar to `approvePendingSharedAddress`) for every member address rather than accepting the fully-assembled `new_shared_address` message from an arbitrary correspondent as authoritative.
- Reject/ignore `device_address` bindings for member addresses that the local node doesn't recognize as its own and that weren't confirmed via the offer/approve handshake (`create_new_shared_address` → `approve_new_shared_address`), rather than trusting a directly pushed `new_shared_address` payload from any peer.

### Proof of Concept
1. Attacker learns `victim_address` (any address that appeared on the public DAG).
2. Attacker crafts `arrDefinition = ["and", [["address", victim_address], ["address", attacker_address]]]` and computes `address = chash160(arrDefinition)`.
3. Attacker sends a `new_shared_address` device message to any paired node (could be the attacker's own second wallet instance, or a victim/third-party node) with:
   ```
   {
     address: <computed address>,
     definition: arrDefinition,
     signers: {
       "r.0": { address: victim_address, device_address: attacker_device_address },
       "r.1": { address: attacker_address, device_address: attacker_device_address }
     }
   }
   ```
4. `handleNewSharedAddress` passes all structural checks (definition hash matches, signer addresses match definition leaves), and calls `addNewSharedAddress`, persisting `shared_address_signing_paths` rows that bind `victim_address` to `attacker_device_address` without any confirmation from the victim.
5. Any subsequent call to `forwardPrivateChainsToOtherMembersOfAddresses` for this shared address forwards private payment data to the attacker's device.

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
