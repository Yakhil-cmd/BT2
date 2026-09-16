### Title
Shared-address peer can inject arbitrary `device_address` for co-signer member addresses, causing private payment data to be routed/leaked to an attacker-controlled device - (File: wallet_defined_by_addresses.js)

### Summary
When a correspondent proposes a new shared (multi-signature) address via the `new_shared_address` device message, `handleNewSharedAddress()` validates that the *definition* hashes to the claimed address and that each `signers[path].address` matches the address embedded at that path in the definition, but it never verifies that the `device_address` claimed for a *co-signer's* member address is the device that actually controls that address. That attacker-supplied `device_address` is persisted into `shared_address_signing_paths` and is later used by `forwardPrivateChainsToOtherMembersOfAddresses()` to decide which device(s) to forward private-payment chain data to when the shared address participates in a private-asset transaction. This is directly analogous to the Saleor bug, where an unprivileged actor could overwrite address/ownership data associated with a shared resource (the pickup warehouse), which was later disclosed to a party who should not have received it.

### Finding Description
`handleNewSharedAddress(body, callbacks)` in `wallet_defined_by_addresses.js` (lines 378-415) is reachable from an unprivileged device message sent by any paired correspondent (the `new_shared_address` subject, dispatched from `wallet.js`'s `handleMessageFromHub`). It performs these checks:
- `body.definition` hashes to `body.address` [1](#0-0) 
- Each `signers[path].address` is a valid address [2](#0-1) 
- Each `signers[path].address` matches the address literal found at that path inside `body.definition` via `extractAddressPathsFromDefinition` [3](#0-2) 

Crucially, there is **no check binding `signers[path].device_address` to the actual owner of `signers[path].address`**. The only place device ownership is ever corrected is `determineIfIncludesMeAndRewriteDeviceAddress()`, and that function only rewrites the device address when the address belongs to **me** (`arrMyMemberAddresses`, derived from my own `my_addresses`/`shared_addresses` tables) [4](#0-3) . For every other co-signer's member address, the `device_address` value supplied by the (possibly malicious) sender is trusted verbatim and passed into `addNewSharedAddress()`, which writes it directly into the `shared_address_signing_paths` table: `(shared_address, address, signing_path, member_signing_path, device_address)` [5](#0-4) .

This attacker-controlled `device_address` value is later relied upon as routing/authorization information for private data. `forwardPrivateChainsToOtherMembersOfAddresses()` selects the set of devices to which a private payment chain (containing amounts, blinding factors, and addresses of the transaction) will be forwarded by joining `shared_address_signing_paths` to `correspondent_devices` on `device_address`:
```
"SELECT device_address FROM shared_address_signing_paths \n\
JOIN correspondent_devices USING(device_address) WHERE shared_address IN(?) AND device_address!=?"
``` [6](#0-5) 
and then calls `walletGeneral.forwardPrivateChainsToDevices(arrDeviceAddresses, arrChains, ...)`.

Because the attacker (any correspondent who can send a `new_shared_address` message) controls which `device_address` is stored for a co-signer's address, the attacker can register their own device (or any device address they control that they've paired with the victim as a correspondent) as the routing target for a legitimate member address of the shared address. When private-asset payments later flow through this shared address (e.g. a private token/asset payment received by or sent from the shared address), `forwardPrivateChainsToOtherMembersOfAddresses`/`handlePrivatePaymentChains` will forward the full private-payment chain — output addresses, amounts, and blinding factors of the counterparty transaction — to the attacker's device instead of (or in addition to) the legitimate co-signer, even though the attacker never actually controls the signing key for that member address.

This mirrors the Saleor root cause exactly: an unprivileged party supplies data (in Saleor: an address; here: a `device_address`/routing binding) associated with a shared/multi-party resource (in Saleor: the click-and-collect warehouse; here: the shared multisig address), and the application persists and later discloses private data (in Saleor: the customer's address; here: the private payment chain) to whichever party is currently bound to that resource — without validating that the binding was set by the resource's legitimate owner.

### Impact Explanation
This is a private-data leak: the confidential contents of a private-asset payment chain (sender/receiver addresses, amounts, and blinding factors used in private payments/blackbytes and other private divisible/indivisible assets) can be disclosed to a device that has no legitimate right to that shared address's signing key, purely because it claimed a `device_address` binding in an unauthenticated `new_shared_address` proposal. It qualifies as unauthorized disclosure of private-payment information reachable from a normal correspondent/peer (no operator, hub, or node privilege required), matching the "private payment chains" and "AA/wallet message handling" categories called out as in-scope.

### Likelihood Explanation
Exploitation requires only that the victim be paired as a correspondent with the attacker (a routine, low-friction wallet operation) and that the attacker propose (or forward) a shared-address definition in which the victim is a member alongside an address the attacker falsely claims to control via their own `device_address`. The victim's wallet automatically calls `handleNewSharedAddress` → `addNewSharedAddress` upon receiving this unsolicited message; no further victim interaction/approval step for the *device_address* bindings is required by this code path (the checks are limited to hash/address consistency, not device ownership). Any subsequent private payment involving that shared address triggers the leak automatically via `forwardPrivateChainsToOtherMembersOfAddresses`.

### Recommendation
- In `handleNewSharedAddress`/`addNewSharedAddress`, do not trust attacker-supplied `device_address` values for co-signer member addresses. Only accept a `device_address` binding for an address that the local node cannot independently verify if it comes from a trusted/pre-established mapping (e.g. previously exchanged via `sendSharedAddressToPeer`/`approvePendingSharedAddress` flow, which is peer-approved per signing path) — reject or flag `device_address` claims for member addresses that are not "my" addresses when they arrive through unsolicited/forwarded `new_shared_address` messages from a single proposer.
- When forwarding private payment chains, additionally verify that the receiving `device_address` is corroborated by more than one source, or restrict forwarding to devices that were independently confirmed as owning the corresponding signing path (e.g., only forward to a device that has previously signed with the claimed address, or only to the device that sent the "approve" message during shared-address creation, as in `approvePendingSharedAddress`).
- Add a lower-severity audit log / user-facing warning when a shared address's `device_address` binding changes for a non-owned member address, since this is unusual and indicates possible malicious reassignment.

### Proof of Concept
1. Attacker Mallory pairs with Victim Alice as a device correspondent (normal wallet pairing flow).
2. Mallory sends Alice a `new_shared_address` device message (subject handled in `wallet.js`, dispatched to `wallet_defined_by_addresses.handleNewSharedAddress`):
   ```
   {
     address: <chash160 of below definition>,
     definition: ["and", [
       ["address", "ALICE_ADDR"],
       ["address", "BOB_REAL_MEMBER_ADDR"]
     ]],
     signers: {
       "r.0": { address: "ALICE_ADDR", device_address: <Alice's own device address> },
       "r.1": { address: "BOB_REAL_MEMBER_ADDR", device_address: <MALLORY'S device address> }
     }
   }
   ```
   Here `BOB_REAL_MEMBER_ADDR` is a real address belonging to some third party Bob who actually co-owns this shared address (e.g. Alice already knows of this shared address independently, or Mallory fabricates a shared address where Bob is a genuine but not-yet-registered member on Alice's node).
3. `handleNewSharedAddress` validates definition-hash and address-vs-path consistency (both satisfied, since Mallory controls the whole message and only needs `BOB_REAL_MEMBER_ADDR` to be a syntactically valid address matching the literal in the definition) [7](#0-6) .
4. `determineIfIncludesMeAndRewriteDeviceAddress` only rewrites the device address bound to `ALICE_ADDR` (Alice's own address); the `BOB_REAL_MEMBER_ADDR → MALLORY'S device address` binding passes through untouched [4](#0-3) .
5. `addNewSharedAddress` writes `(shared_address, BOB_REAL_MEMBER_ADDR, "r.1", null, MALLORY'S device address)` into `shared_address_signing_paths` [8](#0-7) .
6. Later, Alice receives or sends a private-asset payment through this shared address. `forwardPrivateChainsToOtherMembersOfAddresses` queries `shared_address_signing_paths JOIN correspondent_devices` and forwards the full private payment chain (addresses, amounts, blinding factors) to Mallory's device address instead of Bob's [6](#0-5) , leaking the private transaction data to Mallory.

Note: Full confirmation of exploitability under all edge cases (e.g., whether an additional confirmation dialog is shown to the user before `addNewSharedAddress` is invoked in the GUI wallet layer, which sits outside `ocore` and wasn't part of this indexed code) is not verifiable purely from `ocore`; the vulnerable trust gap described above is confirmed at the `ocore` library level in the functions cited.

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

**File:** wallet_defined_by_addresses.js (L281-314)
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
