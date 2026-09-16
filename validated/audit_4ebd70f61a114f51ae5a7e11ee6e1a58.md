### Title
Unauthenticated identity injection into shared-address signing-path records via `new_shared_address` device message - ([File: wallet_defined_by_addresses.js])

### Summary
The `rancher-webhook` bug allowed an unauthenticated caller to submit a crafted admission payload that made the webhook's mutating side-effect path create Kubernetes objects with attacker-chosen identity data — the payload's cryptographic/structural checks passed, but a piece of "identity" metadata used later for authorization was never independently validated and was trusted verbatim. The same bug class exists in ocore's `handleNewSharedAddress` / `addNewSharedAddress` path in `wallet_defined_by_addresses.js`: the `definition` is checked cryptographically, but the `device_address` field inside `body.signers` — which becomes the trusted routing/identity record used for all future signing requests and private-payment forwarding for that shared address — is accepted from the sending peer with no proof of control over that device address.

### Finding Description
When a peer sends a `new_shared_address` device message, `wallet.js` case `"new_shared_address"` forwards `body` directly into `walletDefinedByAddresses.handleNewSharedAddress(body, ...)` [1](#0-0) .

`handleNewSharedAddress` validates that:
- `body.definition` hashes to `body.address` (cryptographic binding of the address itself), and
- for every signing path, the `address` component of `signerInfo` matches the address extracted from the definition tree via `extractAddressPathsFromDefinition`. [2](#0-1) 

However, `signerInfo.device_address` (the field asserting *which correspondent device* is responsible for/reachable for that member address) is never checked against anything — it is not derived from the definition, not verified to belong to the peer sending the message, and not required to match any existing `correspondent_devices` record. It is accepted as-is and stored via `addNewSharedAddress`: [3](#0-2) 

The only self-referential check performed is `determineIfIncludesMeAndRewriteDeviceAddress`, which merely rewrites the caller's *own* device_address when the local address belongs to `my_addresses`/`shared_addresses` — it never validates device_address values for *other* signing paths [4](#0-3) .

This `device_address` value becomes the trust anchor for later, sensitive operations on this shared address:
- `forwardNewSharedAddressToCosignersOfMyMemberAddresses` and `forwardPrivateChainsToOtherMembersOfAddresses` use `shared_address_signing_paths.device_address` to decide which device receives forwarded private-payment chains and shared-address propagation messages [5](#0-4) [6](#0-5) .
- `readAllControlAddresses` walks `shared_address_signing_paths` to compute the set of device addresses that are treated as legitimate controllers/co-signers of a shared address [7](#0-6) .

Because an attacker (any correspondent device that can send this message — the message is handled generically for indirect correspondents too, per `handleMessageFromHub`) fully controls `body.signers[path].device_address` for every path except the one bound to their own address, they can register arbitrary device addresses (including real third-party correspondent device addresses, or self-controlled ones) as "cosigner devices" for a shared address whose other member address they don't actually control the private key material of the routing metadata for. This is exactly the CVE's pattern: the object's cryptographic identity (`address`↔`definition` hash) is validated, but a separate identity/authorization field carried in the same payload (`device_address`↔"who is allowed to receive/route for this member") is trusted blindly and persisted as if legitimate.

### Impact Explanation
Once malicious `shared_address_signing_paths` rows are inserted, the local node will treat the attacker-designated device as an authorized cosigner for the shared (multisig) address:
- Private payment chains for the shared address can be forwarded to the attacker-controlled/attacker-named device (`forwardPrivateChainsToOtherMembersOfAddresses`), leaking private-payment payloads (inputs/outputs/blinding) intended only for legitimate members.
- `readAllControlAddresses`/signature-request flows (`wallet.js` "sign" case, `findAddress`) rely on this table to determine who may be asked to co-sign spends from the shared address, enabling attacker-influenced routing of signing requests and confusing nodes about which addresses/devices legitimately control funds in the shared multisig — a form of AA/wallet fund-control identity confusion that can enable unauthorized signature requests or misdirected private data disclosure for a shared address a node is a member of.

This does not directly forge signatures (funds still require valid keys per the `Definition`), but it corrupts the local routing/identity metadata used to manage a payment address controlled by multiple parties, which can lead to loss of confidentiality of private payments and confusion in the node's determination of legitimate co-signers — a Medium-severity node-disagreement/identity-injection issue analogous to the reported CVE.

### Likelihood Explanation
Reachable by any paired/correspondent device (including indirect correspondents, per the comment in `handleMessageFromHub` allowing several message types through even for indirect correspondents) sending a single `new_shared_address` message with a valid definition but attacker-chosen `device_address` values for other signing paths. No privileged access or prior trust beyond being a device-message peer is required, matching the "unauthenticated/low-authorization actor triggers unauthorized identity-bearing object creation" class from the CVE.

### Recommendation
- Require that `device_address` values in `body.signers` be independently verifiable — e.g., only accept the sender's own `device_address` for the signing path proven to be the peer's own address, and require an explicit approval/pairing handshake (already used for `approve_new_shared_address` in the "create" flow) for device_address bindings of other members, rather than trusting values embedded in the `new_shared_address` propagation message.
- Cross-check any inserted `device_address` against `correspondent_devices` and existing pairing/approval records before persisting `shared_address_signing_paths`.
- Consider signing the `signers` map (device_address ↔ address bindings) as part of the address-creation approval protocol so that recipients can cryptographically verify the binding rather than accept it from a forwarding message.

### Proof of Concept
1. Attacker device A pairs with victim node V (a normal, low-trust correspondent pairing).
2. Attacker crafts a valid multi-signature address `definition` whose leaves reference addresses that resolve to victim's own local `my_addresses`/`shared_addresses` for some signing path, and attacker's own address for another path (satisfying `extractAddressPathsFromDefinition` matching check).
3. Attacker sends `new_shared_address` with `body.signers` mapping the victim's signing path to an arbitrary `device_address` chosen by the attacker (e.g., a third victim's device address, or a device it controls) instead of the true correspondent.
4. `handleNewSharedAddress` passes all checks (definition hash matches, path/address correspondence matches) and calls `addNewSharedAddress`, which inserts the attacker-chosen `device_address` into `shared_address_signing_paths` unconditionally [3](#0-2) .
5. Subsequent operations on this shared address (private payment forwarding, cosigner lookups) now use the attacker-injected `device_address` as though it were a legitimate cosigner device, per [6](#0-5)  and [7](#0-6) .

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

**File:** wallet_defined_by_addresses.js (L239-252)
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

**File:** wallet_defined_by_addresses.js (L545-561)
```javascript
function readAllControlAddresses(conn, arrAddresses, handleLists){
	conn = conn || db;
	conn.query(
		"SELECT DISTINCT address, shared_address_signing_paths.device_address, (correspondent_devices.device_address IS NOT NULL) AS have_correspondent \n\
		FROM shared_address_signing_paths LEFT JOIN correspondent_devices USING(device_address) WHERE shared_address IN(?)", 
		[arrAddresses], 
		function(rows){
			if (rows.length === 0)
				return handleLists([], []);
			var arrControlAddresses = rows.map(function(row){ return row.address; });
			var arrControlDeviceAddresses = rows.filter(function(row){ return row.have_correspondent; }).map(function(row){ return row.device_address; });
			readAllControlAddresses(conn, arrControlAddresses, function(arrControlAddresses2, arrControlDeviceAddresses2){
				handleLists(_.union(arrControlAddresses, arrControlAddresses2), _.union(arrControlDeviceAddresses, arrControlDeviceAddresses2));
			});
		}
	);
}
```
