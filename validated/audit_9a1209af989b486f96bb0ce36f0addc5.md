### Title
Missing sender-authorization check on device-address mapping in `handleNewSharedAddress` allows a paired device to hijack co-signer routing for a multisig (shared) address - ([File: wallet_defined_by_addresses.js])

### Summary
`handleNewSharedAddress()` in `wallet_defined_by_addresses.js` processes the `"new_shared_address"` device message and persists a `signing_path → {address, device_address}` map into `shared_address_signing_paths`. It validates the *shape* of the message (definition hashes to the claimed address, each signer's `address` matches the address extracted from that path in the definition, every leaf has a signer) but never validates that the message's authenticated sender (`from_address`) is entitled to assert which device controls *other* members' addresses in the definition. This mirrors the Mattermost bug class: an authorization check is enforced only on the resource the actor legitimately owns (their own address, corrected via `determineIfIncludesMeAndRewriteDeviceAddress`) but not on the linked target field (the `device_address` claimed for other members), letting the actor redirect a legitimate association to an attacker-controlled target.

### Finding Description
The device-message handler dispatch in `wallet.js` routes `"new_shared_address"` directly into `wallet_defined_by_addresses.handleNewSharedAddress(body, callbacks)` without even passing `from_address`: [1](#0-0) 

`handleNewSharedAddress` performs only structural checks: [2](#0-1) 

It then calls `determineIfIncludesMeAndRewriteDeviceAddress`, which only rewrites the `device_address` for signing paths whose `address` is recognized locally as **my own** address (found in `my_addresses` or `shared_addresses`) — it does nothing to validate the `device_address` claimed for *other* member addresses in the definition (e.g., a known correspondent's address): [3](#0-2) 

The (attacker-controlled) `signers` map is then written verbatim into `shared_address_signing_paths` via `addNewSharedAddress`: [4](#0-3) 

`shared_address_signing_paths.device_address` is the authoritative local record of *which device to contact when a co-signature is needed* for a given member of a shared/multisig address (used by signing-request routing such as in `wallet.js`'s signing-request flow and shared-address payment composition). Because the mapping for non-self members is accepted from any paired device without checking it against the real correspondent who controls that address, a malicious paired device can:
1. Construct (or reuse) a multisig definition that includes a real, funded shared address in which the victim participates together with another real cosigner, and
2. Send `"new_shared_address"` claiming that the other cosigner's address is controlled by the attacker's own `device_address`.

The victim's wallet will overwrite/insert this mapping without ever confirming with the real cosigner or verifying sender authority over that entry.

### Impact Explanation
Once the signer routing table is poisoned, subsequent attempts to spend from the affected shared address will send co-signing requests to the attacker's device instead of the legitimate cosigner's device. The attacker cannot forge a valid signature (on-chain definition/signature validation in `definition.js`/`validation.js` still enforces real cryptographic authorization for spending), so this is not a direct signature-forgery bypass. However, it does allow the attacker to:
- Intercept and observe pending transaction details intended for a legitimate cosigner (information disclosure), and
- Silently drop/never respond to co-signing requests, causing the legitimate multisig owner's transaction flow to stall — a funds-freezing / denial of service on an existing multisig address's ability to confirm new spending transactions, since the wallet no longer knows the correct device to solicit a signature from.

This is a lower-severity variant of the reported CVE's bug class (authorization enforced on the actor's own object but not on the linked target field), rather than a directly exploitable fund-theft or double-spend primitive, because ocore's cryptographic authorization for actual spending is independent of this local routing table.

### Likelihood Explanation
Any already-paired device (a normal, low-privilege relationship in ocore's wallet-pairing model) can send this message at will; no special permission beyond being a correspondent is required, and the check that would need to exist (verifying that the claimed `device_address` for a non-self member actually corresponds to a real correspondent/cosigner) is absent.

### Recommendation
In `handleNewSharedAddress` (or `determineIfIncludesMeAndRewriteDeviceAddress`), require that the `device_address` claimed for any member address other than "my own" addresses be corroborated (e.g., only accept/overwrite an existing mapping if it originates from, or is confirmed by, the device that legitimately owns that address, or restrict updates to first-time creation and require explicit local user confirmation before altering routing for an address that is not controlled by the sender).

### Proof of Concept
Exact routing/overwrite semantics of `shared_address_signing_paths` (e.g., whether `INSERT OR IGNORE` silently skips updates when a row for `(shared_address, signing_path)` already exists) could not be fully confirmed in this session — the schema file content for that table was not retrieved before the session ended, so I cannot state with certainty whether this also allows hijacking of an *already established* signer mapping versus only first-time registration of a shared address. This should be verified directly by inspecting `initial-db/byteball-sqlite.sql` (`shared_address_signing_paths` table definition) and by tracing all writers/readers of that table before finalizing remediation.

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

**File:** wallet_defined_by_addresses.js (L377-405)
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
```
