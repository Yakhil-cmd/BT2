Based on my investigation, the closest analog to the ZITADEL bug (a party that shares a related object — the session ID / the payment address — is able to trigger a state-changing action without the system verifying that party is actually an authorized principal for that object) exists in ocore's device‑message handling for shared/multisig addresses.

### Title
Missing cosigner-authorization check lets any correspondent device request signing on a shared address it does not own - ([File: wallet.js])

### Summary
The `sign` device-message handler in `wallet.js` accepts a signing request for any address that resolves locally (`findAddress`'s `ifLocal` callback), but the code that would verify the requester (`from_address`) is actually a registered cosigner of that address is explicitly disabled/commented out.

### Finding Description
When a peer device sends a `"sign"` message, `wallet.js` validates the unit's structure, payload hashes, and that `body.address` is present among `objUnit.authors`, then calls `findAddress(body.address, body.signing_path, ...)`. In the `ifLocal` branch, the code that would check that the sender is a legitimate cosigner of the address is explicitly commented out: [1](#0-0) 

The comment states the check "would make multilateral signing impossible" — i.e., the authorization step (verifying `from_address` is actually a member of `extended_pubkeys`/`shared_address_signing_paths` for the target address/wallet) was intentionally removed, rather than replaced with a correct, narrower check that scopes the permission to legitimate cosigners of that specific shared address. This mirrors the ZITADEL flaw: the session/API endpoint accepted the caller's identity as sufficient without verifying the caller is authorized to act on the specific target resource (`objContract`/session ID there, address/signing_path here).

Compare this to `wallet_defined_by_addresses.js`, where similar shared-address flows (`handleNewSharedAddress`, `createNewSharedAddress`) only check that *my own* device is referenced somewhere in the proposed definition via `determineIfIncludesMeAndRewriteDeviceAddress`: [2](#0-1) [3](#0-2) 
This accepts an externally supplied definition and signer map without confirming the request came from a device previously invited to co-create that specific shared address — any paired correspondent who knows one of my addresses can push a shared-address record into my wallet.

### Impact Explanation
An attacker who is a correspondent (paired device) of the victim — which requires only mutual pairing, not any special privilege — can:
1. Send a `"sign"` request for `body.address` set to any address the victim's wallet locally controls (a plain address or one leg of a shared/multisig address the victim participates in), with a `signing_path` and `unsigned_unit` of the attacker's choosing.
2. Because the cosigner-membership check is disabled, the wallet will proceed to the signing flow for that address as long as `findAddress` resolves it locally, without confirming the attacker is actually one of the wallet's legitimate cosigning peers for that address.
3. Similarly, `handleNewSharedAddress`/`addNewSharedAddress` in `wallet_defined_by_addresses.js` let any correspondent inject an attacker-crafted shared-address definition (e.g., an `"or"` combination naming the victim's real address and an attacker address) into the victim's `shared_addresses` table, potentially misleading the wallet/UI into treating funds sent there as protected multisig funds when the attacker alone can spend them.

Together these allow unauthorized signing requests and unauthorized creation of shared-address entries that were never approved via the intended pairing/negotiation flow, which can lead to unauthorized spending or the victim being tricked into funding an address effectively controlled by the attacker.

### Likelihood Explanation
Exploitation requires only that the attacker be a paired correspondent of the victim device (a lightweight, commonly satisfied prerequisite in Obyte wallets, and for several subjects like `"pairing"`, `"my_xpubkey"`, `"wallet_fully_approved"` even non-correspondents are allowed per `device.js`'s `arrSubjectsAllowedFromNoncorrespondents`). No knowledge of private keys or special node privileges is needed — only knowledge of a target address, which is public on the DAG.

### Recommendation
Restore and correctly scope the cosigner-authorization check in the `sign` handler: before proceeding, verify `from_address` is a listed member (`shared_address_signing_paths.device_address` or `extended_pubkeys.device_address`) for the specific shared address/wallet associated with `body.address` and `body.signing_path`. In `wallet_defined_by_addresses.js`, require that a shared address only be accepted from a device that was part of a prior mutually-negotiated offer/approval flow (e.g., matching a `pending_shared_addresses`/`pending_shared_address_signing_paths` record), rather than accepting any externally supplied definition merely because it happens to reference one of the recipient's own addresses.

### Proof of Concept
Conceptual PoC (cannot be executed without live wallet instances):
1. Attacker pairs with victim's wallet device as a normal correspondent.
2. Attacker learns victim's address `V` (public on DAG) that is part of a shared/multisig address, or any local address of the victim.
3. Attacker sends a `"sign"` device message: `{address: V, signing_path: "r.0", unsigned_unit: {...attacker-chosen outputs...}}`.
4. Victim's `wallet.js` `case "sign"` reaches `findAddress(...).ifLocal`, and because the disabled check at `wallet.js:335-338` would have verified cosigner membership, the flow proceeds without confirming the attacker is entitled to request a signature involving `V`.
5. Separately, attacker sends `"new_shared_address"` with `{address: A, definition: ["or", [["address", V], ["address", AttackerAddr]]], signers: {...}}`; `handleNewSharedAddress` in `wallet_defined_by_addresses.js` accepts it because `V` belongs to the victim, inserting attacker-controlled address `A` into the victim's `shared_addresses` table without any prior negotiated approval.

### Citations

**File:** wallet.js (L331-339)
```javascript
				// findAddress handles both types of addresses
				findAddress(body.address, body.signing_path, {
					ifError: callbacks.ifError,
					ifLocal: function(objAddress){
						// the commented check would make multilateral signing impossible
						//db.query("SELECT 1 FROM extended_pubkeys WHERE wallet=? AND device_address=?", [row.wallet, from_address], function(sender_rows){
						//    if (sender_rows.length !== 1)
						//        return callbacks.ifError("sender is not cosigner of this address");
							callbacks.ifOk();
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
