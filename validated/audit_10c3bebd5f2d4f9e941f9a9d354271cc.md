### Title
Unauthorized Registration as Shared-Address Cosigner Leaks Private Payment Data to Attacker's Device - ([File: wallet_defined_by_addresses.js])

### Summary
The `new_shared_address` hub message handler accepts and persists a shared-address definition and its cosigner-to-device mappings from any already-paired correspondent device, without verifying that the other signers listed actually consented to be part of the shared address. Once registered, `forwardPrivateChainsToOtherMembersOfAddresses` will automatically forward private payment chains for that shared address to every device address stored in `shared_address_signing_paths`, including the attacker-controlled one — an authorization-bypass analogous to the MyFinances IDOR that let one account read another's invoices.

### Finding Description
When a wallet receives a `new_shared_address` device message, it is handled directly by `wallet_defined_by_addresses.handleNewSharedAddress` [1](#0-0) , with no user confirmation dialog, unlike the locally initiated `create_new_shared_address` flow which explicitly requires user approval via an event before creation [2](#0-1) .

`handleNewSharedAddress` only validates cryptographic self-consistency of the submitted data:
- that `body.address` equals the c-hash of `body.definition`,
- that each `signerInfo.address` at a signing path matches the address embedded in the definition at that same path,
- that the sender's own device is included among the signers (`determineIfIncludesMeAndRewriteDeviceAddress`),
- that the definition is a structurally valid definition (`validateAddressDefinition`). [3](#0-2) 

None of these checks verify that the *other* claimed cosigner device addresses in `body.signers` actually agreed to participate, or that the correspondent sending the message has any relationship to those other device addresses. The attacker (any already-paired correspondent) can craft an arbitrary definition where one signing path is the victim's real address and another path is the attacker's own device address, self-consistently satisfying every check, and send it as `new_shared_address`. The wallet will call `addNewSharedAddress` and persist the mapping into `shared_address_signing_paths` unconditionally.

Later, whenever a payment (in particular a private/indivisible or divisible private-asset payment, i.e. the "invoice"-like PII/financial data) is made to or from this shared address, `forwardPrivateChainsToOtherMembersOfAddresses` queries all devices listed in `shared_address_signing_paths` for that shared address and forwards the private payment chain to every one of them: [4](#0-3) 

Because the attacker's device address was accepted into that table without genuine authorization, it now receives the same private payment chain — addresses, amounts, blinding factors — that legitimate cosigners receive, exposing another customer's private financial data to an unrelated party.

### Impact Explanation
This allows an unprivileged device (any existing correspondent) to insert itself as a fabricated "cosigner" of a shared address it has no legitimate claim to, causing the victim's wallet to leak private payment chain data (private asset transfers, indivisible-asset outputs, blinding factors) — sensitive financial/PII data equivalent to the "invoices" in the reference CVE — to the attacker's device without consent. This is an unauthorized access/disclosure of another party's financial data, meeting the Medium severity bar (confidentiality impact, no availability/integrity impact), matching the reference CVSS (C:H/I:N/A:N).

### Likelihood Explanation
The attacker only needs to already be a paired correspondent of the victim (a very low bar, achieved via any legitimate one-time pairing interaction, e.g. a hub bot or business contact), and can then unilaterally send a `new_shared_address` message referencing the victim's real address at one signing path and the attacker's own device address at another. No cryptographic secret of the victim is required to construct such a definition (the check only validates the mathematically consistent structure of the definition itself). No user confirmation step interrupts this flow, unlike other similarly sensitive operations in the same file.

### Recommendation
Before persisting a `new_shared_address` received via the hub (or at minimum before adding *other* devices' entries into `shared_address_signing_paths`), require:
1. Explicit user confirmation (mirroring the `create_new_shared_address`/`approve_new_shared_address` flow) whenever a shared address is proposed by an inbound message rather than composed locally.
2. Verification, where feasible, that the other claimed signer device addresses are known/expected correspondents relevant to this specific relationship, not arbitrary values chosen by the sender.
3. Restricting `forwardPrivateChainsToOtherMembersOfAddresses` to only forward data to device addresses that have been affirmatively confirmed as legitimate cosigners of the address in question.

### Proof of Concept
1. Attacker device A pairs with victim device V (normal one-time pairing).
2. A crafts an address definition `["and", [["address","$address@V"], ["address","$address@A"]]]`-style structure (fully resolved, not a template) whose c-hash is `S`, with `signers = {"r.0": {address: V_addr, device_address: V}, "r.1": {address: A_addr, device_address: A}}`.
3. A sends `new_shared_address` with `{address: S, definition: ..., signers: ...}` to V.
4. V's `handleNewSharedAddress` passes all self-consistency checks and calls `addNewSharedAddress`, storing `A` as a cosigner device for shared address `S` in `shared_address_signing_paths`.
5. When V later makes/receives a private payment involving address `S`, `forwardPrivateChainsToOtherMembersOfAddresses` forwards the private payment chain to device `A`, disclosing private transaction details to the attacker.

Note: full verification of every guard in the pairing/hub message pipeline (e.g., `arrSubjectsAllowedFromNoncorrespondents`) could not be independently confirmed line-by-line for this specific message subject beyond what is shown above; a Devin session with full repository access is recommended to trace all preconditions end-to-end before remediation.

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

**File:** wallet_defined_by_addresses.js (L380-415)
```javascript
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
