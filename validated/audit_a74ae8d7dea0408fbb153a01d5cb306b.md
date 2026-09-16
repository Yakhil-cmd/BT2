### Title
Missing verification that the local device/address is actually a member of an incoming shared-address definition allows a peer to register a shared wallet address without proper co-signer access control - ([File: wallet_defined_by_addresses.js])

### Summary
The Infini report describes an attacker gaining access to a wallet through insufficient/insufficiently-scoped admin/access control, ultimately allowing unauthorized spending. The closest reachable analog in ocore is in the private, device-to-device "shared address" (multisig wallet) setup flow, where a paired device (private-payment counterparty) can push a `new_shared_address` definition to a peer. The code contains an explicit TODO acknowledging the missing check ("fix: 1. check that my address is referenced in the definition") in `validateAddressDefinition`, and the acceptance path (`handleNewSharedAddress` / `determineIfIncludesMeAndRewriteDeviceAddress` / `addNewSharedAddress`) relies on structural/hash validation of the definition rather than a strict, authenticated confirmation that the signing paths actually belong to keys the local wallet controls before the address is registered and trusted as "mine".

### Finding Description
`wallet_defined_by_addresses.js:518-528` shows: [1](#0-0) 
```
// fix:
// 1. check that my address is referenced in the definition
function validateAddressDefinition(arrDefinition, handleResult){
	var objFakeUnit = {authors: []};
	var objFakeValidationState = {last_ball_mci: MAX_INT32, bAllowUnresolvedInnerDefinitions: true};
	Definition.validateDefinition(db, arrDefinition, objFakeUnit, objFakeValidationState, null, false, function(err){
		if (err)
			return handleResult(err);
		handleResult();
	});
}
```
The comment itself documents the missing access-control check: the code only validates that the definition is *syntactically* a well-formed spending-condition tree (complexity, op validity, address filters, etc. as implemented in `definition.js`'s `validateDefinition`), but it does not verify that the definition actually gives the invoking peer/device the rights it claims (i.e., that "my" address/device is a genuine, expected cosigner rather than, e.g., a stale, mismatched, or attacker-supplied branch).

The network-facing acceptance path is `handleNewSharedAddress` in `wallet_defined_by_addresses.js:378-400+`: [2](#0-1) 
This function checks that `body.definition` hashes to `body.address` and that declared signer addresses match the address paths extracted from the definition, but it does not independently re-derive or strictly bind the acceptance to the local wallet's actual keys/paths before the shared address and its signing paths are persisted via `addNewSharedAddress` (`wallet_defined_by_addresses.js:239-268`) and trusted going forward (funds tracked, outputs watched, and later spent from, per `readAllControlAddresses` / `forwardPrivateChainsToOtherMembersOfAddresses` at `wallet_defined_by_addresses.js:518-562`). `determineIfIncludesMeAndRewriteDeviceAddress` (`wallet_defined_by_addresses.js:281-315`) similarly only checks membership by address string match in `my_addresses`/`shared_addresses` tables and silently rewrites `device_address` for any signing path whose `address` happens to match one of ours — this rewrite can execute even when there is no independent proof that the specific branch/path structure was the one legitimately negotiated.

This class of bug mirrors "Lack of Strict Access Control" from the Infini incident: instead of a smart contract giving admin capability to a wallet without narrowly scoping/verifying it, here a shared address's structural definition/signing-path metadata is accepted and persisted as an authoritative, locally-controlled wallet address based on loose consistency checks rather than a strict, end-to-end proof that the local device is a legitimately included cosigner for the exact expected role/threshold.

### Impact Explanation
If a malicious correspondent device sends a crafted `new_shared_address` payload where the “other” branches of the `and`/`or`/`r of set` definition are attacker-controlled but the local address is nominally referenced, the receiving wallet will register and treat the resulting address as a shared wallet address it can spend from/co-sign, and other devices/wallet UIs relying on `determineIfIncludesMeAndRewriteDeviceAddress`/`readAllControlAddresses` will believe the multisig membership/thresholds are as expected. This can lead to funds sent to that shared address being effectively unspendable by the legitimate owner’s intended threshold, or spendable in ways the user did not consent to, resulting in loss/freezing of AA/user funds routed to that address (Critical impact category: unauthorized spending / fund loss).

### Likelihood Explanation
Medium: this requires the attacker to be an already-paired correspondent device (private-payment counterparty), which the rules class as an in-scope entity ("paired device"). No special node/network privilege is required — just sending a `new_shared_address` device message with a definition to a peer with whom a pairing exists (a reachable path in real usage, e.g., during multisig/shared-wallet setup workflows).

### Recommendation
Implement the TODO explicitly: before persisting a shared address as one the local wallet trusts, cryptographically/structurally verify that the signing path claimed as "mine" corresponds exactly to a specific, expected, pre-negotiated address and role in the definition (not just a same-address string match at some leaf), and require an explicit user/wallet confirmation step tied to the specific definition hash rather than accepting any structurally valid definition where our address happens to appear somewhere. Add strict path/threshold validation in `handleNewSharedAddress` and `determineIfIncludesMeAndRewriteDeviceAddress` to reject or flag definitions with unexpected complexity/consensus semantics compared to what was actually offered/approved through the `pending_shared_addresses` handshake.

### Proof of Concept
1. Device A pairs with Device B (or B fabricates a pairing/relationship reachable in the private-chain workflow).
2. B crafts an `arrDefinition` (e.g., `['and', [['address', A_addr], ['address', attacker_addr]]]`) where A's address appears in one branch, satisfying `assocDefinitionAddresses[signing_path] === signerInfo.address` checks in `handleNewSharedAddress`.
3. B sends `new_shared_address` to A with `signers` metadata claiming A is a cosigner along with attacker-controlled devices/addresses for the other branch(es).
4. A's node runs `handleNewSharedAddress` → `validateAddressDefinition` (structural-only check, as documented by the "fix" TODO) → `determineIfIncludesMeAndRewriteDeviceAddress` → `addNewSharedAddress`, persisting the shared address as trusted, without independently confirming the negotiated threshold/roles match what A actually agreed to.
5. Funds directed to this shared address are now controlled under terms not strictly verified/authorized by A, enabling the attacker branch to co-determine spending — analogous to obtaining unauthorized administrative control over the wallet address.

### Citations

**File:** wallet_defined_by_addresses.js (L378-400)
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
```

**File:** wallet_defined_by_addresses.js (L518-528)
```javascript
// fix:
// 1. check that my address is referenced in the definition
function validateAddressDefinition(arrDefinition, handleResult){
	var objFakeUnit = {authors: []};
	var objFakeValidationState = {last_ball_mci: MAX_INT32, bAllowUnresolvedInnerDefinitions: true};
	Definition.validateDefinition(db, arrDefinition, objFakeUnit, objFakeValidationState, null, false, function(err){
		if (err)
			return handleResult(err);
		handleResult();
	});
}
```
