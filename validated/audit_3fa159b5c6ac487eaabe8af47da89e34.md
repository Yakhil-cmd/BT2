### Title
Unverified peer-supplied shared-address definition allows a co-signer to trick victims into funding a multisig address they don't actually control - (File: wallet_defined_by_addresses.js)

### Summary
This is the closest reachable analog to the reported "risky multi-step initialization" pattern. In the external report, a wallet's security is only finalized after an external actor performs an additional step (ownership transfer) that is trusted without independent verification. In `ocore`, shared/multisig addresses are likewise "initialized" via a multi-step, peer-to-peer negotiation (`create_new_shared_address` → `new_shared_address` device messages) where the final on-chain address definition is accepted from a counterparty device and trusted as syntactically valid, without verifying that it actually encodes the multi-party control structure the local user believes they agreed to.

### Finding Description
A shared (multisig) address is created collaboratively: one device proposes a definition template, other devices approve it by contributing their own addresses, and the finalized `arrDefinition` is distributed via the `new_shared_address` device message, handled by `handleNewSharedAddress` in `wallet_defined_by_addresses.js`.

`handleNewSharedAddress` only checks:
- that `body.definition` hashes to `body.address` [1](#0-0) 
- that every leaf `["address", ...]` in the definition matches an entry in `body.signers`, and vice versa [2](#0-1) 
- generic definition well-formedness via `validateAddressDefinition`, which explicitly notes it is unfinished ("fix: 1. check that my address is referenced in the definition") [3](#0-2) 

None of these checks verify that the *logical structure* of the definition actually requires cooperation from all expected co-signers (e.g., that it is genuinely an `and`/`r of set` requiring every member's signature) as opposed to an `or`/weighted structure that lets the malicious initiator spend unilaterally while still listing the victim's address somewhere in the tree. The initiator of the shared address fully controls `arrDefinition` (see `approvePendingSharedAddress`, which builds `arrDefinition` from the template and distributes it: `wallet_defined_by_addresses.js:172-219`) and the receiving device (`handleNewSharedAddress` / `addNewSharedAddress`) persists it into `shared_addresses` and starts watching/funding it based purely on this trust [4](#0-3) .

This mirrors the external bug class: initialization/finalization of a multi-party control structure is completed by trusting a message from another party (the "admin"/counterparty) instead of the receiving node cryptographically/structurally verifying that the resulting configuration matches the agreed security model.

### Impact Explanation
If the initiating device crafts a definition where the victim's address appears only in a non-binding branch (e.g. `["or", [["address","$victim"], ["address","$attacker"]]]`) while advertising it to the victim as an "N-of-N" or "2-of-2" escrow/shared wallet, the victim's wallet will accept and fund the address (`addNewSharedAddress`) believing both parties must cooperate to spend. In reality the attacker can spend unilaterally, resulting in direct unauthorized spending/theft of funds sent to the shared address — a concrete "unauthorized spending" outcome per the validation criteria.

### Likelihood Explanation
This requires the attacker to be a paired device / correspondent proposing a shared address to the victim — an unprivileged AA/wallet-message counterparty scenario, no hub/network compromise needed. The victim's UI likely shows the requested template (e.g., "r of set"), but the code path that persists and trusts the *final* definition (`handleNewSharedAddress`) does not independently confirm the final definition still enforces the originally agreed policy; it only checks hash consistency and address/leaf correspondence. Whether the wallet UI additionally cross-checks the final definition against the originally-approved template before funding is not verifiable from the indexed files alone.

### Recommendation
Before accepting and funding a `new_shared_address`, the receiving device should independently re-derive/verify that the final definition is consistent with the definition template it originally approved (substituting only the negotiated addresses into the exact template structure), rather than just checking hash validity and leaf/signer correspondence. This is directly analogous to the report's recommendation to use a canonical factory-style pattern (deriving the final configuration deterministically from a fixed, pre-agreed template) instead of trusting an ad hoc "finalization" message from a counterparty.

### Proof of Concept
Conceptual (cannot be fully executed without the wallet UI/negotiation code, which may not be fully indexed):
1. Attacker (device A) proposes shared-address template `["r of set", {required:2, set:[["address","$address@A"],["address","$address@B"]]}]` to victim (device B), as in `createNewSharedAddressByTemplate` / `sendOfferToCreateNewSharedAddress`.
2. Instead of finalizing with this exact structure, attacker sends a `new_shared_address` message whose `definition` is actually `["or",[["address","<A_address>"],["address","<B_address>"]]]`, but keeps `signers` map populated with both A's and B's address at valid signing paths.
3. `handleNewSharedAddress` on B's device passes all checks (`hash matches`, `signers ↔ address leaves` correspondence, generic `validateAddressDefinition`) since these do not enforce the original "r of set / required:2" semantic promised in step 1. [5](#0-4) 
4. B's wallet calls `addNewSharedAddress`, persists the address, and begins watching/funding it, believing it is a 2-of-2 address. [6](#0-5) 
5. Attacker A can now spend all funds sent to this address alone using the `or` branch, without B's cooperation.

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
