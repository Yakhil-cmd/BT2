### Title
Missing ownership verification allows any correspondent device to delete another user's pending shared-address negotiation - (File: wallet_defined_by_addresses.js)

### Summary
The `reject_new_shared_address` device-message handler in `wallet.js` forwards the caller-supplied `address_definition_template_chash` directly into `walletDefinedByAddresses.deletePendingSharedAddress()` without verifying that the authenticated sender (`from_address`) is actually one of the parties referenced in `pending_shared_address_signing_paths` for that template. This mirrors the reported Langflow IDOR pattern: an identifier supplied by an authenticated-but-unrelated caller is used to delete a resource without checking that the caller owns/is a party to it.

### Finding Description
In `wallet.js`, the `handleMessageFromHub` switch contains: [1](#0-0) 
```
case "reject_new_shared_address":
    // {address_definition_template_chash: "BASE32"}
    if (!ValidationUtils.isValidAddress(body.address_definition_template_chash))
        return callbacks.ifError("invalid addr def c-hash");
    walletDefinedByAddresses.deletePendingSharedAddress(body.address_definition_template_chash);
    callbacks.ifOk();
    break;
```
`from_address` (the cryptographically authenticated sender of the device message, verified upstream in `device.js`'s `handleJustsaying`/`hub/message` signature check) is available in this scope but is never passed to, or checked against, the deletion function.

`deletePendingSharedAddress` in `wallet_defined_by_addresses.js` performs an unconditional delete keyed solely by the supplied hash: [2](#0-1) 
```
// unused
function deletePendingSharedAddress(address_definition_template_chash){
	db.query("DELETE FROM pending_shared_address_signing_paths WHERE definition_template_chash=?", [address_definition_template_chash], function(){
		db.query("DELETE FROM pending_shared_addresses WHERE definition_template_chash=?", [address_definition_template_chash], function(){});
	});
}
```
Compare this to the sibling handler `approve_new_shared_address`, which correctly scopes the update to the caller's own row via `AND device_address=?`: [3](#0-2) 
```
function approvePendingSharedAddress(address_definition_template_chash, from_address, address, assocDeviceAddressesByRelativeSigningPaths){
	db.query( // may update several rows if the device is referenced multiple times from the definition template
		"UPDATE pending_shared_address_signing_paths SET address=?, device_addresses_by_relative_signing_paths=?, approval_date="+db.getNow()+" \n\
		WHERE definition_template_chash=? AND device_address=?", 
		[address, JSON.stringify(assocDeviceAddressesByRelativeSigningPaths), address_definition_template_chash, from_address], 
```
The `reject_new_shared_address` path omits the equivalent `device_address=from_address` ownership constraint that its sibling `approve` handler enforces, exactly analogous to the Langflow report where the GET/POST endpoints correctly scoped by user but the DELETE endpoint omitted the scoping check.

### Impact Explanation
Any device that is already a correspondent (paired peer) of a victim and can guess or observe the `definition_template_chash` (a hash of the address-definition template circulated during multisig/shared-address setup among the intended cosigners) can delete the victim's `pending_shared_addresses` and `pending_shared_address_signing_paths` rows even though the attacker is not one of the referenced parties for that template. This destroys the in-progress multisig/shared-address negotiation state on the victim's node, causing the shared-address creation workflow among legitimate parties to silently fail/disappear — a node-state corruption affecting a specific class of address setup used for arbiter/prosaic contract escrow and multi-cosigner wallets.

However, I could not establish that this reaches the stronger, in-scope impact bar required by the rules (concrete unauthorized spending, double-spend of a stable output, supply inflation, AA fund loss/freezing, node disagreement on unit validity/stability, or a network unable to confirm new units): at the time this record can be deleted, no funds have moved to the not-yet-created shared address (the `shared_addresses`/`shared_address_signing_paths` rows are only inserted after all approvals are collected), so no funds are at risk of loss or freezing from this particular deletion. The `sendOfferToCreateNewSharedAddress`, `sendApprovalOfNewSharedAddress`, `sendRejectionOfNewSharedAddress`, `createNewSharedAddressByTemplate`, and `approvePendingSharedAddress` functions are all explicitly marked `// unused`/`// called from UI (unused)` in the current codebase, indicating this feature's sending side is dormant; only the receiving switch-case in `wallet.js` remains wired up, and I was not able to confirm within the available tooling whether this code path is exercised in the current production build or is legacy/dead code retained for backward compatibility.

### Likelihood Explanation
Exploitation requires the attacker to already be a paired correspondent device of the victim and to know or guess the `definition_template_chash` for a pending shared-address negotiation the victim is conducting with someone else. Since this hash is derived from the full address-definition template (which includes the addresses/device addresses of all intended members), an unrelated correspondent generally would not know it unless they are informed out-of-band or the feature is exercised in a context where hashes are guessable/enumerable. Combined with the sending-side functions being marked unused, practical reachability in the current wallet UI is uncertain.

### Recommendation
In `wallet.js`'s `reject_new_shared_address` handler, pass `from_address` into `deletePendingSharedAddress` and, in `wallet_defined_by_addresses.js`, restrict the `DELETE FROM pending_shared_address_signing_paths` (and the subsequent `pending_shared_addresses` cleanup, gated on no remaining signing-path rows) to rows where `device_address=from_address`, mirroring the ownership check already present in `approvePendingSharedAddress`. Additionally verify that the caller is one of the addressed members of the template before permitting deletion, returning an authorization error otherwise.

### Proof of Concept
Not fully constructable from static analysis alone: reproducing this requires (1) confirming the `reject_new_shared_address` / `create_new_shared_address` flow is actually reachable from a shipped wallet UI (the sender-side functions are marked `unused` in this snapshot), and (2) obtaining or predicting a victim's `definition_template_chash` for an in-progress negotiation, which was not verifiable with the tools available in this session. A conceptual PoC: Device C (attacker, a paired correspondent of victim device A but not a party to A's pending shared address with device B) sends a `reject_new_shared_address` device message to A with `address_definition_template_chash` equal to the chash A is using to set up the shared address with B; A's node deletes the `pending_shared_addresses`/`pending_shared_address_signing_paths` rows without checking that C's device_address is among the parties, aborting the legitimate negotiation between A and B.

### Citations

**File:** wallet.js (L228-234)
```javascript
			case "reject_new_shared_address":
				// {address_definition_template_chash: "BASE32"}
				if (!ValidationUtils.isValidAddress(body.address_definition_template_chash))
					return callbacks.ifError("invalid addr def c-hash");
				walletDefinedByAddresses.deletePendingSharedAddress(body.address_definition_template_chash);
				callbacks.ifOk();
				break;
```

**File:** wallet_defined_by_addresses.js (L150-155)
```javascript
function approvePendingSharedAddress(address_definition_template_chash, from_address, address, assocDeviceAddressesByRelativeSigningPaths){
	db.query( // may update several rows if the device is referenced multiple times from the definition template
		"UPDATE pending_shared_address_signing_paths SET address=?, device_addresses_by_relative_signing_paths=?, approval_date="+db.getNow()+" \n\
		WHERE definition_template_chash=? AND device_address=?", 
		[address, JSON.stringify(assocDeviceAddressesByRelativeSigningPaths), address_definition_template_chash, from_address], 
		function(){
```

**File:** wallet_defined_by_addresses.js (L229-234)
```javascript
// unused
function deletePendingSharedAddress(address_definition_template_chash){
	db.query("DELETE FROM pending_shared_address_signing_paths WHERE definition_template_chash=?", [address_definition_template_chash], function(){
		db.query("DELETE FROM pending_shared_addresses WHERE definition_template_chash=?", [address_definition_template_chash], function(){});
	});
}
```
