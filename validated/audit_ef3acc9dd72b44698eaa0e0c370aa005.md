Based on my investigation, I found a concrete analog: the deliberately removed authorization check in the `"sign"` message handler in `wallet.js`, which mirrors the Doorkeeper CWE-732 pattern of a permission/ownership check being dropped from an authorization method, allowing an unprivileged party to invoke a privileged action.

### Title
Missing cosigner-authorization check in device "sign" message handler allows any paired device to trigger signing requests on victim's shared/multisig addresses - ([File: wallet.js])

### Summary
In `handleMessageFromHub`'s `"sign"` case, the code that would verify the sender's device is actually a listed cosigner (i.e., holds an `extended_pubkeys` entry for the target `wallet`) has been explicitly commented out, with the note that keeping it "would make multilateral signing impossible." As a result, any device paired with the victim (any correspondent, not necessarily a cosigner of the target multisig/shared address) can send a `"sign"` request naming one of the victim's local addresses and have it processed as if it came from a legitimate multisig cosigner.

### Finding Description
The `"sign"` case handler validates the address format, signing path format, and that `body.address` appears among `objUnit.authors`, then calls `findAddress`. When the address resolves locally (`ifLocal`), the handler used to check that `from_address` is present in `extended_pubkeys` for the address's wallet — i.e., that the sender is actually a cosigner entitled to request a signature for that address: [1](#0-0) 

That check is commented out: [2](#0-1) 

Without it, `ifLocal` unconditionally calls `callbacks.ifOk()` and proceeds to emit a `"signing_request"` event (for both `signed_message` and regular unit flows) using `from_address` as the requester, regardless of whether `from_address` is actually authorized as a cosigner for that address's wallet: [3](#0-2) 

This is structurally analogous to the Doorkeeper flaw: an authorization/ownership check ("is this caller entitled to perform this action on this resource?") was intentionally removed from a method that is otherwise reachable by any authenticated-but-unprivileged peer (any paired device, not just wallet cosigners), leading to incorrect permission assignment — the action ("request to sign") is granted to parties who should not be entitled to request it.

By contrast, the equivalent remote-forwarding branch (`ifRemote`) still enforces that the sender is a listed cosigner: [4](#0-3) 

This asymmetry confirms the local branch's check was deliberately dropped rather than being unnecessary.

### Impact Explanation
Any device that has previously paired with the victim's wallet (e.g. a merchant, a casual chat contact, or any correspondent added for an unrelated purpose) can craft and send a `"sign"` message naming any of the victim's local addresses as `body.address`, with an arbitrary attacker-chosen `unsigned_unit` (including arbitrary payment outputs). Since the ownership/cosigner check is missing, this reaches the `signing_request` event unconditionally, which the wallet UI surfaces to the user for confirmation. This allows an unauthorized third party (not a party to the multisig, not a counterparty in any legitimate multilateral-signing context) to solicit signatures on transactions of their choosing, misdirecting user consent flows and repeatedly prompting confirmation dialogs for transactions the "requester" has no standing to propose — a violation of the intended access-control model where only actual wallet cosigners should be able to solicit a co-signature for a given address's wallet. If the requester crafts unsigned units whose outputs favor the attacker's own address(es) and the user is not attentive to fully verify outputs and cosigner identity in the confirmation dialog, this can lead to unauthorized spending from the victim's own multisig-funded address.

### Likelihood Explanation
Exploitation only requires that the attacker's device be a paired correspondent of the victim — no special node/hub compromise, no cryptographic break, and no access to any private key is needed. Pairing between devices in this wallet protocol is a low-friction, common occurrence (e.g., for chat, contracts, or one-time payment requests), so an attacker can obtain a qualifying `from_address` easily. The remaining defense is entirely the human user correctly recognizing an unexpected/unauthorized sign confirmation dialog and its correct display of all cosigners/outputs, which is a UX-dependent, not code-enforced, control.

### Recommendation
Reinstate the cosigner-authorization check in the `ifLocal` branch of the `"sign"` case before emitting `signing_request`/before proceeding to `network.handleOnlineJoint`: verify that `from_address` is present in `extended_pubkeys`/`wallet_signing_paths` for the wallet owning `body.address` (mirroring the check already present in `ifRemote`), unless the request is provably part of a legitimate multilateral-signing flow (e.g., `signed_message` case) where the peer's authorization is independently validated by other means (e.g., prosaic/arbiter contract cosigner checks). At minimum, distinguish and separately authorize the multisig-cosigner-signing use case from the multilateral-arbitrary-message-signing use case rather than dropping the check for both.

### Proof of Concept
1. Attacker device A pairs with victim device V (e.g., via a normal chat/contract pairing flow).
2. Victim V has a local address `ADDR` that is part of a 2-of-2 (or n-of-n) shared/multisig wallet with cosigner device C — device A is *not* a cosigner.
3. Attacker A sends V a `"sign"` message: `{subject: "sign", body: {address: ADDR, signing_path: "r.0", unsigned_unit: {authors: [{address: ADDR, authentifiers: {...}}], messages: [...payment message with attacker-controlled outputs...]}}}`.
4. In `handleMessageFromHub`, the `"sign"` case validates format and `findAddress(ADDR, "r", ...)` resolves `ifLocal` (since `ADDR` belongs to V's wallet).
5. Because the cosigner check is commented out, `callbacks.ifOk()` is called immediately and the unit undergoes validation; on success the `"signing_request"` event fires with `from_address = A`, prompting V's wallet UI to display a signing confirmation naming an unauthorized requester as if it were a legitimate cosigning request, despite A never having been part of `extended_pubkeys` for that wallet.

### Citations

**File:** wallet.js (L332-339)
```javascript
				findAddress(body.address, body.signing_path, {
					ifError: callbacks.ifError,
					ifLocal: function(objAddress){
						// the commented check would make multilateral signing impossible
						//db.query("SELECT 1 FROM extended_pubkeys WHERE wallet=? AND device_address=?", [row.wallet, from_address], function(sender_rows){
						//    if (sender_rows.length !== 1)
						//        return callbacks.ifError("sender is not cosigner of this address");
							callbacks.ifOk();
```

**File:** wallet.js (L340-371)
```javascript
							if (objUnit.signed_message && !ValidationUtils.hasFieldsExcept(objUnit, ["signed_message", "authors", "version"])){
								try {
									objUnit.unit = objectHash.getBase64Hash(objUnit); // exact value doesn't matter, it just needs to be there
								}
								catch (e) {
									console.log("signed message hash failed", e);
									objUnit.unit = "failedunit";
								}
								return eventBus.emit("signing_request", objAddress, body.address, objUnit, assocPrivatePayloads, from_address, body.signing_path);
							}
							try {
								objUnit.unit = objectHash.getUnitHash(objUnit);
							}
							catch (e) {
								console.log("to-be-signed unit hash failed", e);
								return;
							}
							var objJoint = {unit: objUnit, unsigned: true};
							eventBus.once("validated-"+objUnit.unit, function(bValid){
								if (!bValid){
									console.log("===== unit in signing request is invalid");
									return;
								}
								// This event should trigger a confirmation dialog.
								// If we merge coins from several addresses of the same wallet, we'll fire this event multiple times for the same unit.
								// The event handler must lock the unit before displaying a confirmation dialog, then remember user's choice and apply it to all
								// subsequent requests related to the same unit
								eventBus.emit("signing_request", objAddress, body.address, objUnit, assocPrivatePayloads, from_address, body.signing_path);
							});
							// if validation is already under way, handleOnlineJoint will quickly exit because of assocUnitsInWork.
							// as soon as the previously started validation finishes, it will trigger our event handler (as well as its own)
							network.handleOnlineJoint(ws, objJoint);
```

**File:** wallet.js (L374-378)
```javascript
					ifRemote: function(device_address, other_device_addresses){
						if (device_address === from_address)
							return callbacks.ifError("looping signing request for address "+body.address+", path "+body.signing_path);
						if (!other_device_addresses.includes(from_address))
							return callbacks.ifError("you are not listed as a cosigner for this address "+body.address);
```
