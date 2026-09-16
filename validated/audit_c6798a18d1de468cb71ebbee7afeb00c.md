Based on my investigation, I found a plausible analog. The pretix CVE is about a data-export code path that skips a permission check that is otherwise enforced elsewhere in the same feature (UI/API redact the secret; the export path forgot to). In `ocore`, the same "one path checks, a parallel path doesn't" pattern exists in the wallet's remote-signing request handler.

### Title
Missing cosigner-authorization check on local "sign" requests lets any paired device probe address ownership and solicit signatures for shared/multisig addresses - ([File: wallet.js])

### Summary
The hub-message handler for the `"sign"` subject in `wallet.js` has two branches depending on where the target address lives: `ifRemote` (the address is hosted on another local device) and `ifLocal` (the address is hosted right here). The `ifRemote` branch explicitly verifies that the requester is a legitimate cosigner of the address before doing anything further. The `ifLocal` branch does not perform the equivalent check — the code that would do it is commented out — before accepting the request, validating/parsing the attached private payloads, and firing the `signing_request` event that drives the confirmation UI.

### Finding Description
In the `ifRemote` handler, the code enforces cosigner membership: [1](#0-0) 

In the `ifLocal` handler for the very same `"sign"` subject, the equivalent check is explicitly disabled with a comment stating it was removed to avoid breaking multilateral signing: [2](#0-1) 

The commented-out code shows the intended check ("sender is cosigner of this address" via `extended_pubkeys`/`my_addresses`), but it is not applied. As written, `findAddress` only distinguishes whether the address is locally hosted, remotely hosted on a paired device, shared, or unknown — it does not verify that `from_address` (i.e., the device that sent the `"sign"` message) is actually one of the parties entitled to co-sign that specific address. Any paired correspondent device can therefore send a forged `"sign"` message naming any address the target wallet happens to control (multisig, shared, or arbiter-contract address) together with an attacker-chosen `unsigned_unit` and — for private assets — an `assocPrivatePayloads` object.

Before reaching this gap, the handler does validate the internal structure and payload-hash consistency of `private_payloads` (lines ~278-330), but that only proves the private payload is self-consistent with the attacker-supplied unit — it says nothing about whether the sender was authorized to know about, or request signing over, this address at all.

Once accepted, the handler calls `callbacks.ifOk()` and emits `signing_request` with the full unsigned unit and any `assocPrivatePayloads` for the wallet's confirmation UI: [3](#0-2) 

This lets an unprivileged paired device (not a real cosigner) (1) learn whether the target device controls a specific address at all — a fact that should only be known to genuine cosigners/wallet members, and (2) push arbitrary attacker-crafted units (including ones spending from a jointly-controlled address) into the target's signing/confirmation flow, repeated across every device that shares that address. If the shared address definition allows a low signature threshold relative to the number of members, or the same trick is played against multiple genuine members simultaneously with a consistent unit, an attacker who is not a true party to the address can accumulate the signatures needed to fully authorize spending from that shared address — the exact "unauthorized spending" outcome analogous to the permission-boundary bypass in the pretix report, where a feature meant to hide privileged data/actions from unauthorized users forgot the check that a sibling code path already enforces.

### Impact Explanation
A device that is not a genuine cosigner of a shared/multisig address can (a) confirm address ownership/membership without authorization (information disclosure of who controls what address), and (b) inject arbitrary spending proposals into the signing pipeline of every legitimate member device that hosts the address locally, working around the cosigner-membership boundary that the `ifRemote` branch enforces. This is a direct analog to "circumventing a permission boundary" and, combined with multiple duped members, can enable unauthorized spending from a shared address.

### Likelihood Explanation
Exploitation only requires being a paired correspondent of the victim device (a normal, low-privilege relationship for wallet users who exchange addresses/contracts), and sending a single crafted `"sign"` hub message. No special access, and no dependency on being an actual address cosigner, is needed to trigger the missing-check branch.

### Recommendation
Restore the cosigner-authorization check in the `ifLocal` branch of the `"sign"` case in `wallet.js`, mirroring the check already performed in `ifRemote` (verify `from_address` is actually listed among the device addresses that control `body.address`, e.g. via `my_addresses`/`extended_pubkeys`/`shared_addresses` membership) before accepting the request, parsing private payloads, or emitting `signing_request`.

### Proof of Concept
1. Attacker device pairs with victim device (normal pairing flow).
2. Victim device hosts a shared/multisig address `A` (not involving attacker) via `wallet_defined_by_addresses`/`wallet_defined_by_keys`.
3. Attacker sends a hub message `{subject: "sign", body: {address: A, signing_path: "r", unsigned_unit: <attacker-crafted-unit-spending-from-A>}}`.
4. In `wallet.js`, `findAddress` resolves `A` as local; the `ifLocal` handler skips the (commented-out) cosigner check, calls `callbacks.ifOk()`, and fires `signing_request`, presenting the attacker's unit for signing on the victim's device — despite the attacker never having been authorized as a cosigner of `A`.

### Citations

**File:** wallet.js (L332-368)
```javascript
				findAddress(body.address, body.signing_path, {
					ifError: callbacks.ifError,
					ifLocal: function(objAddress){
						// the commented check would make multilateral signing impossible
						//db.query("SELECT 1 FROM extended_pubkeys WHERE wallet=? AND device_address=?", [row.wallet, from_address], function(sender_rows){
						//    if (sender_rows.length !== 1)
						//        return callbacks.ifError("sender is not cosigner of this address");
							callbacks.ifOk();
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
```

**File:** wallet.js (L374-378)
```javascript
					ifRemote: function(device_address, other_device_addresses){
						if (device_address === from_address)
							return callbacks.ifError("looping signing request for address "+body.address+", path "+body.signing_path);
						if (!other_device_addresses.includes(from_address))
							return callbacks.ifError("you are not listed as a cosigner for this address "+body.address);
```
