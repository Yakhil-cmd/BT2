## Title
Missing cosigner authorization check in wallet `"sign"` message handler allows any paired device to trigger a signing request for a local address - (File: `wallet.js`)

### Summary
In `handleMessageFromHub()`'s `"sign"` case, when the target address is hosted locally (`findAddress`'s `ifLocal` callback), the code that verified the requesting device is actually a registered cosigner of that address has been commented out. This mirrors the reported IBC middleware bug class: a message is accepted and forwarded for processing based on the fact that it *parses correctly*, while the authorization/sender check that should gate acceptance is disabled, so the handler processes requests it was never intended to service.

### Finding Description
The `"sign"` handler validates the structural shape of the request (`body.address`, `body.signing_path`, `body.unsigned_unit`, payload hashes, etc.) but the actual authorization check — that the requesting correspondent device (`from_address`) is a registered cosigner of `body.address` for a shared/multisig wallet — is commented out: [1](#0-0) 

```js
findAddress(body.address, body.signing_path, {
    ifError: callbacks.ifError,
    ifLocal: function(objAddress){
        // the commented check would make multilateral signing impossible
        //db.query("SELECT 1 FROM extended_pubkeys WHERE wallet=? AND device_address=?", [row.wallet, from_address], function(sender_rows){
        //    if (sender_rows.length !== 1)
        //        return callbacks.ifError("sender is not cosigner of this address");
            callbacks.ifOk();
```

Notice the contrast with the sibling `ifRemote` branch a few lines below, which *does* keep an explicit cosigner check: [2](#0-1) 

```js
ifRemote: function(device_address, other_device_addresses){
    if (device_address === from_address)
        return callbacks.ifError("looping signing request for address "+body.address+", path "+body.signing_path);
    if (!other_device_addresses.includes(from_address))
        return callbacks.ifError("you are not listed as a cosigner for this address "+body.address);
```

For `ifLocal`, any correspondent (paired) device — not just a device that co-hosts the target address — can send a `"sign"` message naming any address that this device happens to host locally, and the handler will proceed to hash the attacker-supplied unsigned unit and fire the `"signing_request"` event toward the wallet UI: [3](#0-2) 

This is functionally identical to the reported bug class: the check needed to decide "is this message actually intended to be handled by me from this sender" was disabled, so the handler falls through and processes/forwards messages that should have been rejected earlier based on sender identity.

### Impact Explanation
An unprivileged correspondent (paired) device — which the rules explicitly list as a reachable, unprivileged actor — can craft a `"sign"` request naming a victim's own address (single-sig or multisig) together with an attacker-chosen unsigned unit (e.g., one that spends the victim's funds to an attacker output). Because the cosigner check is disabled, this request is accepted structurally and surfaced to the user via the `"signing_request"` UI event as if it were a legitimate signing/multisig request, without any verification that the sender has any relationship to that address. This weakens a defense-in-depth control specifically intended to stop unrelated devices from injecting spend requests into the signing flow, increasing the likelihood of unauthorized spending being approved by a confused user, and is inconsistent with the parallel, still-enforced check in the `ifRemote` branch.

### Likelihood Explanation
Reaching this code path requires nothing more than being a paired/correspondent device of the victim (a normal, unprivileged relationship in the wallet/device messaging protocol) and sending a well-formed `"sign"` justsaying message — no hub, node, or protocol-level privilege is needed. The only remaining barrier is the wallet UI confirmation dialog, but the underlying authorization gate that should have filtered out illegitimate requests before they ever reach the user is missing, exactly matching the "flawed condition instead of sender check" pattern from the report.

### Recommendation
Reinstate the cosigner check in the `ifLocal` branch (restoring the commented-out `extended_pubkeys` lookup, or an equivalent check against the address's definition/signer set) before invoking `callbacks.ifOk()` and emitting `"signing_request"`, so that only devices actually associated with the address's wallet/definition can trigger a local signing flow — mirroring the check already present in the `ifRemote` branch.

### Proof of Concept
1. Device A pairs with victim's device (a normal correspondent relationship, not a cosigner of any of the victim's addresses).
2. Device A sends `{subject: "sign", body: {address: <victim_local_address>, signing_path: "r", unsigned_unit: <attacker_crafted_unit_spending_victim_funds>}}` via the hub to the victim's device.
3. `handleMessageFromHub` reaches the `"sign"` case, passes all structural checks, calls `findAddress`, and lands in `ifLocal` since the address is hosted locally on the victim's device.
4. The commented-out cosigner check means `callbacks.ifOk()` is called and `"signing_request"` is emitted with the attacker's unit and `from_address = Device A`, even though Device A has no relation to `body.address`, presenting the malicious signing request to the victim's UI as if legitimate.

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

**File:** wallet.js (L357-371)
```javascript
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
