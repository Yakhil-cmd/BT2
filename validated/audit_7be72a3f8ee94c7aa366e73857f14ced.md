Based on the investigation, I found a concrete analog in `wallet.js`'s `sign` message handler.### Title
Missing cosigner-membership check in `sign` message handler lets any correspondent device trigger unauthorized signing requests on local multisig/shared addresses - (File: wallet.js)

### Summary
The GitLab advisory describes an improper-authorization flaw where a Developer could interact with (open a terminal on) a resource belonging to another user because the server failed to verify the requester's relationship to that resource. In `ocore`'s device-messaging wallet protocol, the analogous authorization check exists for the `ifRemote` branch of the `sign` handler (`if (!other_device_addresses.includes(from_address)) return callbacks.ifError("you are not listed as a cosigner...")`) but is explicitly disabled for the `ifLocal` branch, which handles the far more sensitive case of signing on one of the receiving device's own (local) shared/multisig addresses.

### Finding Description
`wallet.js`'s `handleMessageFromHub` processes the `sign` subject sent by any paired ("correspondent") device — this is reachable from any device that has completed pairing, not just legitimate cosigners of a specific address: [1](#0-0) 

After basic structural/format validation of the `unsigned_unit`, the code resolves the target address via `findAddress` and dispatches to `ifLocal` when the address is one the receiving device actually controls (i.e., a local wallet address or a shared/multisig address where this device is a member): [2](#0-1) 

Crucially, the check that would verify the sender (`from_address`) is actually a registered cosigner of the wallet/address in question is commented out:
```
// the commented check would make multilateral signing impossible
//db.query("SELECT 1 FROM extended_pubkeys WHERE wallet=? AND device_address=?", [row.wallet, from_address], function(sender_rows){
//    if (sender_rows.length !== 1)
//        return callbacks.ifError("sender is not cosigner of this address");
        callbacks.ifOk();
``` [3](#0-2) 

By contrast, the `ifRemote` branch — used when forwarding a signing request to another cosigner device — does perform this exact membership check before proceeding: [4](#0-3) 

This asymmetry means: any device that is merely paired with the victim (a "correspondent", which per `device.js` can be established via pairing secrets, including permanent/multi-use `'*'` secrets) can send a `sign` message referencing any local address the victim controls — including a shared multisig address they are a member of — with an attacker-crafted `unsigned_unit`. Because the authorization/membership check is disabled, the code proceeds to validate the unit as a normal joint and, once validated, fires the `signing_request` event toward the victim's UI: [5](#0-4) 

This is directly analogous to the GitLab bug class: a participant who is not authorized for a specific resource (a specific shared address's cosigner set) is nonetheless allowed to initiate an interactive, resource-bound action (a signing session) against that resource, purely because the server-side authorization gate was removed/never implemented for the local-address code path.

### Impact Explanation
The immediate effect is that any correspondent device (not necessarily an actual cosigner of the targeted shared/multisig address) can force a `signing_request` UI prompt on the victim for an arbitrary unit referencing one of the victim's own local shared addresses. Depending on the wallet UI/headless signer built on top of `getSigner`/`signMessage` (`wallet.js:2016-2029`, `signed_message.js`), an unattended or automated signer that trusts `ifLocal` requests without independently re-verifying `from_address` cosigner membership could be induced to co-sign or partially sign transactions it should never process, potentially enabling: (a) spending confirmations/social-engineering against victim's shared funds, (b) probing which addresses/wallets a device controls (information disclosure oracle via `ifLocal` vs `ifUnknownAddress` vs `ifMerkle` outcomes), and (c) request flooding of the signing UI. Full unauthorized fund movement still requires the human/private key to actually sign, so the worst-case (spending funds) is gated by that additional step for GUI wallets; however, for headless/automated cosigner deployments the missing check removes an intended defense-in-depth layer explicitly documented as protecting against non-cosigner senders in the sibling `ifRemote` branch.

### Likelihood Explanation
Likelihood is Medium: it requires the attacker's device to first be paired as a correspondent with the target (pairing itself can be initiated by anyone who obtains a pairing code/QR, and permanent pairing secrets `'*'` are supported per `device.js:handlePairingMessage`), after which the `sign` message subject is trivially reachable without any per-address relationship check. No special node privileges or protocol-level compromise are needed — only correspondent status, which is the same trust tier the bug is exploiting past.

### Recommendation
Restore and correctly implement the commented-out cosigner-membership check in the `ifLocal` branch of the `sign` case in `wallet.js`, verifying that `from_address` is actually listed as a cosigner/signing-path member of `body.address` (via `extended_pubkeys`, `wallet_signing_paths`, or `shared_address_signing_paths` depending on address type) before emitting `signing_request` or invoking `network.handleOnlineJoint`. If multilateral/prosaic-contract signing genuinely requires accepting requests from non-cosigner correspondents, that use case should be explicitly whitelisted (e.g., by app/message type) rather than disabling the check for all `ifLocal` signing requests.

### Proof of Concept
1. Attacker device pairs with victim device (obtains correspondent status via a pairing code, including a reusable "permanent" pairing secret).
2. Victim controls a shared/multisig address `SHARED_ADDR` for which the attacker's device is *not* listed as a cosigner.
3. Attacker sends a `sign` device message to the victim:
   ```json
   {
     "subject": "sign",
     "body": {
       "address": "SHARED_ADDR",
       "signing_path": "r.0",
       "unsigned_unit": { "authors": [{ "address": "SHARED_ADDR", "authentifiers": {"r.0": ""} }], "messages": [ ... payment app message ... ] }
     }
   }
   ```
4. `handleMessageFromHub` → `case "sign"` resolves `SHARED_ADDR` via `findAddress` to `ifLocal` (since the victim's device is a member of `SHARED_ADDR`).
5. Because the cosigner-membership check is commented out (`wallet.js:334-339`), the request proceeds straight to unit validation and emits `signing_request` to the victim's device UI/automation — despite the attacker never having been a registered cosigner of `SHARED_ADDR`, which the analogous `ifRemote` branch would have rejected with "you are not listed as a cosigner for this address."

*Note: full confirmation of downstream exploitation (whether any bundled headless/automated signer implementation auto-approves `signing_request` without an independent cosigner check) was not verifiable within this repository's indexed contents; this assessment covers the `ocore` library layer where the authorization gate is provably absent.*

### Citations

**File:** wallet.js (L251-277)
```javascript
			case "sign":
				// {address: "BASE32", signing_path: "r.1.2.3", unsigned_unit: {...}}
				if (!ValidationUtils.isValidAddress(body.address))
					return callbacks.ifError("no address or bad address");
				if (!ValidationUtils.isNonemptyString(body.signing_path) || !/^r(\.\d+)*$/.test(body.signing_path))
					return callbacks.ifError("bad signing path");
				var objUnit = body.unsigned_unit;
				if (typeof objUnit !== "object" || objUnit === null)
					return callbacks.ifError("no unsigned unit");
				if (!ValidationUtils.isNonemptyArray(objUnit.authors))
					return callbacks.ifError("no authors array");
				var bJsonBased = (objUnit.version !== constants.versionWithoutTimestamp);
				// replace all existing signatures with placeholders so that signing requests sent to us on different stages of signing become identical,
				// hence the hashes of such unsigned units are also identical
				try {
					objUnit.authors.forEach(function (author) {
						var authentifiers = author.authentifiers;
						for (var path in authentifiers)
							authentifiers[path] = authentifiers[path].replace(/./g, '-');
					});
					const authorAddresses = objUnit.authors.map(author => author.address);
					if (!authorAddresses.includes(body.address))
						return callbacks.ifError("address not found among authors");
				}
				catch (e) {
					return callbacks.ifError("invalid authors: " + e.toString());
				}
```

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
