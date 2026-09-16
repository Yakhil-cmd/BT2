## Analysis: `wallet.js` "sign" request handler — missing cosigner-ownership check

The Bitwarden CVE's root cause is: a request body supplies an identity/binding (email) that is never checked against the authenticated caller, so an unprivileged actor can bind a sensitive credential to a key they control. The closest reachable analog in ocore is the commented-out ownership check in the `"sign"` device-message handler in `wallet.js`.

### Title
Missing cosigner-ownership verification in local signing-request handler allows any paired device to trigger signing on shared/multisig addresses - (File: wallet.js)

### Summary
When a correspondent device sends a `"sign"` message for an address that resolves locally (`findAddress` → `ifLocal`), the handler immediately calls `callbacks.ifOk()` and emits `signing_request` without verifying that the sending device (`from_address`) is actually a legitimate cosigner of that address. The check that would enforce this is explicitly disabled.

### Finding Description
In the `"sign"` case of `handleMessageFromHub`, `findAddress(body.address, body.signing_path, ...)` resolves whether the requested address is hosted locally. If so, `ifLocal` fires: [1](#0-0) 

The comment makes the gap explicit — the intended check ("sender is not cosigner of this address") is commented out: [2](#0-1) 

Unlike `findAddress`'s `ifRemote` branch, which validates `other_device_addresses.includes(from_address)` before allowing a signing request to be forwarded: [3](#0-2) 

...the `ifLocal` branch has no equivalent membership check against `shared_address_signing_paths` / `wallet_signing_paths` for the requesting `from_address`. Any paired correspondent device (an "unprivileged unit poster"-equivalent actor able to reach `handleMessageFromHub` via `device.sendMessageToDevice`) can send a `"sign"` body referencing *any* address the target device locally controls (its own single-sig address, or a shared/multisig address it participates in), as long as `body.address` appears in `objUnit.authors`: [4](#0-3) 

This is exactly analogous to the Bitwarden flaw: the request body carries an identity/binding (`body.address`) that is trusted without confirming the caller is entitled to act on it, because the entitlement check was intentionally disabled to preserve a "multilateral signing" use case.

### Impact Explanation
Emitting `signing_request` triggers the wallet UI to build/sign a unit and, in the `signed_message` (non-payment) path, immediately hash and forward to popup-confirmation logic; for payment units it goes through `network.handleOnlineJoint` validation before a confirmation popup. While actual fund movement still requires local unit validation and (in most UIs) a user-confirmation step, an attacker-controlled correspondent can force repeated signing prompts for message content the attacker fully controls (`unsigned_unit`), targeting local addresses (including shared/multisig addresses the victim didn't co-own with that particular attacker device) that the victim device holds keys for. This can be leveraged to solicit partial signatures over attacker-crafted payment units, potentially resulting in loss/misdirection of funds from a shared address, or denial-of-confirmation spam — a fund-loss/authorization-bypass class impact within the wallet/AA-message handling surface in scope.

### Likelihood Explanation
Reaching this code only requires being an already-paired correspondent device (any peer with whom the victim has previously paired for any legitimate purpose, e.g. a compromised or malicious cosigner on one shared address, or any prior chat contact) — no special trust or admin privilege is required beyond ordinary device pairing, which is explicitly listed as an in-scope reachable actor ("paired device"). The vulnerable code path is unconditionally reached for any `"sign"` message whose declared `body.address` maps to a locally-known address.

### Recommendation
Restore and enforce the ownership check: before emitting `signing_request` / auto-hashing the unit in the `ifLocal` branch, verify that `from_address` is one of the recorded cosigner devices for `body.address` (query `shared_address_signing_paths` / `wallet_signing_paths` for `device_address = from_address`), analogous to the check already performed in `ifRemote`. Reject the "sign" request with `callbacks.ifError("sender is not cosigner of this address")` when the check fails.

### Proof of Concept
1. Attacker device A pairs with victim device V (ordinary pairing, e.g., as a cosigner on shared address `S1` only).
2. Victim V also independently owns/controls unrelated local address `S2` (single-sig or a different shared address in which A is *not* a cosigner).
3. Attacker A sends V a device message: `{"subject":"sign","body":{"address":"S2","signing_path":"r","unsigned_unit":{authors:[{address:"S2",authentifiers:{...}}], messages:[...attacker-crafted payment...]}}}`.
4. `findAddress("S2","r", ...)` resolves to `ifLocal` because `S2` is one of V's `my_addresses`/`shared_addresses`. The disabled check at wallet.js:335-338 means no verification is performed that A is a cosigner of `S2`.
5. `callbacks.ifOk()` fires and `signing_request` is emitted with attacker-controlled `unsigned_unit`, triggering signing/confirmation flow for an address the attacker has no legitimate relationship to.

**Uncertainty note:** I could not fully trace how every wallet UI implementation handles the `signing_request` event (i.e., whether all UIs enforce a robust confirmation dialog that would block automatic signing), since UI-layer code is outside `ocore` and not indexed here. The severity of this finding therefore depends on whether downstream consumers of `signing_request` perform adequate confirmation/binding checks — this should be verified against actual wallet client implementations (e.g., headless wallets or bots that auto-approve based on address matching) before treating it as a confirmed High-severity, no-user-interaction vulnerability.

### Citations

**File:** wallet.js (L253-277)
```javascript
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

**File:** wallet.js (L332-349)
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
```

**File:** wallet.js (L374-378)
```javascript
					ifRemote: function(device_address, other_device_addresses){
						if (device_address === from_address)
							return callbacks.ifError("looping signing request for address "+body.address+", path "+body.signing_path);
						if (!other_device_addresses.includes(from_address))
							return callbacks.ifError("you are not listed as a cosigner for this address "+body.address);
```
