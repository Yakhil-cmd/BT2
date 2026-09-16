### Title
Missing cosigner authorization check in wallet "sign" message handler allows unauthorized signing requests - (File: wallet.js)

### Summary
The Jenkins GitLab Plugin bug (CVE-2025-24397) stems from an HTTP endpoint that checks a weaker/incorrect permission level than required, letting a low-privileged caller enumerate sensitive credential IDs it should not be able to see. The analogous root cause in `ocore--005` is an authorization check that was deliberately removed (left commented out) in the wallet device-message handler for the `"sign"` subject, so **any paired correspondent device** can submit a signing request for a local address without the code verifying that the sender is actually a legitimate cosigner of that address.

### Finding Description
In `wallet.js`, `handleMessageFromHub` processes messages received from paired devices (hub-relayed device messages). For the `case "sign"` subject, after validating the unit/payload structure, the code calls `findAddress(body.address, body.signing_path, {...})`, and in the `ifLocal` callback proceeds to accept the signing offer and emit a `"signing_request"` event without checking whether `from_address` (the device that sent the message) is actually authorized to request a signature for that address: [1](#0-0) 

The authorization check that should gate this path is explicitly present in the code but commented out: [2](#0-1) 

```js
ifLocal: function(objAddress){
    // the commented check would make multilateral signing impossible
    //db.query("SELECT 1 FROM extended_pubkeys WHERE wallet=? AND device_address=?", [row.wallet, from_address], function(sender_rows){
    //    if (sender_rows.length !== 1)
    //        return callbacks.ifError("sender is not cosigner of this address");
        callbacks.ifOk();
        ...
```

By contrast, in the sibling `ifRemote` branch of the same handler, a correct authorization check *is* performed — the sender must be listed among `other_device_addresses` before the request is forwarded: [3](#0-2) 

This asymmetry mirrors the Jenkins advisory pattern precisely: one code path enforces the proper authorization relationship (cosigner/wallet membership) while a parallel, reachable path does not, silently trusting any correspondent device that is capable of sending a `"sign"` device message.

### Impact Explanation
Any device paired with the victim's wallet (a "correspondent" — not necessarily a cosigner of the target address) can send a forged `"sign"` message body naming any locally-controlled address plus an attacker-crafted `unsigned_unit` (including `private_payloads`). Since the cosigner-membership check is disabled, the request is accepted (`callbacks.ifOk()`), the unit is passed into validation/handling, and a `"signing_request"` UI event is fired for the local wallet exactly as if a legitimate cosigner had sent it. This lets an unauthorized paired device:
- Confirm/enumerate that a given address is locally controlled by the wallet (address-ownership disclosure analogous to the credential-ID enumeration in the advisory), and
- Present spoofed multi-signature signing prompts (with attacker-controlled inputs/outputs and private payloads) to the wallet UI, increasing the chance of tricking the user into approving a transaction they were never a legitimate party to — a path toward unauthorized fund movement in shared/multisig addresses.

### Likelihood Explanation
Reaching this code only requires being an existing paired correspondent device (a `from_address` known to `handleMessageFromHub`), which is the same trust tier the report requires ("paired device can reach"). No additional cosigner relationship, hub-admin, or on-chain privilege is needed to hit the vulnerable `ifLocal` branch — the check that would have enforced that additional relationship is simply commented out.

### Recommendation
Restore (or replace with a stricter equivalent) the disabled authorization check in the `ifLocal` branch of the `"sign"` handler: verify that `from_address` is actually a cosigner/member device for `body.address` (e.g., via `extended_pubkeys`/`shared_address_signing_paths`/`wallet_signing_paths`) before calling `callbacks.ifOk()` and emitting `"signing_request"`. If multilateral signing (different addresses, different device sets signing the same unit) must remain supported, the check should be adapted to validate that `from_address` is a legitimate party to *some* address referenced in `objUnit.authors`, rather than removed outright.

### Proof of Concept
1. Device A pairs with Device B (legitimate correspondent pairing, no shared/multisig address between them).
2. Device A (attacker) sends a hub device message to Device B:
```json
{
  "subject": "sign",
  "body": {
    "address": "<B's local wallet address>",
    "signing_path": "r",
    "unsigned_unit": { "authors": [{ "address": "<B's local wallet address>" }], "messages": [...] }
  }
}
```
3. On Device B, `handleMessageFromHub` → `case "sign"` → `findAddress` resolves `ifLocal` because the address is indeed local to B's wallet.
4. Because the cosigner check is commented out, `callbacks.ifOk()` is returned to A (confirming address ownership) and a `"signing_request"` event fires on B's wallet UI, presenting A's crafted transaction for signing — despite A never having been a party to that address.

### Citations

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
