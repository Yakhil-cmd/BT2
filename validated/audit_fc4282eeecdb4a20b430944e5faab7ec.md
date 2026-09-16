### Title
Missing Cosigner Authorization Check on Multi-Signature "sign" Requests from Paired Devices - (File: wallet.js)

### Summary
`wallet.js`'s `handleMessageFromHub` processes the `sign` subject sent by any paired ("correspondent") device. For addresses hosted locally (`findAddress`'s `ifLocal` branch), the code that was meant to verify the requesting device is actually a registered cosigner of the multi-signature address is explicitly disabled (commented out), while the equivalent check *is* enforced for the `ifRemote` branch.

### Finding Description
In the `sign` case of `handleMessageFromHub`, once the target address is resolved as local, the handler immediately proceeds without verifying that `from_address` (the paired device that sent the request) is actually one of the address's registered cosigners: [1](#0-0) 

The check that would have enforced this is present in the code but deliberately commented out with a note explaining it would break a legitimate use case ("multilateral signing"): [2](#0-1) 

By contrast, the `ifRemote` branch (used when the address is hosted on another cosigner's device) *does* enforce authorization, requiring `from_address` to be listed among `other_device_addresses`: [3](#0-2) 

This asymmetry means any device that is merely a "correspondent" (paired chat contact) of the wallet — not necessarily a cosigner of the shared/multisig address in question — can craft a `sign` message referencing any local address the victim controls (single-sig or multisig) and a fully attacker-controlled `unsigned_unit` (including arbitrary payment outputs, e.g. sending funds to an attacker address). The handler validates structural well-formedness of the unit (payload hashes, outputs, inputs) but never checks that the sender has any legitimate relationship to the target address: [4](#0-3) 

The request is accepted (`callbacks.ifOk()`), the unit is fed into `network.handleOnlineJoint` for validation, and on success a `signing_request` event is emitted, which in a normal GUI wallet is meant to display a confirmation dialog — but the underlying authorization gap (unlike the `ifRemote` path) means the *server-side* logic performs no ownership/cosigner check at all for local addresses, unlike a properly-authorized flow.

### Impact Explanation
This mirrors the Airflow HITL bug class (CWE-862, Missing Authorization): an entity that should only be permitted to act on resources it owns (a legitimate cosigner acting on a shared address) can instead act on/target another party's resource (any correspondent device can address arbitrary signing requests naming any local address of the victim, even ones they have no signing role for). Depending on how a wallet UI implementation surfaces `signing_request` (e.g., automated/headless signing setups, or a user who is not scrutinizing signing-path/cosigner details in the confirmation dialog), this can lead to the victim device producing a signature for a transaction crafted entirely by an unauthorized party, directly enabling unauthorized spending of the victim's funds.

### Likelihood Explanation
Reaching this code path only requires being a paired "correspondent" device (any wallet a user has previously exchanged pairing info with, not necessarily a cosigner of the affected address), and requires end-user interaction/approval at the `signing_request` stage in typical GUI wallets, since the code doesn't auto-sign. This somewhat limits automatic exploitability but the root-cause authorization check is objectively missing from a security architecture standpoint, matching the "missing per-resource authorization" class described in the report.

### Recommendation
Reinstate a server-side ownership/cosigner check in the `ifLocal` branch of the `sign` handler before emitting `signing_request` — verify that `from_address` is a legitimate cosigner (e.g., via `extended_pubkeys`/`wallet_signing_paths`/shared-address definition lookup) of `body.address` for the specific `body.signing_path`, mirroring the check already performed in the `ifRemote` branch, rather than relying solely on UI-level confirmation to enforce authorization.

### Proof of Concept
Not directly reproducible from static analysis alone since exploitation depends on downstream UI/headless behavior for the `signing_request` event, which was not found in the indexed codebase. Conceptually:
1. Attacker device pairs with victim device (becomes a "correspondent" — no special privileges required).
2. Attacker sends a `hub/message` with `json.subject === "sign"`, `body.address` = victim's local address (single-sig or shared), `body.signing_path` = a valid path for that address, and `body.unsigned_unit` containing payment outputs directing funds to attacker's address.
3. `handleMessageFromHub`'s `sign` case resolves the address via `findAddress` → `ifLocal`, calls `callbacks.ifOk()` immediately without validating that the attacker device is a cosigner, and emits `signing_request`.
4. If the wallet auto-processes or the user approves without noticing the sender/signing-path mismatch, the victim device signs and can broadcast a transaction spending its own funds to the attacker.

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

**File:** wallet.js (L374-378)
```javascript
					ifRemote: function(device_address, other_device_addresses){
						if (device_address === from_address)
							return callbacks.ifError("looping signing request for address "+body.address+", path "+body.signing_path);
						if (!other_device_addresses.includes(from_address))
							return callbacks.ifError("you are not listed as a cosigner for this address "+body.address);
```
