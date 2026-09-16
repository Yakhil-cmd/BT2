### Title
Missing cosigner-authorization check on incoming "sign" requests lets any paired device solicit unauthorized signatures on shared/multisig addresses - (File: wallet.js)

### Summary
The XWiki advisory's root cause is that a privileged action (evaluating/saving page content) is performed in response to an unauthenticated/unauthorized request, relying only on the fact that a legitimate, privileged user's browser happened to make the request. The ocore analog is in `wallet.js`'s `handleMessageFromHub`, `case "sign"`: any correspondent ("paired device") can ask a wallet to sign an arbitrary unit for any address the wallet locally controls, and the code explicitly does **not** verify that the requesting device is actually an authorized cosigner of that address before invoking the local signing flow.

### Finding Description
`handleMessageFromHub` dispatches device messages from paired correspondents by `subject`. For `subject === "sign"`, the handler parses and structurally validates the `unsigned_unit`, then resolves the target address via `findAddress(body.address, body.signing_path, …)`: [1](#0-0) 

When the address/signing-path resolves to a locally-controlled key, `ifLocal` fires. The authorization check that would normally confirm the requesting device is actually a legitimate cosigner for this address is present only as a **commented-out** block: [2](#0-1) 

Instead, the code immediately calls `callbacks.ifOk()` and proceeds to validate/hash the unit and emit the `signing_request` event, which is expected to trigger a UI confirmation dialog for the user: [3](#0-2) 

`findAddress` itself only checks whether the `(address, signing_path)` pair exists somewhere in `my_addresses`/`wallet_signing_paths` or `shared_address_signing_paths`; it does not scope this lookup to correspondents who are actually registered as cosigners for that specific shared/multisig address (`shared_addresses` / `shared_address_signing_paths` tables), it only checks `device_address` for the *remote* (`ifRemote`) branch, not `ifLocal`: [4](#0-3) 

Consequently, any paired correspondent (which is an explicitly in-scope reachable actor per the "paired device" message-handling channel) that knows or can enumerate a `(shared_address, signing_path)` pair the victim device controls can send a `"sign"` request. The victim's wallet will process it and surface a signing-confirmation prompt, without any code-level assurance that the requester is one of the legitimate parties to that specific shared address's transaction. This mirrors the CSRF class flaw in the report: a state-changing/privileged action (producing a valid signature share over an attacker-chosen unit) is triggered by an unauthorized party, relying only on the victim's own UI approval — the exact "make the privileged actor perform the sensitive action without a validity/authorization check" pattern from the XWiki advisory (there, forging a GET request; here, forging a `sign` device message).

### Impact Explanation
Shared addresses in ocore's multisig wallets (`wallet_defined_by_addresses.js`) require signatures from multiple cosigning devices to spend funds. If a malicious paired device (e.g., an untrusted chat contact who was paired for an unrelated purpose, or a normal cosigner acting maliciously by asking to sign in someone else's name) can produce signing requests for shared addresses without being validated as a legitimate party, it can attempt to get the victim device to countersign an attacker-crafted transaction. Combined with routine approval behavior for cosigning prompts (multisig users regularly approve signing prompts as part of normal wallet operation), this can lead to the victim's device contributing its signature to a malicious spend, resulting in unauthorized spending from the shared/multisig address if the attacker can obtain (or already controls) the remaining required signatures. This satisfies the "concrete unauthorized spending" impact bar.

### Likelihood Explanation
The prerequisite is only that the attacker be a paired device/correspondent of the victim's wallet (an explicitly allowed reach vector per the rules) and know a `(shared_address, signing_path)` the victim participates in — information that is routinely shared during normal shared-address setup (`sendNewSharedAddress`/`sendSharedAddressToPeer`) and thus available to any legitimate-but-malicious cosigner or a device that was previously part of a shared-address negotiation. The commented-out check in the code is direct evidence that the authorization gap is intentional/known-but-unmitigated in the current code, increasing confidence this is exploitable rather than defense-in-depth already covered elsewhere; final mitigation relies entirely on the human user visually verifying and rejecting the confirmation dialog.

### Recommendation
Restore and enforce a check in the `ifLocal` branch of the `"sign"` case that the requesting `from_address` is actually registered as a cosigner for `body.address` at `body.signing_path` (e.g., verify `from_address` appears in `shared_address_signing_paths`/`wallet_signing_paths`/`extended_pubkeys` for the relevant wallet/shared address) before emitting `signing_request`. At minimum, the emitted `signing_request` event should carry unambiguous authorization-context information for the UI so that the confirmation dialog explicitly warns the user when the requester is not a verified party to that specific shared address, rather than presenting a generic "confirm" prompt.

### Proof of Concept
1. Attacker device `D_a` pairs (or is already a chat correspondent) with victim device `D_v`.
2. Attacker learns that `D_v` participates in shared/multisig address `SA` at signing path `r.1.0` (e.g., from a previous legitimate shared-address setup, or by guessing common paths, since no additional secret is required to attempt the request).
3. `D_a` sends a device message with `subject: "sign"`, `body: {address: SA, signing_path: "r.1.0", unsigned_unit: <attacker-crafted spending unit from SA>}` to `D_v`.
4. `D_v`'s `handleMessageFromHub` resolves `SA`/`r.1.0` via `findAddress` to `ifLocal` (code at `wallet.js:332-349`), skips the (commented-out) cosigner check, and emits `signing_request` to the wallet UI.
5. If the victim approves the confirmation dialog (which looks like a routine multisig cosigning request), `D_v` returns a valid signature over the attacker's unit via the `"signature"` message, contributing to a transaction the victim never should have implicitly trusted the requester to construct correctly.

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

**File:** wallet.js (L350-372)
```javascript
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
						//});
```

**File:** wallet.js (L1233-1259)
```javascript
function findAddress(address, signing_path, callbacks, fallbackInfo){
	db.query(
		"SELECT wallet, account, is_change, address_index, full_approval_date, device_address \n\
		FROM my_addresses JOIN wallets USING(wallet) JOIN wallet_signing_paths USING(wallet) \n\
		WHERE address=? AND signing_path=?",
		[address, signing_path],
		async function(rows){
			if (rows.length > 1)
				throw Error("more than 1 address found");
			if (rows.length === 1){
				var row = rows[0];
				if (!row.full_approval_date)
					return callbacks.ifError("wallet of address "+address+" not approved");
				if (row.device_address !== device.getMyDeviceAddress()) {
					const other_rows = await db.query("SELECT DISTINCT device_address FROM wallet_signing_paths WHERE wallet=? AND device_address!=?", [row.wallet, row.device_address]);
					const other_device_addresses = other_rows.map(r => r.device_address);
					return callbacks.ifRemote(row.device_address, other_device_addresses);
				}
				var objAddress = {
					address: address,
					wallet: row.wallet,
					account: row.account,
					is_change: row.is_change,
					address_index: row.address_index
				};
				callbacks.ifLocal(objAddress);
				return;
```
