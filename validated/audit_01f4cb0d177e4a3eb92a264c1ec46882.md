### Title
Missing sender-authorization check in device "sign" message handler allows any paired correspondent to request signing of a victim's addresses they do not co-sign - (File: wallet.js)

### Summary
The `handleMessageFromHub` handler in `wallet.js` processes the `"sign"` device-message subject, which lets one paired device ask another device to co-sign a unit for a shared/multisig address. The intended security check — verifying that the requesting device (`from_address`) is actually a cosigner/co-owner of the target address before honoring the request — is explicitly commented out, and the request is unconditionally accepted (`callbacks.ifOk()`) as long as the target address happens to be locally controlled (`ifLocal`) by the recipient device. [1](#0-0) 

### Finding Description
When a `"sign"` message is received, the code resolves `body.address`/`body.signing_path` via `findAddress()` [2](#0-1)  and, if the resolved address is locally owned (`ifLocal`), immediately proceeds to fire a `signing_request` event with the attacker-supplied `unsigned_unit`/`objUnit`: [3](#0-2) 

The authorization check that would confirm the requester is actually a device entitled to co-sign this address (a cosigner listed for the wallet/shared address) is present in the code but deliberately disabled:
```
// the commented check would make multilateral signing impossible
//db.query("SELECT 1 FROM extended_pubkeys WHERE wallet=? AND device_address=?", [row.wallet, from_address], function(sender_rows){
//    if (sender_rows.length !== 1)
//        return callbacks.ifError("sender is not cosigner of this address");
``` [4](#0-3) 

By contrast, the sibling `ifRemote` branch of the same `findAddress` callback set *does* enforce that `from_address` is among the address's cosigners before forwarding the signing request: [5](#0-4) 

This asymmetry means: any device that is merely a correspondent (paired via `pairing` message, see `handlePairingMessage`) of the victim device — not necessarily a cosigner of the specific multisig/shared address in question — can send a crafted `"sign"` message naming any address the victim locally controls plus an arbitrary `unsigned_unit` payload (attacker-chosen inputs/outputs), and the victim's node will unconditionally accept it (`callbacks.ifOk()`), validate it, and raise a `signing_request` event for that unit as if it originated from a legitimate cosigner. [6](#0-5) 

Where signing confirmation is automated (e.g. multisig/cosigning bots, hardware co-signer services, or arbiter/prosaic-contract flows that rely on `signing_request` handlers auto-approving requests that reference known local addresses and paths), this missing authorization check lets an unrelated paired correspondent inject transactions for signing against a wallet address it has no legitimate relationship to — mirroring the reported bug class of missing per-resource authorization allowing cross-boundary control via manipulated identifiers (here, `body.address`/`body.signing_path` instead of a device/org id).

### Impact Explanation
If the recipient runs any automated cosigning logic on `signing_request` (common for exchange/service multisig setups and prosaic/arbiter contract flows), an attacker who is merely paired as a correspondent — without being an actual cosigner of the targeted shared address — can submit crafted units for signing that reference the victim's addresses, potentially leading to unauthorized spending from those addresses or exhaustion/abuse of the automated signing pipeline. This falls under "concrete unauthorized spending" impact for wallet/contract message handling.

### Likelihood Explanation
Reaching this code path only requires the attacker to already be a correspondent (paired device) of the target — a normal precondition for interacting with any wallet's chat/multisig features — and to know or guess a target `address`/`signing_path` pair the victim controls (addresses are often shared during multisig setup or contract negotiation and are not secret). No additional privilege such as being a listed cosigner is required due to the disabled check, making exploitation straightforward for anyone with an existing pairing relationship.

### Recommendation
Re-enable (in an equivalent, non-breaking form) an authorization check in the `ifLocal` branch of the `"sign"` handler that verifies `from_address` is actually a legitimate participant for `body.address`/`body.signing_path` (e.g., listed in `extended_pubkeys`/`wallet_signing_paths` for multi-device wallets, or in `shared_address_signing_paths` for shared addresses, or otherwise expected in the given contract context) before invoking `callbacks.ifOk()` and emitting `signing_request`. If multilateral signing (different, unrelated addresses signing the same message for prosaic/arbiter contracts) needs to remain supported, the check should be scoped to that specific use case rather than removed entirely for all "sign" requests.

### Proof of Concept
1. Device B pairs with device A (a normal, unprivileged pairing via `pairing` device-message) so that A adds B as a correspondent — no shared-address relationship is created.
2. B learns (e.g., from public chat, a leaked link, or a previous unrelated shared-address negotiation) that address `X` at signing path `r.1` is one of A's addresses (potentially a cosigner path in a wallet A shares with other, unrelated devices).
3. B sends a `sign` device message to A:
   ```
   { subject: "sign", body: { address: X, signing_path: "r.1", unsigned_unit: {...attacker-crafted transaction...} } }
   ```
4. A's `handleMessageFromHub` resolves `X` via `findAddress` to `ifLocal` (since A does host that signing path) and, because the cosigner check is commented out, immediately calls `callbacks.ifOk()` and fires `signing_request` for the attacker-supplied unit — without ever verifying that B is a legitimate cosigner/participant for address `X`.
5. Any automated or lightly-supervised signing flow on A that trusts `signing_request` events tied to known local addresses will process and potentially sign the attacker-controlled unit.

### Citations

**File:** wallet.js (L332-372)
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
							// if validation is already under way, handleOnlineJoint will quickly exit because of assocUnitsInWork.
							// as soon as the previously started validation finishes, it will trigger our event handler (as well as its own)
							network.handleOnlineJoint(ws, objJoint);
						//});
```

**File:** wallet.js (L374-392)
```javascript
					ifRemote: function(device_address, other_device_addresses){
						if (device_address === from_address)
							return callbacks.ifError("looping signing request for address "+body.address+", path "+body.signing_path);
						if (!other_device_addresses.includes(from_address))
							return callbacks.ifError("you are not listed as a cosigner for this address "+body.address);
						try {
							var text_to_sign = objectHash.getUnitHashToSign(body.unsigned_unit).toString("base64");
						}
						catch (e) {
							return callbacks.ifError("unit hash failed: " + e.toString());
						}
						// I'm a proxy, wait for response from the actual signer and forward to the requestor
						eventBus.once("signature-"+device_address+"-"+body.address+"-"+body.signing_path+"-"+text_to_sign, function(sig){
							sendSignature(from_address, text_to_sign, sig, body.signing_path, body.address);
						});
						// forward the offer to the actual signer
						device.sendMessageToDevice(device_address, subject, body);
						callbacks.ifOk();
					},
```

**File:** wallet.js (L797-848)
```javascript
					const contacts_hash = arbiter_contract.getContactsHash({
						me_is_payer: body.me_is_payer,
						my_pairing_code: body.my_pairing_code,
						peer_pairing_code: body.peer_pairing_code,
						my_contact_info: contractContent.my_contact_info,
						peer_contact_info: contractContent.peer_contact_info,
					});
					if (payload.contacts_hash !== contacts_hash)
						return callbacks.ifError("contacts hash doesn't match the signing unit");
					if (payload.contract_text_hash !== body.contract_hash)
						return callbacks.ifError("contract hash doesn't match the signing unit");
					if (payload.arbiter !== body.arbiter_address)
						return callbacks.ifError("arbiter address doesn't match the signing unit");

					const author = objUnit.authors.find(author => author.address === body.shared_address);
					if (!author)
						return callbacks.ifError("shared address author not found in signing unit");
					const signing_paths = Object.keys(author.authentifiers);
					const isMutuallySigned = signing_paths.find(p => p.startsWith('r.0.0')) && signing_paths.find(p => p.startsWith('r.0.1'));
					if (!isMutuallySigned)
						return callbacks.ifError(`signing unit ${body.unit} is not mutually signed, authentifiers: ${JSON.stringify(author.authentifiers)}`);
					const definition = author.definition;
					if (!definition)
						return callbacks.ifError("no definition for shared address author in signing unit");
					let offeror_address, acceptor_address;
					try {
						const mutualPart = definition[1][0][1];
						offeror_address = mutualPart[0][1];
						acceptor_address = mutualPart[1][1];
					} catch (e) {
						return callbacks.ifError("unexpected definition structure in signing unit");
					}
					if (typeof offeror_address !== 'string' || typeof acceptor_address !== 'string')
						return callbacks.ifError("unexpected definition structure in signing unit");
					const bCorrectParties =
						offeror_address === body.my_address && acceptor_address === body.peer_address
						|| offeror_address === body.peer_address && acceptor_address === body.my_address;
					if (!bCorrectParties)
						return callbacks.ifError("offeror and acceptor addresses in signing unit don't match the dispute request");

					const rows = await db.query("SELECT 1 FROM my_addresses WHERE address=?", [body.arbiter_address]);
					if (rows.length === 0)
						return callbacks.ifError("the arbiter is not me");

					// rejection is ok, the message will not be deleted from the hub
					const { device_address } = await arbiters.getArbstoreInfo(body.arbiter_address);
					if (device_address !== from_address)
						return callbacks.ifError("you are not my arbstore");

					body.contract_content = contractContent;
					body.arbstore_device_address = from_address;
					arbiter_contract.insertDispute(body, function(res) {
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
