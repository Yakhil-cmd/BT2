This confirms the analog. The `"sign"` message handler in `wallet.js` explicitly has the membership-authorization check **disabled** at lines 335-338, with a comment stating that enabling it "would make multilateral signing impossible." Any paired correspondent device can send a `sign` request naming an arbitrary local wallet address it does not control (`ifLocal` branch), and the code proceeds directly to `callbacks.ifOk()` and emits `signing_request`/validates the unit without first checking whether `from_address` (the requester) is actually a cosigner (`extended_pubkeys`/`wallet_signing_paths`) of that wallet — mirroring the GitLab bug class of missing membership checks that let an authenticated-but-unrelated principal reach group-scoped data/actions. [1](#0-0) [2](#0-1) 

### Title
Missing cosigner-membership check in device "sign" request handler allows unauthorized signing requests for foreign wallet addresses - (File: wallet.js)

### Summary
The `"sign"` subject handler in `handleMessageFromHub` (`wallet.js`) resolves the target address via `findAddress`, and when the address is local (`ifLocal`), it immediately proceeds to validate/emit a signing request for *any* paired device, without verifying that the sending device (`from_address`) is actually a cosigner/member of the wallet that owns the address. The check that would enforce this membership is explicitly commented out.

### Finding Description
In the `"sign"` case of `doHandle()` inside `handleMessageFromHub`, once `findAddress` resolves the address locally, the code goes straight to `callbacks.ifOk()` and fires the `signing_request` event / calls `network.handleOnlineJoint`, presenting the caller-supplied unsigned unit (and any accompanying private payloads) to the wallet's signing/confirmation flow: [1](#0-0) 

The membership check that historically gated this — verifying that `from_address` is one of the `extended_pubkeys`/cosigners of the wallet owning `body.address` — is present only as a comment:
```
// the commented check would make multilateral signing impossible
//db.query("SELECT 1 FROM extended_pubkeys WHERE wallet=? AND device_address=?", [row.wallet, from_address], function(sender_rows){
//    if (sender_rows.length !== 1)
//        return callbacks.ifError("sender is not cosigner of this address");
``` [3](#0-2) 

By contrast, the `ifRemote` branch of the same handler *does* enforce an equivalent membership check (`other_device_addresses.includes(from_address)`) before proxying the request: [4](#0-3) 

This asymmetry means that for the `ifLocal` branch — i.e., when the requested address is actually controlled by keys on the recipient's own device — *any* correspondent (paired) device address can submit a `sign` request naming a wallet/address it has no relationship to, and the code will still validate the caller-supplied unit and surface it to the local wallet's confirmation/signing pipeline (`network.handleOnlineJoint`, `eventBus.emit("signing_request", ...)`), rather than being rejected outright for lack of authorization. The only remaining constraints are that `body.address` be a valid address string and that it be found among `objUnit.authors` — both attacker-controlled — not that the caller has any legitimate multisig/cosigner relationship with that address's wallet.

### Impact Explanation
An unrelated paired device (e.g., someone who once paired for an unrelated chat/textcoin/arbiter interaction) can:
- Trigger unauthorized "signing_request" prompts referencing wallet addresses it does not co-own, potentially disclosing sensitive unit contents (outputs, amounts, and reconstructed private payloads for indivisible/private assets) to the local wallet's UI/event handlers and any code subscribed to `signing_request`.
- Attempt to solicit signatures from a device on transactions unrelated to any legitimate multisig session it belongs to, since the identity/membership of the requester relative to the target wallet is never validated at this stage — this could be leveraged to trick less careful signer flows (e.g., automated/`signWithLocalPrivateKey` integrations) into presenting or authorizing unit content for a wallet the caller has no established relationship with.

This corresponds to a Medium-severity authorization gap: unauthorized access to another cosigner-group's signing-flow data/state, analogous to the GitLab Virtual Registry cross-group data access issue, but scoped to ocore's device/wallet signing protocol reachable by any paired device.

### Likelihood Explanation
The path is reachable by any device that has successfully paired with the victim (a normal, low-privilege trust relationship, not requiring wallet cosignership) simply by sending a well-formed `sign` message referencing a `body.address` the recipient happens to control locally. The check preventing this was deliberately disabled (not merely absent by oversight) with a comment acknowledging the design tension around multilateral signing, increasing confidence this is a genuine, currently-live gap rather than a hypothetical one.

### Recommendation
Reinstate a membership/authorization check in the `ifLocal` branch of the `"sign"` handler before calling `callbacks.ifOk()`/emitting `signing_request`, verifying that `from_address` is a legitimate cosigner or an otherwise pre-established multilateral-signing participant for `body.address`'s wallet (e.g., checking `extended_pubkeys`/`wallet_signing_paths`, or, for legitimate multilateral/dumb-contract use cases, checking `correspondent_devices`/contract-specific tables such as `prosaic_contracts`/`wallet_arbiter_contracts`), mirroring the check already applied in the `ifRemote` branch (`other_device_addresses.includes(from_address)`), so unrelated paired devices cannot solicit signing/confirmation flows for wallets they do not participate in.

### Proof of Concept
1. Attacker device pairs with Victim device (a normal one-time pairing, e.g. via a support/contact flow).
2. Attacker learns (or guesses/observes) a valid address `A` that Victim's wallet controls locally (`my_addresses`/`wallet_signing_paths`) — for many flows addresses are shared during payment requests/chat, so this is often available.
3. Attacker sends a `"sign"` message to Victim's hub-facing device handler:
   ```
   {
     subject: "sign",
     body: {
       address: "A",
       signing_path: "r",
       unsigned_unit: { authors: [{ address: "A", authentifiers: {...} }], messages: [...] }
     }
   }
   ```
4. `handleMessageFromHub` → `findAddress("A", "r", ...)` resolves `ifLocal` because `A` is genuinely owned by Victim.
5. Because the cosigner check is commented out, the handler calls `callbacks.ifOk()` and proceeds to validate/emit `signing_request` for the attacker-supplied unit, even though the Attacker device has no cosigner relationship with wallet(s) owning `A`, demonstrating the missing-authorization gap.

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

**File:** wallet.js (L374-378)
```javascript
					ifRemote: function(device_address, other_device_addresses){
						if (device_address === from_address)
							return callbacks.ifError("looping signing request for address "+body.address+", path "+body.signing_path);
						if (!other_device_addresses.includes(from_address))
							return callbacks.ifError("you are not listed as a cosigner for this address "+body.address);
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
