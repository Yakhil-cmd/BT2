### Title
Missing Authentication in `my_xpubkey` Device-Message Handler Allows Unpaired Devices to Inject Cosigner Records and Permanently Freeze Multisig Wallet Finalization - (File: wallet_defined_by_keys.js)

### Summary
The Saleor advisory (GHSA-rgcm-rpq9-9cgr) describes a mutation (`checkoutCustomerAttach`) that let any caller attach an arbitrary resource to any user ID because the mutation never verified that the caller was authorized to act on that ID. The direct analog in ocore is the `my_xpubkey` device-message handler: it is explicitly whitelisted to be processed from devices that are not even paired correspondents, and the underlying handler `addDeviceXPubKey` blindly inserts/updates a row keyed by `(wallet, device_address)` supplied by the sender, without ever checking that `device_address` is one of the addresses that were actually invited into that wallet's cosigner set.

### Finding Description
In `device.js`, when a `hub/message` arrives from a device that is not a known correspondent, most subjects are rejected — except an explicit whitelist: [1](#0-0) 

`my_xpubkey` is on that whitelist, matching the comment in `wallet.js`: [2](#0-1) 

The handler only validates that `wallet` and `my_xpubkey` are present strings of correct type/length — it never checks that the sending `from_address` is a device that belongs to the target wallet's definition: [3](#0-2) 

Compare this with the sibling flow `handleOfferToCreateNewWallet`, which correctly calls `validateWalletDefinitionTemplate` to verify `from_address` is actually mentioned in the wallet definition template before accepting the offer: [4](#0-3) [5](#0-4) 

No equivalent check exists for `addDeviceXPubKey`. As a result, any device on the network — even one that has never paired with the victim and is not part of the wallet's cosigner set — can send a `my_xpubkey` message with a `wallet` value equal to any wallet hash the victim locally knows about (learned e.g. from a `create_new_wallet` offer, or a previously canceled wallet, since `cancelWallet` never deletes the local `wallets` row for the canceling/initiating device — it only deletes `extended_pubkeys` and `wallet_signing_paths`): [6](#0-5) 

This injects a foreign `(wallet, device_address, extended_pubkey, approval_date)` row into `extended_pubkeys` that was never part of the wallet's `wallet_signing_paths`/definition. Because `checkAndFinalizeWallet` joins ALL `extended_pubkeys` rows for the wallet (not just the legitimate signing-path devices) and requires every row to have `member_ready_date` set before it will mark the wallet `ready_date`: [7](#0-6) 

the injected row's `member_ready_date` can never be set (the attacker never sends the corresponding `wallet_fully_approved` confirmation), so `checkAndFinalizeWallet` will forever see a row with `!member_ready_date` and refuse to finalize the wallet, permanently blocking the `wallet_completed` state for that wallet.

### Impact Explanation
This is a missing-authorization vulnerability in wallet/cosigner message handling, one of the explicitly in-scope surfaces (wallet and contract message handling). An unauthenticated/unpaired device can:
- Insert itself as a phantom cosigner into any wallet ID it can learn (leaked/observed wallet hashes, or stale hashes from canceled wallet setups that are never cleaned up locally), without ever being invited or verified via `validateWalletDefinitionTemplate`.
- Permanently prevent `checkAndFinalizeWallet` from completing for that wallet (denial of the wallet-setup completion state), a concrete freezing/DoS condition on a specific victim wallet's setup process.

Note: I was not able to fully verify within the available context whether `ready_date`/`wallet_completed` gates any spending-critical path (e.g., whether it is required before addresses derived via `deriveAddress` can be used to sign/spend), since `deriveAddress`/`checkAndFullyApproveWallet` (which gates `full_approval_date`, used by `findAddress`) do NOT appear to be blocked by the injected row — only `ready_date`/`wallet_completed` is. This limits certainty on whether the impact rises to full fund freezing versus a UI/completion-state DoS. Given this uncertainty, the severity should be treated as Medium pending confirmation of how `ready_date`/`wallet_completed` gates wallet usage in the UI/wallet layer.

### Likelihood Explanation
Exploitation requires no pairing, no authentication, and no privileged position — the attacker only needs network connectivity to the hub and knowledge of the target `wallet` hash (base64 SHA-256 of the initiator's xPubKey), which is transmitted in the `create_new_wallet` offer to intended cosigners and persists in the local `wallets` table indefinitely (including after a locally canceled wallet on the initiator's side, since `cancelWallet` doesn't purge the `wallets` row). The whitelist in `device.js` explicitly permits this specific message type from unknown/unpaired devices, making this a low-effort, remotely triggerable condition.

### Recommendation
In `addDeviceXPubKey` (or in the `my_xpubkey` case in `wallet.js`), verify that `device_address` (the sender) is actually one of the addresses derived from the wallet's stored `wallet_signing_paths` (or `definition_template`) before inserting/updating `extended_pubkeys`. Reject the message if the device is not a legitimate member of that wallet, mirroring the check already performed in `validateWalletDefinitionTemplate`/`handleOfferToCreateNewWallet`. Additionally, ensure `cancelWallet` deletes the local `wallets` row (not just `extended_pubkeys`/`wallet_signing_paths`) so stale wallet hashes cannot be reused as attack targets, and have `checkAndFinalizeWallet`/`checkAndFullyApproveWallet` filter `extended_pubkeys` rows to only those device addresses present in `wallet_signing_paths` for the wallet, rather than trusting all rows keyed by `wallet`.

### Proof of Concept
1. Attacker device (never paired with victim) observes/learns a `wallet` hash belonging to a victim's in-progress or previously canceled multisig wallet (e.g., by being a former cosigner who was removed via `cancelWallet`, since the initiator's local `wallets` row for that hash is never deleted).
2. Attacker sends a `hub/message` to the victim's hub with `subject: "my_xpubkey"`, `body: {wallet: "<victim_wallet_hash>", my_xpubkey: "<attacker_supplied_base58_xpubkey>"}`, signed with the attacker's own device key.
3. Per `device.js`'s whitelist (`arrSubjectsAllowedFromNoncorrespondents = ["pairing", "my_xpubkey", "wallet_fully_approved"]`), the message is processed even though the attacker is not a correspondent.
4. `wallet.js`'s `my_xpubkey` case calls `walletDefinedByKeys.addDeviceXPubKey(body.wallet, from_address, body.my_xpubkey, ...)` with no ownership check.
5. `addDeviceXPubKey` inserts/updates a row `(wallet, attacker_device_address, attacker_xpubkey, approval_date=NOW())` in `extended_pubkeys`.
6. From this point on, `checkAndFinalizeWallet(wallet, ...)` will always find the attacker's row lacking `member_ready_date` and will never set `ready_date`/emit `wallet_completed` for that wallet, permanently blocking its finalization on the victim's device.

### Citations

**File:** device.js (L213-219)
```javascript
				else{ // correspondent not known
					var arrSubjectsAllowedFromNoncorrespondents = ["pairing", "my_xpubkey", "wallet_fully_approved"];
					if (arrSubjectsAllowedFromNoncorrespondents.indexOf(json.subject) === -1){
						respondWithError("correspondent not known and not whitelisted subject");
						return;
					}
					handleMessage(false);
```

**File:** wallet.js (L162-171)
```javascript
			case "my_xpubkey": // allowed from non-correspondents
				// {wallet: "base64", my_xpubkey: "base58"}
				if (!ValidationUtils.isNonemptyString(body.wallet))
					return callbacks.ifError("no wallet");
				if (!ValidationUtils.isNonemptyString(body.my_xpubkey))
					return callbacks.ifError("no my_xpubkey");
				if (body.my_xpubkey.length > 112)
					return callbacks.ifError("my_xpubkey too long");
				walletDefinedByKeys.addDeviceXPubKey(body.wallet, from_address, body.my_xpubkey, callbacks.ifOk);
				break;
```

**File:** wallet_defined_by_keys.js (L99-107)
```javascript
	validateWalletDefinitionTemplate(body.wallet_definition_template, from_address, function(err, arrDeviceAddresses){
		if (err)
			return callbacks.ifError(err);
		if (body.other_cosigners.length !== arrDeviceAddresses.length - 1)
			return callbacks.ifError("wrong length of other_cosigners");
		var arrOtherDeviceAddresses = _.uniq(body.other_cosigners.map(function(cosigner){ return cosigner.device_address; }));
		arrOtherDeviceAddresses.push(from_address);
		if (!_.isEqual(arrDeviceAddresses.sort(), arrOtherDeviceAddresses.sort()))
			return callbacks.ifError("wrong other_cosigners");
```

**File:** wallet_defined_by_keys.js (L123-138)
```javascript
function checkAndFinalizeWallet(wallet, onDone){
	db.query("SELECT member_ready_date FROM wallets LEFT JOIN extended_pubkeys USING(wallet) WHERE wallets.wallet=?", [wallet], function(rows){
		if (rows.length === 0){ // wallet not created yet or already deleted
		//	throw Error("no wallet in checkAndFinalizeWallet");
			console.log("no wallet in checkAndFinalizeWallet");
			return onDone ? onDone() : null;
		}
		if (rows.some(function(row){ return !row.member_ready_date; }))
			return onDone ? onDone() : null;
		db.query("UPDATE wallets SET ready_date="+db.getNow()+" WHERE wallet=? AND ready_date IS NULL", [wallet], function(){
			if (onDone)
				onDone();
			eventBus.emit('wallet_completed', wallet);
		});
	});
}
```

**File:** wallet_defined_by_keys.js (L305-328)
```javascript
function cancelWallet(wallet, arrDeviceAddresses, arrOtherCosigners){
	console.log("canceling wallet "+wallet);
	// some of the cosigners might not be paired
	/*
	arrDeviceAddresses.forEach(function(device_address){
		if (device_address !== device.getMyDeviceAddress())
			sendCommandToCancelNewWallet(device_address, wallet);
	});*/
	var arrOtherDeviceAddresses = _.uniq(arrOtherCosigners.map(function(cosigner){ return cosigner.device_address; }));
	var arrInitiatorDeviceAddresses = _.difference(arrDeviceAddresses, arrOtherDeviceAddresses);
	if (arrInitiatorDeviceAddresses.length !== 1)
		throw Error("not one initiator?");
	var initiator_device_address = arrInitiatorDeviceAddresses[0];
	sendCommandToCancelNewWallet(initiator_device_address, wallet);
	arrOtherCosigners.forEach(function(cosigner){
		if (cosigner.device_address === device.getMyDeviceAddress())
			return;
		// can't use device.sendMessageToDevice because some of the proposed cosigners might not be paired
		device.sendMessageToHub(cosigner.hub, cosigner.pubkey, "cancel_new_wallet", {wallet: wallet});
	});
	db.query("DELETE FROM extended_pubkeys WHERE wallet=?", [wallet], function(){
		db.query("DELETE FROM wallet_signing_paths WHERE wallet=?", [wallet], function(){});
	});
}
```

**File:** wallet_defined_by_keys.js (L361-376)
```javascript
function addDeviceXPubKey(wallet, device_address, xPubKey, onDone){
	db.query(
		"INSERT "+db.getIgnore()+" INTO extended_pubkeys (wallet, device_address) VALUES(?,?)",
		[wallet, device_address],
		function(){
			db.query(
				"UPDATE extended_pubkeys SET extended_pubkey=?, approval_date="+db.getNow()+" WHERE wallet=? AND device_address=?", 
				[xPubKey, wallet, device_address],
				function(){
					eventBus.emit('wallet_approved', wallet, device_address);
					checkAndFullyApproveWallet(wallet, onDone);
				}
			);
		}
	);
}
```

**File:** wallet_defined_by_keys.js (L492-495)
```javascript
	if (arrDeviceAddresses.indexOf(device.getMyDeviceAddress()) === - 1)
		return handleResult("my device address not mentioned in the definition");
	if (arrDeviceAddresses.indexOf(from_address) === - 1)
		return handleResult("sender device address not mentioned in the definition");
```
