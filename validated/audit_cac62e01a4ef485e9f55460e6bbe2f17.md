### Title
Missing cosigner-membership check when processing `my_xpubkey` device messages lets an unauthorized device corrupt multi-signature wallet approval state - (File: wallet_defined_by_keys.js)

### Summary
The `my_xpubkey` device-message handler in `wallet.js` is explicitly allowed **from non-correspondents** and forwards attacker-controlled `wallet` and `my_xpubkey` values directly into `addDeviceXPubKey()` without ever checking that the sending device is actually one of the cosigners named in that wallet's definition template. This mirrors the CVE-2018-25007 pattern: a state-synchronization message handler accepts and applies a property update (here, an `extended_pubkeys` row for a target wallet) without validating that the sender is authorized to change that particular piece of state.

### Finding Description
`wallet.js` routes the `my_xpubkey` message with only light shape/length validation and no ownership check: [1](#0-0) 

This is explicitly comment-documented as reachable by devices that are not even paired correspondents ("allowed from non-correspondents"), and is dispatched straight to `walletDefinedByKeys.addDeviceXPubKey`: [1](#0-0) 

`addDeviceXPubKey` performs an unconditional `INSERT ... IGNORE` followed by an `UPDATE extended_pubkeys SET extended_pubkey=?, approval_date=NOW() WHERE wallet=? AND device_address=?`, keyed purely on the `wallet` and `device_address` values taken from the untrusted message body/sender: [2](#0-1) 

Contrast this with the *offer* path (`create_new_wallet`), which does call `validateWalletDefinitionTemplate()` to check that `from_address` is actually named in the wallet's definition template before accepting anything: [3](#0-2) [4](#0-3) 

No equivalent check exists for `my_xpubkey`. Because any device (even a non-correspondent) can guess or learn a target `wallet` hash (a SHA-256 of an xpubkey, sent openly between cosigners during wallet setup) and can supply any `device_address` derived from its own key, it can insert/overwrite a row in `extended_pubkeys` for a wallet it is not a member of, and mark it "approved": [5](#0-4) 

This corrupted state is consumed by `checkAndFullyApproveWallet` / `checkAndFinalizeWallet`, which iterate over *all* `extended_pubkeys` rows for the wallet to decide whether every member has approved/finalized: [6](#0-5) 

An attacker-injected row that is missing `member_ready_date` will permanently block `rows.some(row => !row.member_ready_date)` from being false, preventing legitimate cosigners from ever finalizing the wallet — a denial-of-service/freeze on wallet creation for the victims. Conversely, since `checkAndFullyApproveWallet` also fires notifications to every `device_address` present in `extended_pubkeys` for the wallet (including the attacker's injected one), the attacker can also insert itself into the notification flow of a wallet-in-progress that it has no legitimate claim on.

### Impact Explanation
This is state corruption of a security-relevant table (`extended_pubkeys`) without verifying the sender is a rightful party to the given wallet, exactly the "missing check on which client/message may update which server-side property" class described in CVE-2018-25007. Consequences reachable by a single unprivileged device message:
- Freezing legitimate multisig wallet setup/finalization for other users (their `checkAndFinalizeWallet` never completes because of the bogus injected row lacking `member_ready_date`).
- Corruption of the local record of which devices are members/approvers of a wallet in progress, since the check that ties `from_address` to the wallet's definition template (used elsewhere, e.g. `validateWalletDefinitionTemplate`) is absent here.

This does not directly move funds because `wallet_signing_paths`/definitions used for spending still come from the definition template negotiated in `create_new_wallet`, so it is capped at Medium severity (freezing/griefing of wallet setup rather than direct fund loss), consistent with the CVSS 4.3 of the source CVE.

### Likelihood Explanation
Trivial to trigger: any device capable of sending a device message (pairing not required per the code's own "allowed from non-correspondents" comment) can send a `my_xpubkey` message with a known target `wallet` hash and any `my_xpubkey`/`device_address` of its own choosing. No cryptographic proof of cosigner membership is required, unlike the parallel `create_new_wallet` flow.

### Recommendation
In the `my_xpubkey` handler (or in `addDeviceXPubKey`), before inserting/updating `extended_pubkeys`, verify that `from_address` is one of the device addresses referenced in the wallet's `definition_template` (stored in the `wallets` table) — the same check `validateWalletDefinitionTemplate` already performs for `create_new_wallet`. Reject the message if the sender is not a named cosigner of that wallet.

### Proof of Concept
1. Attacker (unpaired device) observes/learns the `wallet` hash used during a victim's ongoing multisig-wallet creation (sent in cleartext as part of `create_new_wallet`/`my_xpubkey` exchanges among the real cosigners).
2. Attacker sends a `my_xpubkey` device message: `{wallet: "<target_wallet_hash>", my_xpubkey: "<attacker xpubkey>"}` from a device never referenced in that wallet's definition template.
3. `wallet.js`'s handler accepts it (no correspondent/cosigner check) and calls `walletDefinedByKeys.addDeviceXPubKey`, which inserts a new `extended_pubkeys` row for `(wallet, attacker_device_address)` with `approval_date` set but `member_ready_date` unset. [2](#0-1) 
4. When legitimate cosigners later try to finalize the wallet, `checkAndFinalizeWallet`'s `rows.some(row => !row.member_ready_date)` check permanently returns true because of the attacker's row, so `ready_date` is never set and the wallet never finalizes. [7](#0-6)

### Citations

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

**File:** wallet_defined_by_keys.js (L99-110)
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
		eventBus.emit("create_new_wallet", body.wallet, body.wallet_definition_template, arrDeviceAddresses, body.wallet_name, body.other_cosigners, body.is_single_address);
		callbacks.ifOk();
	});
```

**File:** wallet_defined_by_keys.js (L123-166)
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

function checkAndFullyApproveWallet(wallet, onDone){
	db.query("SELECT approval_date FROM wallets LEFT JOIN extended_pubkeys USING(wallet) WHERE wallets.wallet=?", [wallet], function(rows){
		if (rows.length === 0) // wallet not created yet
			return onDone ? onDone() : null;
		if (rows.some(function(row){ return !row.approval_date; }))
			return onDone ? onDone() : null;
		db.query("UPDATE wallets SET full_approval_date="+db.getNow()+" WHERE wallet=? AND full_approval_date IS NULL", [wallet], function(){
			db.query(
				"UPDATE extended_pubkeys SET member_ready_date="+db.getNow()+" WHERE wallet=? AND device_address=?", 
				[wallet, device.getMyDeviceAddress()], 
				function(){
					db.query(
						"SELECT device_address FROM extended_pubkeys WHERE wallet=? AND device_address!=?", 
						[wallet, device.getMyDeviceAddress()], 
						function(rows){
							// let other members know that I've collected all necessary xpubkeys and ready to use this wallet
							rows.forEach(function(row){
								sendNotificationThatWalletFullyApproved(row.device_address, wallet);
							});
							checkAndFinalizeWallet(wallet, onDone);
						}
					);
				}
			);
		});
	});
}
```

**File:** wallet_defined_by_keys.js (L360-376)
```javascript
// called from network, without user interaction
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

**File:** wallet_defined_by_keys.js (L485-495)
```javascript
function validateWalletDefinitionTemplate(arrWalletDefinitionTemplate, from_address, handleResult){
	try {
		var arrDeviceAddresses = getDeviceAddresses(arrWalletDefinitionTemplate);
	}
	catch (e) {
		return handleResult("failed to get device addresses of new wallet: " + e.toString());
	}
	if (arrDeviceAddresses.indexOf(device.getMyDeviceAddress()) === - 1)
		return handleResult("my device address not mentioned in the definition");
	if (arrDeviceAddresses.indexOf(from_address) === - 1)
		return handleResult("sender device address not mentioned in the definition");
```
