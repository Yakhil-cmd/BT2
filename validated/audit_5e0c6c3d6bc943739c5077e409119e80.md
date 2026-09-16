### Title
Missing cosigner-membership check on `my_xpubkey`/`wallet_fully_approved` device messages allows any device to poison and permanently freeze multisig wallet setup - (File: `wallet.js`, `wallet_defined_by_keys.js`, `device.js`)

### Summary
The GHSA-mfcw-83qg-4vw3 bug class is a message handler that fails to restrict who is allowed to invoke it, letting an untrusted party influence the trusted side's state. In `ocore`, the device-messaging protocol explicitly whitelists `my_xpubkey` and `wallet_fully_approved` to be processed **even from devices that are not paired correspondents at all**, and the underlying handlers (`addDeviceXPubKey`, `handleNotificationThatWalletFullyApproved`) never verify that the sending `device_address` is actually one of the cosigners that were named in the original wallet's `wallet_definition_template`. This lets any device (or, more importantly, a paired device that was never invited to a specific shared/multisig wallet) inject bogus rows into `extended_pubkeys` for a wallet hash it merely learns about, permanently blocking that wallet's completion.

### Finding Description
When a hub relays a `hub/message` justsaying that a device is *not* a known correspondent of, `device.js` only allows it through if the `subject` is in a small whitelist: [1](#0-0) 

Two of those whitelisted subjects, `my_xpubkey` and `wallet_fully_approved`, are handled in `wallet.js` with only shape/type validation of the body - there is no check that `from_address` is actually a cosigner that belongs to the target `wallet`: [2](#0-1) 

Those calls flow into `wallet_defined_by_keys.js`, where `addDeviceXPubKey` and `handleNotificationThatWalletFullyApproved` blindly `INSERT ... IGNORE` a new `(wallet, device_address)` row into `extended_pubkeys` and then update it, with no verification that `device_address` was ever part of `wallet_signing_paths`/the wallet's definition template: [3](#0-2) 

The wallet-completion logic then requires **every** row in `extended_pubkeys` for that wallet hash to have `approval_date` (for "full approval") and `member_ready_date` (for final "ready" state) before emitting `wallet_completed`: [4](#0-3) 

Because any device can inject an extra, illegitimate row keyed by its own `device_address` for a wallet hash it merely observes (the `wallet` value is a SHA-256 of the initiator's xpubkey and is passed around unencrypted-looking base64 in multiple device messages such as `create_new_wallet`/`my_xpubkey` that indirect/known correspondents relay), that extra row will never legitimately reach `member_ready_date` unless the attacker chooses to complete it. This permanently keeps `checkAndFinalizeWallet`'s condition `rows.some(row => !row.member_ready_date)` true, so `wallet_completed` never fires for the legitimate multisig wallet - a denial-of-finalization for a shared address's owners.

### Impact Explanation
This maps to the "AA fund loss/freezing" / "address definitions and authentifiers" category in scope: a shared/multisig address's setup process can be permanently stuck in an unfinalized state due to attacker-injected bogus cosigner rows that the protocol never validates as authorized members of that wallet. Victims who rely on the `wallet_completed` event to know a multisig address is safe to fund may be misled, and legitimate cosigners can never get the wallet to reach the finalized/ready state, effectively freezing the shared-address setup. Additionally, `readCosigners` joins `extended_pubkeys` with `correspondent_devices` and throws when a device address in `extended_pubkeys` has no matching correspondent name, which can crash cosigner-listing logic: [5](#0-4) 

### Likelihood Explanation
Any device is reachable through this path merely by relaying a signed device message with the right `subject`; the `my_xpubkey`/`wallet_fully_approved` non-correspondent bypass was explicitly hard-coded, and no code anywhere validates that the sender is one of the addresses derived from the wallet's `arrWalletDefinitionTemplate`/`wallet_signing_paths`. This is directly analogous to the Jenkins Xpediter plugin flaw where an agent/controller message lacked an origin restriction, letting the untrusted side reach functionality/state meant to be constrained to a trusted set of participants.

### Recommendation
Before processing `my_xpubkey` or `wallet_fully_approved`, verify that `from_address` is present in `wallet_signing_paths` (or the equivalent device-address set derived from the wallet's definition template) for the referenced `wallet`. Reject (and do not insert any row for) messages from device addresses that are not legitimate members of that wallet, regardless of whether the wallet ID was learned legitimately or not.

### Proof of Concept
1. Attacker device `D_evil` (unpaired, or paired but not part of wallet `W`) learns the wallet hash `W` (e.g., by being a relay/indirect correspondent of a `create_new_wallet`/`my_xpubkey` message intended for someone else, or simply guessing/observing it from a shared context).
2. `D_evil` sends `hub/message` with `subject: "my_xpubkey"`, `body: {wallet: W, my_xpubkey: <any valid-looking base58 key>}`.
3. Per `device.js:213-220`, this passes the non-correspondent whitelist check.
4. `wallet.js:162-171` accepts it (only checks string types/lengths) and calls `walletDefinedByKeys.addDeviceXPubKey(W, D_evil, xpubkey, ...)`.
5. `addDeviceXPubKey` (`wallet_defined_by_keys.js:361-376`) inserts a brand-new `extended_pubkeys` row `(wallet=W, device_address=D_evil, approval_date=now)` with no check that `D_evil` is a real cosigner of `W`.
6. `checkAndFinalizeWallet` for `W` will now always find this extra row lacking `member_ready_date` (unless `D_evil` chooses to complete it), so `wallet_completed` never fires for the legitimate owners of wallet `W`, freezing the multisig wallet setup indefinitely.

### Citations

**File:** device.js (L213-220)
```javascript
				else{ // correspondent not known
					var arrSubjectsAllowedFromNoncorrespondents = ["pairing", "my_xpubkey", "wallet_fully_approved"];
					if (arrSubjectsAllowedFromNoncorrespondents.indexOf(json.subject) === -1){
						respondWithError("correspondent not known and not whitelisted subject");
						return;
					}
					handleMessage(false);
				}
```

**File:** wallet.js (L162-178)
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
			
			case "wallet_fully_approved": // allowed from non-correspondents
				// {wallet: "base64"}
				if (!ValidationUtils.isNonemptyString(body.wallet))
					return callbacks.ifError("no wallet");
				walletDefinedByKeys.handleNotificationThatWalletFullyApproved(body.wallet, from_address, callbacks.ifOk);
				break;
```

**File:** wallet_defined_by_keys.js (L122-166)
```javascript
// check that all members agree that the wallet is fully approved now
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

**File:** wallet_defined_by_keys.js (L360-393)
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

// called from network, without user interaction
function handleNotificationThatWalletFullyApproved(wallet, device_address, onDone){
	db.query( // just in case it was not inserted yet
		"INSERT "+db.getIgnore()+" INTO extended_pubkeys (wallet, device_address) VALUES(?,?)",
		[wallet, device_address],
		function(){
			db.query(
				"UPDATE extended_pubkeys SET member_ready_date="+db.getNow()+" WHERE wallet=? AND device_address=?", 
				[wallet, device_address],
				function(){
					checkAndFinalizeWallet(wallet, onDone);
				}
			);
		}
	);
}
```

**File:** wallet_defined_by_keys.js (L395-413)
```javascript
function readCosigners(wallet, handleCosigners){
	db.query(
		"SELECT extended_pubkeys.device_address, name, approval_date, extended_pubkey \n\
		FROM extended_pubkeys LEFT JOIN correspondent_devices USING(device_address) WHERE wallet=?", 
		[wallet], 
		function(rows){
			rows.forEach(function(row){
				if (row.device_address === device.getMyDeviceAddress()){
					if (row.name !== null)
						throw Error("found self in correspondents");
					row.me = true;
				}
				else if (row.name === null)
					throw Error("cosigner not found among correspondents, cosigner="+row.device_address+", my="+device.getMyDeviceAddress());
			});
			handleCosigners(rows);
		}
	);
}
```
