## Analog Found

### Title
Missing membership check in multisig wallet xpubkey handling allows any device to freeze victim's shared-wallet setup - (File: wallet_defined_by_keys.js)

### Summary
The upstream CVE describes a Chrome extension service worker that accepted `runtime.onMessageExternal` requests without validating who the sender was, letting any web page impersonate the client and exfiltrate an API key. The analogous defect in `ocore` is not a missing signature check (device messages are properly signed/authenticated), but a missing **authorization** check: the `my_xpubkey` device-message handler is explicitly allowed from devices that are not even paired correspondents, and the function it calls never verifies that the claimed sender is actually one of the cosigners of the target multisig wallet.

### Finding Description
In `device.js`, the hub-message dispatcher whitelists a small set of subjects that are accepted **even from devices the node doesn't know about** (non-correspondents): [1](#0-0) 

`my_xpubkey` is one of the whitelisted subjects, and `wallet.js` routes it straight into `walletDefinedByKeys.addDeviceXPubKey` using `from_address`, which is only the cryptographically-authenticated *device address of the sender* — not a validated member of the target wallet: [2](#0-1) 

`addDeviceXPubKey` performs no check that `device_address` belongs to the multisig wallet's definition template — it just blind-inserts/updates a row keyed by `(wallet, device_address)`: [3](#0-2) 

By contrast, the *initial* wallet-creation offer (`handleOfferToCreateNewWallet`) does validate that the sender's device address is part of the wallet definition template via `validateWalletDefinitionTemplate`: [4](#0-3) 

but that check is never re-applied when subsequent `my_xpubkey` messages arrive for an existing wallet — `wallet` is just an attacker-guessable/observable base64 hash (`sha256(xPubKey)`), and any device (paired or not) can inject an extra row into `extended_pubkeys` for that wallet id.

### Impact Explanation
`checkAndFullyApproveWallet` / `checkAndFinalizeWallet` gate wallet finalization on **every** row in `extended_pubkeys` for the wallet having `approval_date` / `member_ready_date` set: [5](#0-4) [6](#0-5) 

An attacker's spurious row (inserted with `approval_date` set but never receiving `member_ready_date`, since only the real hub interaction sets that) will permanently block `checkAndFinalizeWallet`'s `rows.some(row => !row.member_ready_date)` check from ever passing. Because `deriveAddress` refuses to derive any address until `full_approval_date`/full approval is complete: [7](#0-6) 

a victim's legitimate multisig wallet can be permanently prevented from becoming usable — freezing the shared wallet before any address/funds can even be issued to it, a real (if pre-chain) fund-freezing/denial-of-service impact reachable by an unprivileged, unpaired device.

### Likelihood Explanation
Any node can trivially generate a device keypair, learn a target's `wallet` id (visible in the `create_new_wallet`/`my_xpubkey` protocol, or observable if the attacker was a rejected/withdrawn candidate cosigner), and send a signed `my_xpubkey` justsaying message. No pairing, invitation or existing correspondent relationship is required because `my_xpubkey` is explicitly whitelisted for non-correspondents in `device.js`.

### Recommendation
In `addDeviceXPubKey` (and `handleNotificationThatWalletFullyApproved`), verify that `device_address` is actually one of the device addresses derived from the wallet's stored `definition_template` (the same check `validateWalletDefinitionTemplate` already performs for the initial offer) before inserting/updating `extended_pubkeys`, rejecting messages from devices that are not legitimate cosigners of that wallet.

### Proof of Concept
1. Observe/learn the `wallet` id (base64 sha256 of the initiator's xPubKey) of a target multisig wallet being set up between the initiator and one legitimate cosigner.
2. From an unrelated device (no pairing required), send a `hub/message`-wrapped `my_xpubkey` justsaying with `{wallet: <target_wallet>, my_xpubkey: <attacker_xpub>}` to the initiator's hub.
3. `device.js` accepts it under the non-correspondent whitelist; `wallet.js`/`addDeviceXPubKey` inserts a row `(wallet, attacker_device_address, attacker_xpub, approval_date=now)` with no `member_ready_date`.
4. `checkAndFinalizeWallet` will now always see this row with `member_ready_date IS NULL`, so the wallet can never reach `ready_date`, and legitimate cosigners can never derive/use addresses for it.

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

**File:** wallet_defined_by_keys.js (L122-138)
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
```

**File:** wallet_defined_by_keys.js (L140-166)
```javascript
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

**File:** wallet_defined_by_keys.js (L544-549)
```javascript
function deriveAddress(wallet, is_change, address_index, handleNewAddress){
	db.query("SELECT definition_template, full_approval_date FROM wallets WHERE wallet=?", [wallet], function(wallet_rows){
		if (wallet_rows.length === 0)
			throw Error("wallet not found: "+wallet+", is_change="+is_change+", index="+address_index);
		if (!wallet_rows[0].full_approval_date)
			throw Error("wallet not fully approved yet: "+wallet);
```
