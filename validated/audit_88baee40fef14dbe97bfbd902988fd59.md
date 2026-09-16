### Title
Unauthenticated "my_xpubkey" device message allows freezing multi-signature wallet setup for arbitrary wallet IDs - (File: wallet_defined_by_keys.js)

### Summary
The `my_xpubkey` device-message handler is explicitly whitelisted to be processed even from devices that are not confirmed correspondents, and it inserts a permanent row into `extended_pubkeys` keyed only by an attacker-supplied `wallet` identifier and the sender's own (authenticated) device address — with no check that the sender was ever invited into that wallet's cosigner set. This mirrors CVE-2016-6813's root cause: an API intended only for a legitimate party to register itself is reachable by anyone who merely knows an opaque identifier belonging to another user, with no verification that the caller is entitled to act on that identifier.

### Finding Description
`device.js` explicitly allows the `my_xpubkey` (and `wallet_fully_approved`) subjects to be processed from devices that are *not* known correspondents: [1](#0-0) 

`wallet.js`'s `handleMessageFromHub` routes this subject straight to `walletDefinedByKeys.addDeviceXPubKey` with only length/type checks on `wallet` and `my_xpubkey`, no validation that `from_address` is a member of that wallet's definition: [2](#0-1) 

`addDeviceXPubKey` then unconditionally inserts a new row into `extended_pubkeys` for the supplied `wallet` and the caller's own `device_address`, and marks it approved: [3](#0-2) 

Wallet finalization logic (`checkAndFullyApproveWallet` / `checkAndFinalizeWallet`) requires that *every* row present in `extended_pubkeys` for that wallet has `approval_date`/`member_ready_date` set before the wallet is marked ready: [4](#0-3) 

Because the phantom row inserted by an uninvited device will never receive a `member_ready_date` (that requires the attacker to also send `wallet_fully_approved`, which they control and will simply never send), `checkAndFinalizeWallet`'s `rows.some(row => !row.member_ready_date)` check permanently evaluates true, and the legitimate wallet's `ready_date` is never set. The legitimate cosigners of the shared wallet can never complete setup of that multisig wallet as long as the attacker's row exists, with no self-service way to detect or remove the unauthorized row (`extended_pubkeys` has no ownership/authorization column, and the schema doesn't restrict inserts to devices named in the wallet definition template).

There is no analog to `wallet_signing_paths`/`arrDeviceAddresses` cross-check inside `addDeviceXPubKey` before performing the mutating INSERT — the only place such validation exists is in `handleOfferToCreateNewWallet`/`validateWalletDefinitionTemplate` for the wallet creator's own flow, not for `my_xpubkey`, which is a completely separate, unauthenticated entry point: [5](#0-4) 

### Impact Explanation
Any device on the network that learns or otherwise obtains a target wallet's base64 `wallet` identifier (e.g., a would-be cosigner who is invited but never included in the final `other_cosigners` list, a paired device that intercepts or replays the initial pairing chat, or simply a party who once saw an offer) can permanently prevent that shared/multisig wallet from ever reaching a "ready" state. Since wallet UIs and downstream address-issuance logic (`issueOrSelectNextAddress`, `checkAndFinalizeWallet`) gate on the wallet being fully approved/ready, this results in a freeze of the victims' ability to use funds under that shared wallet — a concrete "AA/wallet fund freezing" outcome matching the required impact bar. It requires no privileged access, no admin key, and no cooperation from the wallet's real members; a single message is enough.

### Likelihood Explanation
Reachability is high once an attacker knows a target `wallet` value: the code path is explicitly reachable from `non-correspondents` by design (`arrSubjectsAllowedFromNoncorrespondents`), requires only a valid device signature over the attacker's own device message, and involves no rate limiting, ownership check, or wallet-definition cross-validation before the mutating DB write occurs. The main constraint is obtaining the `wallet` identifier, which is plausible for a "paired device"/rejected cosigner scenario explicitly permitted in scope (a device that was part of the initial pairing/negotiation exchange, e.g., received the `create_new_wallet` offer or `wallet` value through legitimate chat, but was later excluded from the finalized cosigner set, or a malicious cosigner targeting a wallet after being removed).

### Recommendation
In `addDeviceXPubKey` (and the `my_xpubkey`/`wallet_fully_approved` handlers in `wallet.js`), verify that `from_address` is actually listed as a member device for the specified `wallet` (e.g., cross-check against `wallet_signing_paths` or the stored `definition_template`) before inserting/updating `extended_pubkeys`. Reject the message if the wallet exists but the sender is not a member, and consider removing `my_xpubkey`/`wallet_fully_approved` from the non-correspondent whitelist once the initial "create_new_wallet" handshake has established real correspondent relationships for all cosigners.

### Proof of Concept
1. Attacker device (any device, need not be a real correspondent) determines the base64 `wallet` value of a target's in-progress shared wallet (e.g., through prior participation in wallet-setup chat, or by being an initially-considered but ultimately excluded cosigner).
2. Attacker sends a device message to any legitimate cosigner's device address with `subject: "my_xpubkey"`, `body: {wallet: "<target wallet>", my_xpubkey: "<attacker-controlled xpubkey>"}`.
3. `device.js` allows this because `my_xpubkey` is in `arrSubjectsAllowedFromNoncorrespondents`, bypassing the correspondent check [1](#0-0) .
4. `wallet.js` forwards to `walletDefinedByKeys.addDeviceXPubKey(wallet, attacker_device_address, my_xpubkey, ...)` [2](#0-1) .
5. A new row `(wallet, attacker_device_address, approval_date=now)` is inserted into `extended_pubkeys` [3](#0-2) .
6. From this point on, `checkAndFinalizeWallet` will forever find a row (the attacker's) with `member_ready_date IS NULL`, so the wallet's `ready_date` is never set [6](#0-5) , freezing the legitimate cosigners out of a fully-ready shared wallet indefinitely.

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
