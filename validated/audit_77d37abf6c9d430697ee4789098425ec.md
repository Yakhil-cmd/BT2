Found the analog. It sits in the `"my_xpubkey"` and `"wallet_fully_approved"` device-message handlers of the multi-device (multisig) wallet-creation flow, which are explicitly whitelisted to be accepted **from non-correspondent (unpaired) devices**, and whose handlers never verify that the sending `device_address` is actually a party invited into that wallet's definition template.

### Title
Unauthenticated join of a multisig wallet-creation session via forged `my_xpubkey`/`wallet_fully_approved` device messages - (File: wallet.js, wallet_defined_by_keys.js)

### Summary
`wallet.js`'s `handleMessageFromHub` explicitly allows the subjects `"pairing"`, `"my_xpubkey"`, and `"wallet_fully_approved"` to be processed **even when the sender is not a known/paired correspondent device**: [1](#0-0) . `"my_xpubkey"` is routed to `walletDefinedByKeys.addDeviceXPubKey(body.wallet, from_address, body.my_xpubkey, ...)` [2](#0-1) , and `addDeviceXPubKey` blindly inserts/updates the `extended_pubkeys` row for `(wallet, device_address)` and marks it approved, with no check that `device_address` was one of the addresses referenced in the wallet's `definition_template` when the wallet was created: [3](#0-2) . The `wallet` identifier used as the session key is just `sha256(xPubKey)` — a value that is disclosed in plaintext to every intended cosigner during wallet setup (`sendOfferToCreateNewWallet`/`sendMyXPubKey`), and is otherwise a 256-bit but publicly-shared-between-multiple-parties "session id" for the multisig-creation session: [4](#0-3) .

### Finding Description
This is a direct analog of the Coral Server bug class: a value that identifies an in-progress "session" (here, the multisig wallet-creation session identified by the `wallet` hash) is trusted for authorization without validating that the sender is an authenticated participant. In the wallet flow:
- `addDeviceXPubKey` performs `INSERT OR IGNORE ... (wallet, device_address)` then `UPDATE extended_pubkeys SET extended_pubkey=?, approval_date=NOW() WHERE wallet=? AND device_address=?` — it does not look up `wallet_signing_paths`/the definition template to confirm `device_address` is one of the members that were supposed to take part in `wallet`. [3](#0-2) 
- Because the subject is in `arrSubjectsAllowedFromNoncorrespondents`, this works even from a device the user never paired with — the hub-level authentication (`hub/login` ECDSA challenge/response) only proves the sender controls *some* permanent device key, not that they are an expected cosigner of that specific wallet. [5](#0-4) 
- `checkAndFullyApproveWallet` then treats the wallet as "fully approved" as soon as every row in `extended_pubkeys` for that `wallet` has an `approval_date`, and notifies all members that the wallet is ready: [6](#0-5) .
- `checkAndFinalizeWallet` likewise finalizes the wallet (marks `ready_date`) purely by counting rows with `member_ready_date` set, which any attacker-injected row satisfies via the also-whitelisted `"wallet_fully_approved"` message: [7](#0-6) [8](#0-7) 

An attacker who learns the `wallet` id (visible to any of the real, intended cosigners, or leaked in logs/UI/clipboard the way a "session identifier" would be) can inject an arbitrary `extended_pubkey` for an attacker-controlled `device_address` into that wallet's cosigner set before the legitimate cosigner responds, or race the legitimate flow, effectively joining someone else's in-progress multisig wallet-creation session without ever having been paired or invited.

### Impact Explanation
If an attacker's `device_address`/xpubkey is injected into `extended_pubkeys` for a wallet whose signing template expects `n` fixed cosigners, this corrupts the address-derivation state for that shared multisig wallet: the definition template (`r of set`, `and`, etc., built from `$pubkey@device_address` placeholders) may resolve using the attacker's pubkey instead of (or in addition to) a legitimate cosigner's, and `checkAndFullyApproveWallet`/`checkAndFinalizeWallet` will report the wallet "ready" prematurely and out of the true consensus of intended participants. Depending on the definition-template op (`or`, `r of set` with `required<n`), this can let an attacker unilaterally satisfy a signing branch, enabling unauthorized spending from funds sent to the shared address — matching the "unauthorized spending"/"AA-fund-loss" bar required by the rules. At minimum it desynchronizes the multisig wallet across legitimate members, since some nodes will consider the wallet fully approved with a bogus cosigner while the true participants disagree, i.e., node disagreement over which address/definition is valid for spending.

### Likelihood Explanation
Reaching this path only requires being able to address a device message with subject `"my_xpubkey"` or `"wallet_fully_approved"` to a hub server that a target device is registered on, containing a `wallet` value the attacker has learned — no pairing, no prior trust relationship, and no signature over the `wallet`/`extended_pubkey` binding is required, because `arrSubjectsAllowedFromNoncorrespondents` deliberately bypasses the correspondent check for these subjects. This matches the "unprivileged... device message" reachable surface explicitly in scope.

### Recommendation
Before accepting `"my_xpubkey"`/`"wallet_fully_approved"` in `addDeviceXPubKey`/`handleNotificationThatWalletFullyApproved`, verify that `from_address` is actually one of the device addresses derived from the wallet's `arrWalletDefinitionTemplate`/`wallet_signing_paths` (i.e., that it was a party invited when the wallet was created), analogous to the check already performed in `validateAddressDefinitionTemplate` for shared addresses (`arrDeviceAddresses.indexOf(from_address) === -1`). Reject xpubkey/approval messages for `device_address` values not present in `wallet_signing_paths` for that `wallet`.

### Proof of Concept
1. Legitimate user A initiates a 2-of-2 (or n-of-n) multisig wallet with cosigner B via `createMultisigWallet`, producing `wallet = sha256(xPubKey_A)`, which is sent to B in the "create_new_wallet" offer body (`wallet` field, visible in the message and to any party who can observe it, e.g., via a compromised transport, log, or simply because it's shared plaintext across the pairing/relay path).
2. Attacker C (unpaired with A, no correspondent relationship) sends A a device message `{subject: "my_xpubkey", body: {wallet: <captured wallet id>, my_xpubkey: <attacker's own xpubkey>}}`.
3. A's node processes this via `wallet.js` `case "my_xpubkey"` because the subject is in `arrSubjectsAllowedFromNoncorrespondents`, calling `walletDefinedByKeys.addDeviceXPubKey(wallet, C_device_address, attacker_xpubkey, ...)`. [2](#0-1) 
4. `addDeviceXPubKey` inserts/updates an `extended_pubkeys` row for `(wallet, C_device_address)` with `approval_date` set, with zero verification that C is an intended cosigner of `wallet`. [3](#0-2) 
5. Once all expected rows (now including the attacker's forged one) show `approval_date`, `checkAndFullyApproveWallet` marks the wallet fully approved and can drive it to `ready_date`, even though a party never invited nor authenticated for this specific wallet session has been merged into its cosigner state.

### Citations

**File:** device.js (L203-221)
```javascript
			// check that we know this device
			db.query("SELECT hub, is_indirect FROM correspondent_devices WHERE device_address=?", [from_address], function(rows){
				if (rows.length > 0){
					if (json.device_hub && typeof json.device_hub === 'string' && json.device_hub.length <= 200 && network.isValidWsUrl(conf.WS_PROTOCOL + json.device_hub) && json.device_hub !== rows[0].hub) // update correspondent's home address if necessary
						db.query("UPDATE correspondent_devices SET hub=? WHERE device_address=?", [json.device_hub, from_address], function(){
							handleMessage(rows[0].is_indirect);
						});
					else
						handleMessage(rows[0].is_indirect);
				}
				else{ // correspondent not known
					var arrSubjectsAllowedFromNoncorrespondents = ["pairing", "my_xpubkey", "wallet_fully_approved"];
					if (arrSubjectsAllowedFromNoncorrespondents.indexOf(json.subject) === -1){
						respondWithError("correspondent not known and not whitelisted subject");
						return;
					}
					handleMessage(false);
				}
			});
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

**File:** wallet_defined_by_keys.js (L234-257)
```javascript
function createWallet(xPubKey, account, arrWalletDefinitionTemplate, walletName, isSingleAddress, handleWallet){
	var wallet = crypto.createHash("sha256").update(xPubKey, "utf8").digest("base64");
	console.log('will create wallet '+wallet);
	var arrDeviceAddresses = getDeviceAddresses(arrWalletDefinitionTemplate);
	addWallet(wallet, xPubKey, account, arrWalletDefinitionTemplate, function(){
		handleWallet(wallet);
		if (arrDeviceAddresses.length === 1) // single sig
			return;
		console.log("will send offers");
		// this continues in parallel while the callback handleWallet was already called
		// We need arrOtherCosigners to make sure all cosigners know the pubkeys of all other cosigners, even when they were not paired.
		// For example, there are 3 cosigners: A (me), B, and C. A is paired with B, A is paired with C, but B is not paired with C.
		device.readCorrespondentsByDeviceAddresses(arrDeviceAddresses, function(arrOtherCosigners){
			if (arrOtherCosigners.length !== arrDeviceAddresses.length - 1)
				throw Error("incorrect length of other cosigners");
			_.uniq(arrDeviceAddresses).forEach(function(device_address){
				if (device_address === device.getMyDeviceAddress())
					return;
				console.log("sending offer to "+device_address);
				sendOfferToCreateNewWallet(device_address, wallet, arrWalletDefinitionTemplate, walletName, arrOtherCosigners, isSingleAddress, null);
				sendMyXPubKey(device_address, wallet, xPubKey);
			});
		});
	});
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
