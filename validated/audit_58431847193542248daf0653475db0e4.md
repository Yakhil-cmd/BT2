### Title
IDOR in `addDeviceXPubKey` allows any paired device to register itself as a wallet cosigner without membership verification - (File: wallet_defined_by_keys.js)

### Summary
The `my_xpubkey` device-message handler accepts a `wallet` id and an `xpubkey` from any known correspondent device and unconditionally inserts/updates a row in `extended_pubkeys` for that `(wallet, from_address)` pair — without ever checking that `from_address` is actually one of the device addresses referenced in the wallet's `definition_template`. This mirrors the Mattermost IDOR pattern: an action that should be scoped to "your own membership record" is instead performed using an attacker-supplied identifier (`wallet`) with no ownership/membership check.

### Finding Description
In `wallet.js`, the `"my_xpubkey"` case is explicitly listed as `allowed from non-correspondents` [1](#0-0) , and only validates that `body.wallet` and `body.my_xpubkey` are non-empty strings before calling straight into `walletDefinedByKeys.addDeviceXPubKey(body.wallet, from_address, body.my_xpubkey, callbacks.ifOk)`.

`addDeviceXPubKey` then does: [2](#0-1) 

It performs `INSERT OR IGNORE INTO extended_pubkeys (wallet, device_address)` followed by an `UPDATE ... SET extended_pubkey=?, approval_date=NOW() WHERE wallet=? AND device_address=?`, with **no check that `wallet` exists as a wallet the sender is entitled to join**, and no check that `from_address` is a member declared in `wallets.definition_template` for that wallet id. Compare this to `handleOfferToCreateNewWallet`, which does validate via `validateWalletDefinitionTemplate` that the sender's device address is actually part of the definition template before accepting a new-wallet offer [3](#0-2) . No equivalent check exists for `addDeviceXPubKey`.

After the insert/update, `checkAndFullyApproveWallet` is invoked, which determines "full approval" purely by checking whether every row currently in `extended_pubkeys` for that wallet has a non-null `approval_date`: [4](#0-3) 

Because a newly-inserted attacker row is immediately given `approval_date=NOW()` by the same `addDeviceXPubKey` call, it can never appear as a "missing approval" blocker; it can only ever help the `rows.some(row => !row.approval_date)` check pass. This means an attacker (any paired device correspondent, or any device the user has "her" wallet id) can inject an approved-looking cosigner slot into another user's `extended_pubkeys` table for a `wallet` value it merely knows, potentially triggering `full_approval_date`/`ready_date` to be set and `wallet_fully_approved`/`wallet_completed` events to fire before the legitimate cosigners set specified in `definition_template` have actually approved — since the completion check never cross-references `definition_template` membership, only whatever rows happen to exist in `extended_pubkeys`.

### Impact Explanation
This is an authorization/IDOR-class defect matching the same bug class as the Mattermost CVE (unauthenticated/insufficiently-authorized cross-user state mutation keyed by a caller-supplied identifier). Concretely, it lets an unprivileged paired device:
- Pollute another wallet's `extended_pubkeys` table with an attacker-controlled `device_address`/`xpubkey` row.
- Cause `checkAndFullyApproveWallet`/`checkAndFinalizeWallet` to reach "fully approved"/"ready" state prematurely, since these routines only iterate whatever rows exist for the wallet id rather than validating against the wallet's `definition_template` member set, potentially causing addresses to be treated as ready and used for payments/asset issuance before the legitimate cosigner set has confirmed.

I was not able to fully trace every downstream consumer of `full_approval_date`/`ready_date` (e.g., UI-side spend flows) within the available context to confirm this always results in concrete fund loss versus a wallet-state/UI-trust inconsistency; that determination would need runtime tracing of how UI layers gate spending on `ready_date`.

### Likelihood Explanation
Reachable by any device that is a "correspondent" (paired device) of the victim node, without needing to be a real member of the target wallet — the subject is explicitly whitelisted "from non-correspondents" as well, but even for correspondents there's no membership validation at all. The only requirement is knowledge of the target `wallet` id (a base64 SHA-256 hash), which is shared during multisig-wallet setup among intended cosigners and hub-message recipients, and could be exposed/guessed/leaked in a multi-party wallet setup context.

### Recommendation
In `addDeviceXPubKey` (and correspondingly in `handleNotificationThatWalletFullyApproved`), verify that `device_address` (i.e., `from_address`) is one of the device addresses derivable from the target wallet's stored `definition_template` (as already done in `validateWalletDefinitionTemplate`/`handleOfferToCreateNewWallet`) before inserting/updating `extended_pubkeys`, and before treating the wallet as "fully approved." Reject the message otherwise instead of silently accepting the update.

### Proof of Concept
1. Attacker device D pairs with victim device V as a normal correspondent.
2. Attacker learns (or guesses) a `wallet` id `W` that V is in the process of setting up as a multisig wallet with other genuine cosigners (id is a base64 sha256 digest shared during setup handshakes such as `create_new_wallet`/`my_xpubkey` messages relayed through hubs).
3. Attacker sends a `hub/message` to V's hub addressed to V with `json = {subject: "my_xpubkey", body: {wallet: W, my_xpubkey: "<attacker-controlled xpub>"}}`, signed with D's own device key (passes all the signature/hash checks in `device.js`'s `handleJustsaying`/`hub/message` case).
4. V's node processes it via `wallet.js`'s `"my_xpubkey"` case (`allowed from non-correspondents` path) → `walletDefinedByKeys.addDeviceXPubKey(W, D, xpub, ...)`.
5. `addDeviceXPubKey` inserts a new `extended_pubkeys` row for `(W, D)` with `approval_date=NOW()` regardless of whether D is a declared member of `W`'s `definition_template`, then calls `checkAndFullyApproveWallet(W, ...)`, which may prematurely mark the wallet fully approved/ready if all currently-present rows (including the bogus one) have approval dates. [1](#0-0) [5](#0-4)

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

**File:** wallet_defined_by_keys.js (L361-393)
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
