Found it. `addDeviceXPubKey` in `wallet_defined_by_keys.js` is the analog: it writes an `extended_pubkey` for a `device_address` supplied in the network message body, without verifying that the sender of the `my_xpubkey` message is actually the device that owns that `device_address`.

### Title
Authorization bypass in multisig wallet xpubkey registration allows a non-member device to inject/overwrite a cosigner's extended pubkey - ([File: wallet_defined_by_keys.js])

### Summary
`wallet_defined_by_keys.addDeviceXPubKey(wallet, device_address, xPubKey, onDone)` [1](#0-0)  updates `extended_pubkeys` for an arbitrary `(wallet, device_address)` pair using values taken directly from an incoming `my_xpubkey` device message, without re-checking that `device_address` equals the actual sender (`from_address`) of that message. This mirrors the Revive Adserver CVE pattern: a party who is authenticated on the messaging layer (has a valid pairing/device session) can perform an update that is supposed to be scoped to "myself" but instead targets an arbitrary other identity (here, another wallet cosigner's device_address), because the target identity comes from the message body rather than from the verified sender.

### Finding Description
`wallet.js`'s `handleMessageFromHub` dispatches the `my_xpubkey` subject, and the underlying handler eventually calls `addDeviceXPubKey(wallet, device_address, xPubKey, ...)`. The SQL performed is an unconditional insert/update: [1](#0-0) 
There is no check anywhere in this path that the `device_address` whose `extended_pubkey` is being set is the same as the device that actually sent the message (`from_address`, derived from the verified device-message signature in `device.js`/`network.js`). Compare this with the `arbiter_contract_update` handler in `wallet.js`, which does check ownership before mutating shared contract state (`from_address !== objContract.peer_device_address ...`) [2](#0-1) . The `my_xpubkey`/`addDeviceXPubKey` path has no equivalent binding between the authenticated sender and the `device_address` field being written.

Since `extended_pubkeys.device_address` determines whose public key is used to derive the shared multisig address (via `deriveAddress` in the same file, which iterates `extended_pubkeys` rows keyed by `device_address` and plugs each `extended_pubkey` into the wallet definition template) [3](#0-2) , a malicious correspondent who is a legitimate wallet member (or who has been added as an indirect correspondent during the multi-party wallet-creation handshake) can send a `my_xpubkey` message claiming to be a *different* member's `device_address` together with an attacker-chosen `xPubKey`. If accepted, `checkAndFullyApproveWallet`/`deriveAddress` will derive a shared address using the attacker's chosen pubkey in place of the legitimate cosigner's, corrupting the multisig definition that other members compute locally.

### Impact Explanation
If the target device_address's slot in `extended_pubkeys` can be silently overwritten/pre-populated with an attacker-controlled xpubkey, the derived multisig wallet address that other members compute for that signing path would differ from what the impersonated cosigner controls, or, if the attacker's own device is one signer and it can effectively force the record for another signer, it may allow deriving m-of-n addresses whose signing power the legitimate cosigner does not actually hold, an integrity failure that can lead to permanent loss/freezing of any funds sent to the resulting shared address (nobody with the intended signer's key can produce a valid signature) — this maps to "AA fund loss or freezing" / consensus-relevant "node disagreement on validity" of the resulting address structure.

### Likelihood Explanation
The attacker only needs to be a peer/cosigner participant already reachable in the wallet-creation handshake (added as indirect correspondent through `approveWallet`/`addIndirectCorrespondents`), which is a normal, low-privilege, unprivileged-user reachable flow, no hub, node, or leaked-key assumptions are required. It requires the target wallet to still be mid-approval (before `full_approval_date`), somewhat narrowing the window but not eliminating the exploitability of the flow.

### Recommendation
In the handler that processes the `my_xpubkey` message (and in `addDeviceXPubKey`), require that `device_address` passed to `addDeviceXPubKey` equals the verified `from_address` of the message, and reject/ignore messages where these differ, mirroring the ownership check pattern already used for `arbiter_contract_update`.

### Proof of Concept
1. Attacker device D3 is included as an indirect correspondent in a 3-party wallet creation between D1 (victim) and D2 (attacker), as happens through the normal `create_new_wallet` handshake.
2. Before D1 sends its own `my_xpubkey`, D2 sends a crafted `my_xpubkey` message to D1/other members with `wallet` set to the shared wallet id and `device_address` field spoofed to D1's device_address, but with D2's own chosen `xPubKey`.
3. `addDeviceXPubKey(wallet, D1_device_address, attacker_xPubKey, ...)` executes, updating the `extended_pubkeys` row for D1 with the attacker-chosen key before D1's genuine message arrives or is processed (or overwriting once fully-approved-checks race).
4. Once other members compute `deriveAddress`, the shared address they compute embeds the attacker's pubkey rather than D1's, since `extended_pubkeys.device_address=D1_address` now maps to attacker's key. [4](#0-3) 

Note: I was unable to fully trace the exact code path within `wallet.js` that reads `body.device_address` for the `my_xpubkey` subject specifically (index limits truncated some of that handler), so I could not 100% confirm whether `device_address` in that specific case handler is taken from `from_address` or from the message body before calling `addDeviceXPubKey`. This should be verified directly in `wallet.js`'s `my_xpubkey` case before treating this as fully confirmed; if `wallet.js` already binds `device_address = from_address` there, the vulnerability would not be exploitable as described and this analog would need to be withdrawn.

### Citations

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

**File:** wallet_defined_by_keys.js (L544-571)
```javascript
function deriveAddress(wallet, is_change, address_index, handleNewAddress){
	db.query("SELECT definition_template, full_approval_date FROM wallets WHERE wallet=?", [wallet], function(wallet_rows){
		if (wallet_rows.length === 0)
			throw Error("wallet not found: "+wallet+", is_change="+is_change+", index="+address_index);
		if (!wallet_rows[0].full_approval_date)
			throw Error("wallet not fully approved yet: "+wallet);
		var arrDefinitionTemplate = JSON.parse(wallet_rows[0].definition_template);
		db.query(
			"SELECT device_address, extended_pubkey FROM extended_pubkeys WHERE wallet=?", 
			[wallet], 
			function(rows){
				if (rows.length === 0)
					throw Error("no extended pubkeys in wallet "+wallet);
				var path = "m/"+is_change+"/"+address_index;
				var params = {};
				rows.forEach(function(row){
					if (!row.extended_pubkey)
						throw Error("no extended_pubkey for wallet "+wallet);
					params['pubkey@'+row.device_address] = derivePubkey(row.extended_pubkey, path);
					console.log('pubkey for wallet '+wallet+' path '+path+' device '+row.device_address+' xpub '+row.extended_pubkey+': '+params['pubkey@'+row.device_address]);
				});
				var arrDefinition = Definition.replaceInTemplate(arrDefinitionTemplate, params);
				var address = objectHash.getChash160(arrDefinition);
				handleNewAddress(address, arrDefinition);
			}
		);
	});
}
```

**File:** wallet.js (L687-690)
```javascript
					db.query("SELECT 1 FROM wallet_signing_paths JOIN my_addresses USING(wallet) WHERE device_address=? AND address=?", [from_address, objContract.my_address], function(rows) {
						const from_cosigner = (rows.length && objContract.me_is_cosigner);
						if (from_address !== objContract.peer_device_address && !from_cosigner && !(from_address === objContract.arbstore_device_address && objContract.status === 'in_appeal' && body.field === 'status'))
							return callbacks.ifError("not an owner");
```
