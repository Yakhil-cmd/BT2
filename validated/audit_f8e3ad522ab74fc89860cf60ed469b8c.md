### Title
Silently ignored delivery-failure of private-payment chains during forwarding - ([File: wallet_general.js])

### Summary
`wallet_general.js`'s `sendPrivatePayments()` forwards private-payment element chains (the actual private asset data a recipient needs to prove and later spend a private-asset output) to the counterparty's device, but the `ifOk`/`ifError` callbacks passed to `device.sendMessageToDevice()` are both empty no-op functions. This mirrors the reported ERC20 pattern: an external "transfer" call is made but its success/failure result is discarded, so the caller proceeds as if the transfer had definitely succeeded.

### Finding Description
`sendPrivatePayments` in [1](#0-0)  is the function used to hand a private-asset payment chain to the receiving device:

```
function sendPrivatePayments(device_address, arrChains, bForwarded, conn, onSaved){
	var body = {chains: arrChains};
	if (bForwarded)
		body.forwarded = true;
	device.sendMessageToDevice(device_address, "private_payments", body, {
		ifOk: function(){},
		ifError: function(){},
		onSaved: onSaved
	}, conn);
}
```

`device.sendMessageToDevice` resolves the correspondent's hub and ultimately calls `sendMessageToHub` / `reliablySendPreparedMessageToHub`, invoking the supplied `ifOk`/`ifError` to report whether the message was actually accepted for delivery to the hub queue [2](#0-1) . Because both handlers here are empty, any delivery failure (e.g., hub rejects the encrypted package, network error, unknown correspondent when `bIgnoreMissingCorrespondents` is not set — which instead throws — or other hub-side error) is swallowed. The caller only relies on `onSaved`, which in the underlying private-payment write flow (`indivisible_asset.js` `preCommitCallback`, and `wallet.js`'s `sendMultiPayment` `preCommitCb`) is used purely to gate commit of the local unit, not to guarantee the recipient actually received the private chain [3](#0-2)  and [4](#0-3) .

This is the same bug class as the DODO finding: a value-carrying "transfer" operation's result is not checked, so the sender's bookkeeping/state (here: the already-signed and about-to-be-committed spend of a private-asset output) advances unconditionally regardless of whether the transfer of the private chain to the counterparty actually succeeded.

### Impact Explanation
For fixed-denomination/private assets, the spend proof and address/blinding revealing information exist only inside the private-element chain sent peer-to-peer; there is no public broadcast of this data (payload_location is "none" for private assets, see `composeIndivisibleAssetPaymentJoint`/`composeDivisibleAssetPaymentJoint` in [5](#0-4) ). If the outbound `private_payments` message silently fails to reach the recipient's hub/device (and the sender's code doesn't detect or retry based on `ifError`), the recipient never learns the details needed to prove ownership of the newly received private coin, effectively freezing/losing those funds for the payee, while the payer's UTXO has already been consumed and the unit committed. This is a fund-loss/freezing condition reachable by any wallet user making an ordinary private-asset payment to another device — no special privilege is required, matching the "AA/wallet fund loss or freezing" acceptance criterion.

### Likelihood Explanation
Likelihood is limited by the fact that the underlying hub protocol is designed to be eventually-consistent (queued messages, hub-side storage) and typical failures may be transient and later retried at a higher layer. However, the code path explicitly discards the direct delivery-confirmation callbacks (`ifOk`/`ifError` are no-ops) at the exact point that matters — the correspondent-lookup/hub-send step — so any hard failure (e.g., correspondent record missing without `bIgnoreMissingCorrespondents`, hub connection error surfaced through `ifError` in `reliablySendPreparedMessageToHub`) is unconditionally ignored instead of bubbling up to alert the user or abort/retry. This makes the loss silent rather than impossible, and it is reachable by any two paired wallets performing a routine private-asset transfer.

### Recommendation
Wire the `ifError` (and ideally `ifOk`) callbacks in `sendPrivatePayments` (wallet_general.js) through to the caller instead of using no-ops, and propagate failures to `onSaved`/`cb` so the private-payment pre-commit flow can retry, warn the user, or abort the unit commit when the private chain fails to reach the counterparty. At minimum, log/surface the error and expose a retry mechanism so private-asset funds are not stranded when peer-to-peer forwarding fails.

### Proof of Concept
1. Alice initiates a private-asset payment to Bob via `wallet.js` `sendMultiPayment`, which for private assets registers a `preCommitCb` that calls `walletGeneral.sendPrivatePayments(recipient_device_address, arrChainsOfRecipientPrivateElements, false, conn, cb2)` (`wallet.js:2402-2429`).
2. `sendPrivatePayments` calls `device.sendMessageToDevice(device_address, "private_payments", body, { ifOk: function(){}, ifError: function(){}, onSaved })` (`wallet_general.js:19-28`).
3. Simulate a hub-side delivery failure inside `reliablySendPreparedMessageToHub` (e.g., mock the hub connection to return an error) — because `ifError` is a no-op, the failure is not observed by `sendPrivatePayments`; `onSaved` is invoked regardless, allowing the pre-commit chain to proceed and the payment unit to be finalized.
4. Bob's device never receives the private element chain containing spend_proof/blinding data for his new output; he cannot construct a valid spend of the received private asset, while Alice's original output is already spent — resulting in loss of the transferred private-asset value.

### Citations

**File:** wallet_general.js (L18-28)
```javascript
// unlike similar function in network, this function sends multiple chains in a single package
function sendPrivatePayments(device_address, arrChains, bForwarded, conn, onSaved){
	var body = {chains: arrChains};
	if (bForwarded)
		body.forwarded = true;
	device.sendMessageToDevice(device_address, "private_payments", body, {
		ifOk: function(){},
		ifError: function(){},
		onSaved: onSaved
	}, conn);
}
```

**File:** device.js (L733-750)
```javascript
function sendMessageToDevice(device_address, subject, body, callbacks, conn){
	if (!device_address)
		throw Error("empty device address");
	conn = conn || db;
	conn.query("SELECT hub, pubkey, is_blackhole FROM correspondent_devices WHERE device_address=?", [device_address], function(rows){
		if (rows.length !== 1 && !conf.bIgnoreMissingCorrespondents)
			throw Error("correspondent not found");
		if (rows.length === 0 && conf.bIgnoreMissingCorrespondents || rows[0].is_blackhole){
			console.log(rows.length === 0 ? "ignoring missing correspondent " + device_address : "not sending to " + device_address + " which is set as blackhole");
			if (callbacks && callbacks.onSaved)
				callbacks.onSaved();
			if (callbacks && callbacks.ifOk)
				callbacks.ifOk();
			return;
		}
		sendMessageToHub(rows[0].hub, rows[0].pubkey, subject, body, callbacks, conn);
	});
}
```

**File:** indivisible_asset.js (L791-801)
```javascript
							var objMessage = {
								app: "payment",
								payload_location: objAsset.is_private ? "none" : "inline",
								payload_hash: payload_hash
							};
							if (objAsset.is_private){
								assocPrivatePayloads[payload_hash] = payload;
								objMessage.spend_proofs = [arrPayloadsWithProofs[i].spend_proof];
							}
							else
								objMessage.payload = payload;
```

**File:** indivisible_asset.js (L869-937)
```javascript
					if (bPrivate){
						preCommitCallback = function(conn, cb){
							async.eachSeries(
								Object.keys(assocPrivatePayloads),
								function(payload_hash, cb2){
									var message_index = composer.getMessageIndexByPayloadHash(objUnit, payload_hash);
									var payload = assocPrivatePayloads[payload_hash];
									// We build, validate, and save two chains: one for the payee, the other for oneself (the change).
									// They differ only in the last element
									async.forEachOfSeries(
										payload.outputs,
										function(output, output_index, cb3){
											// we have only heads of the chains so far. Now add the tails.
											buildPrivateElementsChain(
												conn, unit, message_index, output_index, payload, 
												function(arrPrivateElements){
													validateAndSavePrivatePaymentChain(conn, _.cloneDeep(arrPrivateElements), {
														ifError: function(err){
															cb3(err);
														},
														ifOk: function(){
															if (output.address === to_address)
																arrRecipientChains.push(arrPrivateElements);
															arrCosignerChains.push(arrPrivateElements);
															cb3();
														}
													});
												}
											);
										},
										cb2
									);
								},
								function(err){
									if (err){
										console.log("===== error in precommit callback: "+err);
										bPreCommitCallbackFailed = true;
										return cb(err);
									}
									if (!conf.bLight)
										var onSuccessfulPrecommit = function(err) {
											if (err) {
												bPreCommitCallbackFailed = true;
											}
											return cb(err);
										}
									else 
										var onSuccessfulPrecommit = function(err){
											if (err) {
												bPreCommitCallbackFailed = true;
												return cb(err);
											}
											composer.postJointToLightVendorIfNecessaryAndSave(
												objJoint, 
												function onLightError(err){ // light only
													console.log("failed to post indivisible payment "+unit);
													bPreCommitCallbackFailed = true;
													cb(err); // will rollback
												},
												function save(){ // not actually saving yet but greenlighting the commit
													cb();
												}
											);
										};
									if (!callbacks.preCommitCb)
										return onSuccessfulPrecommit();
									callbacks.preCommitCb(conn, objJoint, arrRecipientChains, arrCosignerChains, onSuccessfulPrecommit);
								}
							);
```

**File:** wallet.js (L2402-2429)
```javascript
						params.callbacks.preCommitCb = function(conn, objJoint, arrChainsOfRecipientPrivateElements, arrChainsOfCosignerPrivateElements, cb){
							if (!arrChainsOfRecipientPrivateElements || !arrChainsOfCosignerPrivateElements)
								throw Error('no private elements');
							var sendToRecipients = function(cb2){
								if (recipient_device_address) {
									walletGeneral.sendPrivatePayments(recipient_device_address, arrChainsOfRecipientPrivateElements, false, conn, cb2);
								} 
								else if (Object.keys(assocAddresses).length > 0) {
									var mnemonic = assocMnemonics[Object.keys(assocMnemonics)[0]]; // TODO: assuming only one textcoin here
									if (typeof opts.getPrivateAssetPayloadSavePath === "function") {
										opts.getPrivateAssetPayloadSavePath(function(fullPath, cordovaPathObj){
											if (!fullPath && (!cordovaPathObj || !cordovaPathObj.fileName)) {
												return cb2("no file path provided for storing private payload");
											}
											storePrivateAssetPayload(fullPath, cordovaPathObj, mnemonic, arrChainsOfRecipientPrivateElements, function(err) {
												if (err)
													throw Error(err);
												saveMnemonicsPreCommit(conn, objJoint, cb2);
											});
										});
									} else {
										throw Error("no getPrivateAssetPayloadSavePath provided");
									}
								}
								else { // paying to another wallet on the same device
									forwardPrivateChainsToOtherMembersOfOutputAddresses(arrChainsOfRecipientPrivateElements, false, conn, cb2);
								}
							};
```
