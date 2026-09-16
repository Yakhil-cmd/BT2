### Title
Unchecked private-payment device-message delivery result causes silent, permanent loss-of-notice for private asset transfers - (File: wallet_general.js)

### Summary
`wallet_general.js`'s `sendPrivatePayments()` sends the encrypted chain of private-payment elements to the recipient's device but discards the actual delivery result (`ifOk`/`ifError` are both no-ops), mirroring the reported pattern of not checking a `transfer()`-like call's success/failure. This is analogous to the unchecked `transfer()` bug: the caller proceeds as if the value (here, the private-payment notification) was successfully delivered, when in fact delivery may have failed and the failure is silently swallowed.

### Finding Description
`sendPrivatePayments` forwards a private-payment chain to a device with hard-coded empty callbacks: [1](#0-0) 

This is the exclusive mechanism used by `sendMultiPayment`'s `preCommitCb` to notify a private-asset recipient (and cosigners) about a payment, right after the paying unit has already been composed/committed: [2](#0-1) 

The only thing actually awaited/checked by the caller is `onSaved` — fired once the message is inserted into the local `outbox` table — not `ifOk`/`ifError`, which reflect the real network delivery outcome: [3](#0-2) [4](#0-3) [5](#0-4) 

Because `ifOk`/`ifError` are no-ops in `sendPrivatePayments`, any delivery error surfaced by `sendPreparedMessageToConnectedHub`'s `handleError` (bad hub response, invalid temp pubkey, failed signature verification, encryption failure, etc.) is discarded. The outbox row is retried periodically by `resendStalledMessages`, but the wallet code that initiated the payment never learns whether the private-payment chain was ever actually delivered — it only knows the message was queued.

### Impact Explanation
Private assets require the actual private-payload chain (unblinded outputs, addresses, blinding factors) to be delivered out-of-band via device messaging; this data cannot be recovered from the public unit alone. If the delivery to the recipient device permanently or persistently fails (e.g., stale/incorrect correspondent pubkey, hub misconfiguration, or any of the various `handleError` paths in `device.js`), the sender's wallet has no signal to retry through another channel, resend manually, or warn the user. The result is that a legitimately paid private-asset output becomes practically inaccessible/frozen for the counterparty, while the sender's wallet reports the payment as successfully sent (since `ifOk`/`ifError` from the actual hub round trip are ignored). This matches the "AA/user fund freezing" impact class: value is transferred on-chain but the recipient can be permanently unable to learn of or spend it, with no error path visible to correct it.

### Likelihood Explanation
This code path is exercised on every private-asset payment made through `sendMultiPayment` (textcoins/private outputs, shared/multisig cosigner forwarding), which is a routine wallet operation for any private-payment counterparty. No malicious peer action is required — a mundane message-delivery hiccup (which is explicitly handled and reported by `device.js`'s `handleError`) is enough to trigger the silent failure, since the reporting path is discarded by the caller.

### Recommendation
Do not discard the `ifOk`/`ifError` results in `sendPrivatePayments` (and its callers in `wallet.js`, `wallet_defined_by_keys.js`, `wallet_defined_by_addresses.js` that use `forwardPrivateChainsToDevices`). Propagate delivery failures to the caller so the wallet can retry via a different channel, alert the user, or otherwise ensure the recipient eventually gets the private-payment chain instead of silently assuming success.

### Proof of Concept
1. Alice sends a private asset (e.g., textcoin/private payment) to Bob via `sendMultiPayment`, which internally calls `walletGeneral.sendPrivatePayments(recipient_device_address, arrChainsOfRecipientPrivateElements, false, conn, cb2)` inside `preCommitCb` [6](#0-5) .
2. `sendPrivatePayments` calls `device.sendMessageToDevice(..., {ifOk: function(){}, ifError: function(){}, onSaved: onSaved}, conn)` [7](#0-6) .
3. The unit is saved/committed once `onSaved` fires (i.e., once the message is merely queued in `outbox`), not once it is actually delivered [8](#0-7) .
4. Suppose Bob's correspondent record has a stale/incorrect `pubkey`; `sendPreparedMessageToConnectedHub` fails signature/temp-pubkey checks and calls `handleError(...)`, which in turn calls `callbacks.ifError(error)` [9](#0-8) .
5. Because `sendPrivatePayments` supplied `ifError: function(){}`, this failure is never surfaced to Alice's wallet UI/logic; Alice believes the payment chain was sent, Bob never receives the private elements needed to detect/spend the payment, and no corrective retry via another channel is triggered.

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

**File:** wallet.js (L2400-2437)
```javascript
						var saveMnemonicsPreCommit = params.callbacks.preCommitCb;
						// save messages in outbox before committing
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
							var sendToCosigners = function(cb2){
								if (wallet)
									walletDefinedByKeys.forwardPrivateChainsToOtherMembersOfWallets(arrChainsOfCosignerPrivateElements, [wallet], false, conn, cb2);
								else // arrPayingAddresses can be only shared addresses
									forwardPrivateChainsToOtherMembersOfSharedAddresses(arrChainsOfCosignerPrivateElements, arrPayingAddresses, null, false, conn, cb2);
							};
							async.series([sendToRecipients, sendToCosigners], cb);
						};
```

**File:** device.js (L584-601)
```javascript
	var message_hash = objectHash.getBase64Hash(objDeviceMessage);
	conn = conn || db;
	conn.query(
		"INSERT INTO outbox (message_hash, `to`, message) VALUES (?,?,?)", 
		[message_hash, recipient_device_address, JSON.stringify(objDeviceMessage)], 
		function(){
			if (callbacks && callbacks.onSaved){
				callbacks.onSaved();
				// db in resendStalledMessages will block until the transaction commits, assuming only 1 db connection
				// (fix if more than 1 db connection is allowed: in this case, it will send only after SEND_RETRY_PERIOD delay)
				process.nextTick(resendStalledMessages);
				// don't send to the network before the transaction commits
				return callbacks.ifOk ? callbacks.ifOk() : null;
			}
			sendPreparedMessageToHub(ws, recipient_device_pubkey, message_hash, json, callbacks);
		}
	);
}
```

**File:** device.js (L603-619)
```javascript
// first param is either WebSocket or hostname of the hub
function sendPreparedMessageToHub(ws, recipient_device_pubkey, message_hash, json, callbacks){
	if (!callbacks)
		return new Promise((resolve) => sendPreparedMessageToHub(ws, recipient_device_pubkey, message_hash, json, { ifOk: resolve, ifError: resolve }));
	if (typeof ws === "string"){
		var hub_host = ws;
		network.findOutboundPeerOrConnect(conf.WS_PROTOCOL+hub_host, function onLocatedHubForSend(err, ws){
			if (err){
				db.query("UPDATE outbox SET last_error=? WHERE message_hash=?", [err, message_hash], function(){});
				return callbacks.ifError(err);
			}
			sendPreparedMessageToConnectedHub(ws, recipient_device_pubkey, message_hash, json, callbacks);
		}, true);
	}
	else
		sendPreparedMessageToConnectedHub(ws, recipient_device_pubkey, message_hash, json, callbacks);
}
```

**File:** device.js (L621-668)
```javascript
// first param is WebSocket only
function sendPreparedMessageToConnectedHub(ws, recipient_device_pubkey, message_hash, json, callbacks){
	network.sendRequest(ws, 'hub/get_temp_pubkey', recipient_device_pubkey, false, function(ws, request, response){
		function handleError(error){
			callbacks.ifError(error);
			db.query("UPDATE outbox SET last_error=? WHERE message_hash=?", [error, message_hash], function(){});
		}
		if (!response)
			return handleError("empty response");
		if (response.error)
			return handleError(response.error);
		var objTempPubkey = response;
		if (!objTempPubkey.temp_pubkey || typeof objTempPubkey.temp_pubkey !== 'string' || !objTempPubkey.pubkey || !objTempPubkey.signature)
			return handleError("missing fields in hub response");
		if (objTempPubkey.pubkey !== recipient_device_pubkey)
			return handleError("temp pubkey signed by wrong permanent pubkey");
		try {
			if (!ecdsaSig.verify(objectHash.getDeviceMessageHashToSign(objTempPubkey), objTempPubkey.signature, objTempPubkey.pubkey))
				return handleError("wrong sig under temp pubkey");
		}
		catch (e) {
			return handleError("temp pub key hash failed: " + e.toString());
		}
		if (!isValidPubKey(objTempPubkey.temp_pubkey))
			return handleError("invalid temp pubkey");
		try {
			var objEncryptedPackage = createEncryptedPackage(json, objTempPubkey.temp_pubkey);
		}
		catch (e) {
			return handleError("failed to encrypt to temp pubkey: " + e.toString());
		}
		var recipient_device_address = objectHash.getDeviceAddress(recipient_device_pubkey);
		var objDeviceMessage = {
			encrypted_package: objEncryptedPackage,
			to: recipient_device_address,
			pubkey: objMyPermanentDeviceKey.pub_b64 // who signs. Essentially, the from again. 
		};
		objDeviceMessage.signature = ecdsaSig.sign(objectHash.getDeviceMessageHashToSign(objDeviceMessage), objMyPermanentDeviceKey.priv);
		network.sendRequest(ws, 'hub/deliver', objDeviceMessage, false, function(ws, request, response){
			if (response === "accepted"){
				db.query("DELETE FROM outbox WHERE message_hash=?", [message_hash], function(){
					callbacks.ifOk();
				});
			}
			else
				handleError( response?.error || ("unrecognized response: " + util.inspect(response, { depth: 5 })) );
		});
	});
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
