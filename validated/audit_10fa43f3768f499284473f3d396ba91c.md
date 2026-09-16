### Title
Private-asset payments can be finalized on-chain while the required proof chain is silently dropped for an unknown/mistyped recipient device address, permanently freezing the transferred funds - (File: `wallet.js`, `wallet_general.js`, `device.js`)

### Summary
`bridgeAsset()`/`bridgeMessage()` in the referenced report move value to a `destinationNetwork` without confirming that destination is real, so funds can be stranded if the network never exists. The analogous weakness in ocore is in the private-asset payment flow: `sendMultiPayment()` in `wallet.js` broadcasts/commits the on-chain payment and then hands off delivery of the mandatory private-chain proof to `walletGeneral.sendPrivatePayments()`, which calls `device.sendMessageToDevice()`. That function only "delivers" the message if the target is a *known correspondent*; if it is unknown, the outcome depends on `conf.bIgnoreMissingCorrespondents` and either throws or silently succeeds without ever queuing anything to reach the intended party. There is no requirement that the destination device_address correspond to a real, reachable correspondent before the private-asset transfer is treated as committed.

### Finding Description
For private (indivisible/hidden) assets, ownership after a transfer can only be proven with the full chain of `payload`/`spend_proof` elements built by `buildPrivateElementsChain()`; the on-chain output alone is not sufficient to prove or later spend the coin (this is why `sendMultiPayment` sets up `preCommitCb` specifically to forward `arrChainsOfRecipientPrivateElements` before finalizing).

In `wallet.js`: [1](#0-0) 
`sendToRecipients` calls `walletGeneral.sendPrivatePayments(recipient_device_address, arrChainsOfRecipientPrivateElements, false, conn, cb2)`.

`sendPrivatePayments` treats delivery as fire-and-forget - both `ifOk` and `ifError` are no-ops, and only `onSaved` (i.e., "queued") gates the precommit `cb2`: [2](#0-1) 

`device.sendMessageToDevice()` is the function that actually decides whether the message can even be queued. It requires the `device_address` to exist in `correspondent_devices`; if not found: [3](#0-2) 
- If `conf.bIgnoreMissingCorrespondents` is falsy, it `throw`s inside a DB callback (unhandled/uncaught in normal async flow).
- If `conf.bIgnoreMissingCorrespondents` is truthy (or the correspondent is blackholed), it silently logs "ignoring missing correspondent" and immediately invokes `callbacks.onSaved()`/`callbacks.ifOk()` **without ever writing anything to the outbox or notifying anyone**.

Because `onSaved` is exactly what the precommit logic in `wallet.js` treats as "delivery handled," the private-chain-forwarding step reports success even though the chain was never transmitted anywhere. The public/base-currency payment for the transaction fee and the private asset's on-chain (hidden) output are still written and broadcast by `writer.saveJoint`, exactly as in the reported bridge bug where the bridge contract still transfers funds while ignoring whether `destinationNetwork` is valid.

There is no independent validation elsewhere in the payment-composition path (`composeIndivisibleAssetPaymentJoint`, `getSavingCallbacks`, `validatePayment`/`validatePaymentInputsAndOutputs` in `validation.js`) that the `recipient_device_address` used for private-chain delivery is a real, currently reachable correspondent capable of receiving and later forwarding/proving the private chain. The recipient's payment `address` field is checked only for base32-format validity (`isValidAddressWithCase`), not for reachability of the associated device.

### Impact Explanation
If a wallet user (an ordinary private-payment counterparty/sender - one of the explicitly in-scope actors) supplies a mistyped, stale, or otherwise non-existent `recipient_device_address` while sending a private asset, and the runtime has `conf.bIgnoreMissingCorrespondents` enabled (a supported, non-privileged configuration path used to tolerate unpaired/indirect recipients), the transaction is committed and broadcast on the DAG, consuming real, transferable value, but the private-chain proof that the recipient needs to ever spend or even acknowledge the coin is never generated or transmitted to anyone. Because private-asset ownership requires the full provenance chain (not just a valid-looking output on the DAG), the transferred funds become permanently unspendable/unprovable for the intended recipient and unrecoverable for the sender, matching the "funds sent to a non-existing destination become inaccessible and lost" impact class from the report - here it is a fund-freezing bug for anyone using the private-payment flow.

### Likelihood Explanation
Any wallet user composing a private-asset payment supplies `recipient_device_address` as ordinary user input (a pairing code / device address string), with no protocol-level requirement that the address currently be a live correspondent. Typos, expired pairings, or removed correspondents are common real-world occurrences, and the failure mode (silent success reported via `onSaved`) is indistinguishable from a normal successful send unless the configuration flag happens to cause a hard throw instead. This makes the bug reachable through routine, unprivileged usage rather than requiring any special access.

### Recommendation
Before finalizing (in the precommit stage of) a private-asset payment, positively verify that `recipient_device_address` resolves to a live correspondent capable of receiving the private chain, and fail the entire transaction (abort the precommit, causing rollback) if it does not, rather than treating an "ignored missing correspondent" as a successful delivery. At minimum, `walletGeneral.sendPrivatePayments()` should surface delivery failures (not swallow them via no-op `ifError`) so `sendToRecipients`/`preCommitCb` can properly reject the commit, and the `bIgnoreMissingCorrespondents` fallback path in `device.js` should not silently report success for time-critical, funds-bearing private-payment deliveries.

### Proof of Concept
1. Configure a node/wallet with `conf.bIgnoreMissingCorrespondents = true` (an existing, supported configuration option, per `device.js`).
2. Call `wallet.sendMultiPayment()` with a private (`is_private`) asset, specifying a `recipient_device_address` that is not present in `correspondent_devices` (e.g., a mistyped or unpaired device pubkey-derived address).
3. Observe that `getSavingCallbacks`'s `preCommitCallback` proceeds through `sendToRecipients` → `walletGeneral.sendPrivatePayments` → `device.sendMessageToDevice`, which logs "ignoring missing correspondent" and calls `onSaved()` immediately: [4](#0-3) 
4. The precommit therefore succeeds, `writer.saveJoint` commits the unit, and `network.broadcastJoint(objJoint)` is invoked in `wallet.js`: [5](#0-4) 
5. No `private_payments` device message was ever created or queued; the recipient has no way to obtain `arrRecipientChains` and can never prove or spend the private-asset output, while the sender has already relinquished on-chain custody of the funds - a full analog of "funds sent to a non-existing destination are inaccessible and lost."

*Note: I was unable to fully trace how a synchronous `throw` inside the `db.query` callback (`device.js` line 738-739, `bIgnoreMissingCorrespondents=false` path) propagates through the `mutex`/`async` chain used by `writer.saveJoint`'s precommit machinery; that alternate failure mode may or may not correctly abort/rollback the transaction, and would need direct testing to confirm whether it also leads to fund loss or is safely caught elsewhere.*

### Citations

**File:** wallet.js (L2277-2288)
```javascript
					ifOk: function(objJoint, arrChainsOfRecipientPrivateElements, arrChainsOfCosignerPrivateElements){
						if (opts.compose_only)
							return handleResult(null, objJoint.unit.unit, assocMnemonics, objJoint.unit);
						network.broadcastJoint(objJoint);
						if (!arrChainsOfRecipientPrivateElements){ // send notification about public payment
							if (recipient_device_address)
								walletGeneral.sendPaymentNotification(recipient_device_address, objJoint.unit.unit);
							if (recipient_device_addresses)
								recipient_device_addresses.forEach(function(r_device_address){
									walletGeneral.sendPaymentNotification(r_device_address, objJoint.unit.unit);
								});
						}
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

**File:** wallet_general.js (L18-27)
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
