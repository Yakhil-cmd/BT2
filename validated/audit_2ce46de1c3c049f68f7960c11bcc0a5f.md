### Title
Private-payment "shares" (output ownership) and "state" (spendability proof) are split between unvalidated `to_address` and `recipient_device_address` - (File: wallet.js)

### Summary
The external report describes a class of bug where the entity that receives the transferable asset (ERC20 shares) is different from the entity for which the internal accounting/state needed to redeem those shares is created (controller vs. receiver), so neither party can actually use the funds. The closest reachable analog in ocore is in the private-asset payment flow in `wallet.js`, where the on-chain output owner (`to_address`) and the off-chain recipient of the private-payment proof chain (`recipient_device_address`) are two independently supplied, unvalidated parameters.

### Finding Description
When composing a payment of a private asset, `sendMultiPayment`/`sendPaymentFromWallet` accept both `to_address` (the address that will actually own the output on the DAG - the "shares") and, separately, `recipient_device_address` (the device that will be sent the private element chain - i.e., the blinding/amount proof required to prove and later spend that output - analogous to the vault's internal `state`/cost-basis). [1](#0-0) 

In the pre-commit callback, the private chains that reveal the output for `to_address` are sent only to `recipient_device_address` via `walletGeneral.sendPrivatePayments`, with no check that `recipient_device_address` is actually a device controlling `to_address`: [2](#0-1) 

The underlying private-payment building code confirms that only the chain whose head output address equals `to_address` is treated as "the recipient chain" that gets sent out: [3](#0-2) 

Separately, `forwardPrivateChainsToOtherMembersOfOutputAddresses` re-derives recipients purely from `output.address` in the payload and looks up wallets by that address - this is the correct, self-consistent path, but it is only used as a fallback ("paying to another wallet on the same device") and is bypassed entirely whenever `recipient_device_address` is explicitly supplied: [4](#0-3) [5](#0-4) 

Because `to_address` and `recipient_device_address` are independent caller-supplied values, they can diverge: `to_address` could be an address not actually controlled by `recipient_device_address`, or vice-versa. Since Obyte private assets (`is_private: true`, e.g. indivisible/black-byte-style assets) can only be validated and later spent by whoever possesses the private element chain (the `blinding`, `output_hash` preimages, and spend proof), this creates exactly the split described in the report:
- The DAG-level output (the "shares"/ownership) is created for `to_address`.
- The off-chain state required to actually use/redeem that ownership (the private chain / blinding data, analogous to `SuperVaultStrategy.state`/cost basis) is delivered only to `recipient_device_address`.

If these two do not correspond to the same real-world controller, the address that legitimately owns the output cannot reconstruct the private chain (it never learns the blinding factors) and therefore cannot spend/prove the private output, while the device that did receive the chain has no claim on `to_address`'s funds because it doesn't control that address's private key. This is the direct analog of the report's core defect: "shares" (ERC20 mint / DAG output) go to one identity while the accompanying internal state needed to redeem/spend goes to a different, disconnected identity.

### Impact Explanation
For private, indivisible or divisible assets sent through this code path, a mismatch between `to_address` and `recipient_device_address` results in permanently unspendable ("frozen") funds for the legitimate output owner, since Obyte's privacy model requires possession of the off-chain proof chain to prove and spend a private output; there is no on-chain fallback to recover this proof. This matches the "AA fund loss or freezing" / "unauthorized inability to redeem" impact category, scoped to the private-payment counterparty who is reachable by simply being given (or specifying) inconsistent `to_address`/`recipient_device_address` values when composing or receiving a private payment.

### Likelihood Explanation
`recipient_device_address` and `to_address` are both externally influenced parameters passed into `sendMultiPayment`/`sendPaymentFromWallet` (e.g., by calling UI code, third-party integrations, or a malicious/buggy counterparty relaying the payment request). There is no code path that cross-checks these two values belong to the same wallet/device before the chain is dispatched only to `recipient_device_address`, so any caller (a private-payment counterparty) that supplies mismatched values, or any integration bug that decouples the "pay to" address from the "notify" device, reliably reproduces the freezing condition. I was not able to fully trace every caller of `sendMultiPayment` (e.g., textcoin flows, GUI wallets, arbiter contract flows) within the tool-call budget to confirm whether a higher-level caller always guarantees `to_address` and `recipient_device_address` correspond; this should be verified against all call sites before treating this as a confirmed, exploitable issue in a specific caller path.

### Recommendation
Before forwarding recipient private chains only to `recipient_device_address`, validate that `recipient_device_address` is a known correspondent/device that actually controls `to_address` (e.g., cross-check against `my_addresses`/`shared_address_signing_paths`/`peer_addresses`, similar to what `forwardPrivateChainsToOtherMembersOfOutputAddresses`/`readWalletsByAddresses` already do). If no such correspondence can be established, either reject the payment composition or additionally forward the recipient chain through the address-based path (`forwardPrivateChainsToOtherMembersOfOutputAddresses`) so that whichever device truly controls `to_address` also receives the proof chain needed to spend it.

### Proof of Concept
Conceptual PoC (not executed, given tool limitations):
1. Wallet A composes a private-asset payment via `sendPaymentFromWallet`/`sendMultiPayment` with `to_address = X` (an address it does not itself control, e.g. belonging to Wallet C) and `recipient_device_address = B` (a correspondent device unrelated to address X). [1](#0-0) 
2. The private chain for the output at address X is computed and sent exclusively to device B: `walletGeneral.sendPrivatePayments(recipient_device_address, arrChainsOfRecipientPrivateElements, ...)`. [5](#0-4) 
3. The unit is committed on-chain: output at address X now exists (the "shares"), owned in ledger terms by whoever controls X.
4. Wallet C (real controller of X) never receives the private element chain (blinding/output_hash preimages) because it was only sent to device B, and has no way to reconstruct it from the public ledger alone (private outputs deliberately hide `address`/`blinding` from anyone but the chain holder).
5. Device B has the chain data but cannot spend the output because it does not control the private key for address X.
Result: the asset output at X is permanently unspendable by anyone, mirroring the reported "receiver has shares but no usable state, controller has state but no shares" freezing pattern.

### Citations

**File:** wallet.js (L1082-1116)
```javascript
function forwardPrivateChainsToOtherMembersOfOutputAddresses(arrChains, bForwarded, conn, onSaved){
	console.log("forwardPrivateChainsToOtherMembersOfOutputAddresses", arrChains);
	var assocOutputAddresses = {};
	arrChains.forEach(function(arrPrivateElements){
		var objHeadPrivateElement = arrPrivateElements[0];
		var payload = objHeadPrivateElement.payload;
		payload.outputs.forEach(function(output){
			if (output.address)
				assocOutputAddresses[output.address] = true;
		});
		if (objHeadPrivateElement.output && objHeadPrivateElement.output.address)
			assocOutputAddresses[objHeadPrivateElement.output.address] = true;
	});
	var arrOutputAddresses = Object.keys(assocOutputAddresses);
	console.log("output addresses", arrOutputAddresses);
	conn = conn || db;
	if (!onSaved)
		onSaved = function(){};
	readWalletsByAddresses(conn, arrOutputAddresses, function(arrWallets){
		if (arrWallets.length === 0){
		//	breadcrumbs.add("forwardPrivateChainsToOtherMembersOfOutputAddresses: " + JSON.stringify(arrChains)); // remove in livenet
		//	eventBus.emit('nonfatal_error', "not my wallet? output addresses: "+arrOutputAddresses.join(', '), new Error());
		//	throw Error("not my wallet? output addresses: "+arrOutputAddresses.join(', '));
		}
		var arrFuncs = [];
		if (arrWallets.length > 0)
			arrFuncs.push(function(cb){
				walletDefinedByKeys.forwardPrivateChainsToOtherMembersOfWallets(arrChains, arrWallets, bForwarded, conn, cb);
			});
		arrFuncs.push(function(cb){
			walletDefinedByAddresses.forwardPrivateChainsToOtherMembersOfAddresses(arrChains, arrOutputAddresses, bForwarded, conn, cb);
		});
		async.series(arrFuncs, onSaved);
	});
}
```

**File:** wallet.js (L1954-1967)
```javascript
function sendPaymentFromWallet(
		asset, wallet, to_address, amount, change_address, arrSigningDeviceAddresses, recipient_device_address, signWithLocalPrivateKey, handleResult)
{
	sendMultiPayment({
		asset: asset,
		wallet: wallet,
		to_address: to_address,
		amount: amount,
		change_address: change_address,
		arrSigningDeviceAddresses: arrSigningDeviceAddresses,
		recipient_device_address: recipient_device_address,
		signWithLocalPrivateKey: signWithLocalPrivateKey
	}, handleResult);
}
```

**File:** wallet.js (L2399-2429)
```javascript
					if (objAsset.is_private){
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
```

**File:** indivisible_asset.js (L882-896)
```javascript
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
```
