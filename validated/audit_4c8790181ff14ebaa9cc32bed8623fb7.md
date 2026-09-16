Confirmed: `forwardPrivateChainsToOtherMembersOfOutputAddresses` (in `wallet.js`) collects the union of all output addresses across all chains in the batch, then finds the wallets/devices controlling *any* of those addresses, and forwards the *entire* `arrChains` array (unfiltered, all chains, not just the one(s) relevant to that recipient) to each of them via `forwardPrivateChainsToOtherMembersOfWallets` / `forwardPrivateChainsToOtherMembersOfAddresses`.### Title
Private-payment chain forwarding leaks unrelated recipients' private-asset payment data across output-address scopes - (File: wallet.js)

### Summary
The Linux CVE describes `__netlink_deliver_tap_skb` failing to restrict netlink message observation to the originating namespace, letting a party with limited privilege ("just" CAP_NET_ADMIN on an nlmon interface) observe traffic belonging to other namespaces/processes. The ocore analog is in the private-payment forwarding logic: when a private-asset payment unit has multiple, unrelated output "chains" bundled in a single batch, the forwarding code computes the *union* of all recipients across the whole batch and then sends the *entire unfiltered batch* to each recipient/cosigner device, rather than scoping delivery to only the chain(s) that belong to that recipient.

### Finding Description
`handlePrivatePaymentChains` in `wallet.js` receives an array of private-payment chains (`arrChains`) from a device/hub and, after validating each, calls: [1](#0-0) 

`forwardPrivateChainsToOtherMembersOfOutputAddresses` then aggregates **all** output addresses seen across **every** chain in `arrChains` into one set, and for **each** wallet/address in that combined set, forwards the **whole** `arrChains` array (unfiltered) to the devices controlling that wallet/address: [2](#0-1) 

The same unfiltered-forwarding pattern occurs at composition time in `indivisible_asset.js`'s `getSavingCallbacks`, where `arrCosignerChains` includes chains for *all* output addresses (recipient + change + any other outputs), and the whole `arrCosignerChains` array is forwarded to cosigner devices of the paying/shared address: [3](#0-2) 

The intended privacy boundary for indivisible ("blackbytes"-style) private assets is per-output partial hiding: `buildPrivateElementsChain` deliberately strips `address`/`blinding` from sibling outputs in the payload so that only the output belonging to a specific chain element is revealed: [4](#0-3) 

That output-level hiding is undermined at the batch/forwarding layer: `forwardPrivateChainsToOtherMembersOfOutputAddresses` and `forwardPrivateChainsToOtherMembersOfWallets`/`forwardPrivateChainsToOtherMembersOfAddresses` operate on the full `arrChains`/`arrCosignerChains` list without filtering per-recipient, so a device that legitimately owns one output address in the batch also receives the fully-resolved chains (revealed address + blinding + amount) belonging to *other, unrelated* output addresses in the same unit/batch: [5](#0-4) [6](#0-5) 

This is the direct analog of the CVE's bug class: a legitimate, limited-scope observer (a wallet/device that is a genuine party to *one* output in the batch, analogous to a process with CAP_NET_ADMIN on an nlmon interface) is able to observe private financial data (addresses, blinding factors, amounts) belonging to a different scope (a different recipient's output) that it was never a party to, because the forwarding/broadcast logic does not isolate the confidential payload per recipient namespace.

### Impact Explanation
Successful exploitation discloses confidential financial information — payment addresses, blinding factors, and amounts of a private-asset transfer — to parties who are not the intended recipient or cosigner of that specific output, but merely happen to be a legitimate counterparty on another output in the same batched unit. This is a privacy/confidentiality violation of the private-payment/private-asset feature (aligns with the "AA fund loss or freezing / private chain confidentiality" reachable-impact category via disclosure of private financial data to an unauthorized-but-not-fully-untrusted counterparty), rather than a spend/inflation bug. Severity is Medium, matching the CVE's own Medium/local-information-disclosure classification (CVSS 4.7, confidentiality-only impact).

### Likelihood Explanation
The forwarding path is reachable by any legitimate private-payment counterparty: whenever a private (indivisible or divisible) asset unit contains multiple outputs to different wallets/addresses (e.g., payment + change output, or a payment with several recipients bundled through a shared/multisig address), `forwardPrivateChainsToOtherMembersOfOutputAddresses`/`forwardPrivateChainsToOtherMembersOfWallets` will be invoked with the full multi-output chain set. No malicious peer, hub, or node is required — the sender or receiver simply constructs (or receives) a normal multi-output private-asset payment, which is a standard, supported wallet operation.

### Recommendation
Filter the chains forwarded to each destination wallet/device so that only the chain(s) whose output address is actually owned/controlled by that destination are included, rather than forwarding the full unfiltered `arrChains`/`arrCosignerChains` array to every recipient discovered in the combined output-address set. This applies to `forwardPrivateChainsToOtherMembersOfOutputAddresses` in `wallet.js`, `forwardPrivateChainsToOtherMembersOfWallets` in `wallet_defined_by_keys.js`, `forwardPrivateChainsToOtherMembersOfAddresses` in `wallet_defined_by_addresses.js`, and the cosigner-chain forwarding in `indivisible_asset.js`'s `getSavingCallbacks`.

### Proof of Concept
1. Wallet A composes a private indivisible-asset payment with two outputs in the same message: one to recipient R (a wallet/device not otherwise related to A), and a change output back to A's own shared/multisig address controlled by cosigner C.
2. During `getSavingCallbacks`'s `preCommitCallback`, both `arrRecipientChains` (R's chain) and `arrCosignerChains` (both R's and A's change chain) are built via `buildPrivateElementsChain` (`indivisible_asset.js:863-896`).
3. When the payment is forwarded to cosigner C via `forwardPrivateChainsToOtherMembersOfWallets(arrChainsOfCosignerPrivateElements, [wallet], ...)`, C receives the *entire* `arrCosignerChains`, including the fully-resolved private element for R's output (R's address, blinding, and amount) — data C has no legitimate need to see and is not a party to.
4. Similarly, on receipt at a hub-relay hop, `handlePrivatePaymentChains` → `forwardPrivateChainsToOtherMembersOfOutputAddresses` (`wallet.js:1082-1116`) will forward the complete `arrChains` batch to any wallet matching *any* address in the combined output-address set, exposing other unrelated outputs' private data to that wallet's devices.

### Citations

**File:** wallet.js (L1074-1076)
```javascript
			// forward the chains to other members of output addresses
			if (!body.forwarded)
				forwardPrivateChainsToOtherMembersOfOutputAddresses(arrChains, true);
```

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

**File:** indivisible_asset.js (L619-638)
```javascript
function buildPrivateElementsChain(conn, unit, message_index, output_index, payload, handlePrivateElements){
	var asset = payload.asset;
	var denomination = payload.denomination;
	var output = payload.outputs[output_index];
	var hidden_payload = _.cloneDeep(payload);
	hidden_payload.outputs.forEach(function(o){
		delete o.address;
		delete o.blinding;
		// output_hash was already added
	});
	var arrPrivateElements = [{
		unit: unit,
		message_index: message_index,
		payload: hidden_payload,
		output_index: output_index,
		output: {
			address: output.address,
			blinding: output.blinding
		}
	}];
```

**File:** indivisible_asset.js (L863-896)
```javascript
					var bPrivate = !!assocPrivatePayloads;
					var arrRecipientChains = bPrivate ? [] : null; // chains for to_address
					var arrCosignerChains = bPrivate ? [] : null; // chains for all output addresses, including change, to be shared with cosigners (if any)
					var preCommitCallback = null;
					var bPreCommitCallbackFailed = false;
					
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
```

**File:** wallet_defined_by_keys.js (L828-839)
```javascript
function forwardPrivateChainsToOtherMembersOfWallets(arrChains, arrWallets, bForwarded, conn, onSaved){
	console.log("forwardPrivateChainsToOtherMembersOfWallets", arrWallets);
	conn = conn || db;
	conn.query(
		"SELECT device_address FROM extended_pubkeys WHERE wallet IN(?) AND device_address!=?", 
		[arrWallets, device.getMyDeviceAddress()], 
		function(rows){
			var arrDeviceAddresses = rows.map(function(row){ return row.device_address; });
			walletGeneral.forwardPrivateChainsToDevices(arrDeviceAddresses, arrChains, bForwarded, conn, onSaved);
		}
	);
}
```

**File:** wallet_defined_by_addresses.js (L855-861)
```javascript

```
