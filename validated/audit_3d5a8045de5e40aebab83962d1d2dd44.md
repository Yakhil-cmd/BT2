### Title
Private payment chains are indiscriminately re-broadcast to unrelated cosigner devices during output-address forwarding - (File: wallet.js)

### Summary
The netrc/CVE-2026-6429 bug class is "data scoped to one destination is carried over and disclosed to a different destination when a bulk/forwarding path is followed." The closest reachable analog in ocore is in the receive-side forwarding of private asset payment chains, where a single unscoped forwarding call re-sends an entire batch of private chains to every device that co-owns *any* address touched by that batch, instead of only the chain(s) relevant to that device's own address.

### Finding Description
When a wallet receives private payment chains (`handlePrivatePaymentChains` in [1](#0-0) ), after successful validation it calls `forwardPrivateChainsToOtherMembersOfOutputAddresses(arrChains, true)` ( [2](#0-1) ).

That function collects **all** output addresses across **every chain in the whole batch** into one flat set (`assocOutputAddresses`), with no per-chain/per-address partitioning: [3](#0-2) 

It then resolves *all* wallets/shared-address cosigners that control *any* of those addresses (`readWalletsByAddresses`, `walletDefinedByKeys.forwardPrivateChainsToOtherMembersOfWallets`, `walletDefinedByAddresses.forwardPrivateChainsToOtherMembersOfAddresses`) and forwards the **entire original `arrChains` array** — not just the subset belonging to each recipient's address — to each of them: [4](#0-3) 

The low-level fan-out confirms the same unscoped behavior: `forwardPrivateChainsToDevices` iterates target devices and sends the full `arrChains` to each one via `sendPrivatePayments`, without filtering to the chain(s) that address is actually an output of: [5](#0-4) [6](#0-5) [7](#0-6) 

This mirrors the curl bug pattern exactly: a piece of sensitive data (there, the netrc password; here, the private payment chain — including asset, amounts, blinding factors, addresses, and prior spend history) that is validly scoped to one destination (host / output address) leaks to an unrelated second destination (the redirected-to host / an unrelated shared-address cosigner) purely because the forwarding/batch logic reuses the same connection/payload for multiple destinations without re-scoping it.

### Impact Explanation
Any unprivileged unit poster who can get their address included as one output among several in a batched private-asset payment (e.g., an indivisible/divisible privacy-asset transfer with outputs to multiple different shared addresses in one message) can cause the receiving wallet(s) to leak the full private chain data — including amounts, blinding factors and addresses of *other, unrelated* outputs — to any cosigner of any of the other output addresses in the same batch. This breaks the confidentiality guarantee that is the entire purpose of the private-asset/private-payment-chain mechanism (`private_payment.js`, `indivisible_asset.js`, `divisible_asset.js`), exposing counterparties' spend amounts, blinding data and ownership chains to unrelated third parties who were never a party to that specific output.

### Likelihood Explanation
Reachable by any unprivileged party who can construct or trigger a multi-output private-asset payment/forward (a normal wallet operation, not requiring any special privilege, malicious node, or network position). The forwarding path executes automatically and unconditionally whenever `handlePrivatePaymentChains` succeeds and `body.forwarded` is not set, or when `new_direct_private_chains` fires — no user interaction gating this specific broadcast decision, only the initial receipt of a private-payment message from a paired device.

### Recommendation
In `forwardPrivateChainsToOtherMembersOfOutputAddresses` (and its wallet_defined_by_keys/wallet_defined_by_addresses counterparts), partition `arrChains` per destination address before forwarding: only forward the specific chain(s) whose head-element output address is actually controlled by the target device/wallet/shared-address, instead of broadcasting the full `arrChains` array to every device that matches any address in the combined set.

### Proof of Concept
1. Construct (or receive, as an intermediary) a single "private_payments" batch (`body.chains`) containing two independent private chains: chain A with output address = SharedAddress1 (cosigned by Bob & Carol) and chain B with output address = SharedAddress2 (cosigned by Dave & Eve).
2. Bob's wallet processes the batch via `handlePrivatePaymentChains`; both chain A and chain B validate successfully.
3. `checkIfAllValidated` → `forwardPrivateChainsToOtherMembersOfOutputAddresses(arrChains, true)` executes with the full two-chain `arrChains`.
4. `assocOutputAddresses` = {SharedAddress1, SharedAddress2}; `readWalletsByAddresses`/`readAllControlAddresses` resolve cosigner devices for both, including Carol (SharedAddress1) and Dave/Eve (SharedAddress2).
5. `walletGeneral.forwardPrivateChainsToDevices` sends the **entire** `arrChains` (both chain A and chain B) to Carol, Dave, and Eve alike — so Dave and Eve (who have no relationship to SharedAddress1) receive chain A's private payload (amount, blinding factor, address, ancestor spend chain), which was never meant for them.

Note: I could not fully trace whether the sender-side per-recipient filtering in `indivisible_asset.js`/`divisible_asset.js` (which does scope `arrRecipientChains` to `to_address`) is bypassed in every batching scenario (e.g., `outputs_by_asset` multi-recipient sends); this receive-side re-forwarding path is confirmed unscoped regardless of how the batch originated.

### Citations

**File:** wallet.js (L955-983)
```javascript
function handlePrivatePaymentChains(ws, body, from_address, callbacks){
	var arrChains = body.chains;
	if (!ValidationUtils.isNonemptyArray(arrChains))
		return callbacks.ifError("no chains found");
	if (!arrChains.every(c =>
		isNonemptyArray(c) &&
		c.every(e =>
			isNonemptyObject(e) &&
			isNonemptyString(e.unit) &&
			isNonemptyObject(e.payload) &&
			isNonemptyString(e.payload.asset) &&
			isNonemptyArray(e.payload.inputs) &&
			isNonemptyArray(e.payload.outputs) &&
			e.payload.inputs.every(isNonemptyObject) &&
			e.payload.outputs.every(isNonemptyObject)
		)
	))
		return callbacks.ifError("malformed private chain");
	try {
		var cache_key = objectHash.getBase64Hash(arrChains);
	}
	catch (e) {
		return callbacks.ifError("chains hash failed: " + e.toString());		
	}
	if (handledChainsCache[cache_key]) {
		eventBus.emit('all_private_payments_handled', from_address);
		eventBus.emit('all_private_payments_handled-' + arrChains[0][0].unit);
		return callbacks.ifOk();
	}
```

**File:** wallet.js (L1074-1076)
```javascript
			// forward the chains to other members of output addresses
			if (!body.forwarded)
				forwardPrivateChainsToOtherMembersOfOutputAddresses(arrChains, true);
```

**File:** wallet.js (L1082-1096)
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
```

**File:** wallet.js (L1100-1116)
```javascript
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

**File:** wallet_general.js (L19-39)
```javascript
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

function forwardPrivateChainsToDevices(arrDeviceAddresses, arrChains, bForwarded, conn, onSaved){
	console.log("devices: "+arrDeviceAddresses);
	async.eachSeries(
		arrDeviceAddresses,
		function(device_address, cb){
			console.log("forwarding to device "+device_address);
			sendPrivatePayments(device_address, arrChains, bForwarded, conn, cb);
		},
		onSaved
	);
```

**File:** wallet_defined_by_addresses.js (L531-543)
```javascript
function forwardPrivateChainsToOtherMembersOfAddresses(arrChains, arrAddresses, bForwarded, conn, onSaved){
	conn = conn || db;
	conn.query(
		"SELECT device_address FROM shared_address_signing_paths \n\
		JOIN correspondent_devices USING(device_address) WHERE shared_address IN(?) AND device_address!=?", 
		[arrAddresses, device.getMyDeviceAddress()], 
		function(rows){
			console.log("shared address devices: "+rows.length);
			var arrDeviceAddresses = rows.map(function(row){ return row.device_address; });
			walletGeneral.forwardPrivateChainsToDevices(arrDeviceAddresses, arrChains, bForwarded, conn, onSaved);
		}
	);
}
```

**File:** wallet_defined_by_keys.js (L855-861)
```javascript
function forwardPrivateChainsToOtherMembersOfAddresses(arrChains, arrAddresses, conn, onSaved){
	console.log("forwardPrivateChainsToOtherMembersOfAddresses", arrAddresses);
	conn = conn || db;
	readDeviceAddressesControllingPaymentAddresses(conn, arrAddresses, function(arrDeviceAddresses){
		walletGeneral.forwardPrivateChainsToDevices(arrDeviceAddresses, arrChains, true, conn, onSaved);
	});
}
```
