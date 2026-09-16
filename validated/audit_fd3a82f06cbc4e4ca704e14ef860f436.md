### Title
Unrelated private-payment chains are batch-forwarded to cosigners of any shared address involved in a multi-chain message - ([File: wallet.js])

### Summary
`handlePrivatePaymentChains` in `wallet.js` receives a `chains` array from any correspondent device (a private-payment counterparty) and, once all chains validate, forwards the *entire* `arrChains` batch to the cosigners of *every* author address found across *all* chains combined, instead of forwarding only the chain(s) that actually belong to each specific shared address. This mirrors the Discourse bug class: a broad "you're in this group" check (cosigner of some address referenced in the batch) grants access to sensitive content (another party's private payment chain: amounts, addresses, asset) that the recipient was never a party to.

### Finding Description
`handlePrivatePaymentChains(ws, body, from_address, callbacks)` accepts `body.chains`, an array of independent private-payment chains, from a paired device [1](#0-0) . After validating each chain individually, `checkIfAllValidated` computes the set of unit authors across *all* chains in the batch and forwards the *whole* `arrChains` array to the cosigners of those combined author addresses: [2](#0-1) 

`forwardPrivateChainsToOtherMembersOfSharedAddresses` then takes this combined `arrChains` and the combined `arrPayingAddresses`, resolves all cosigner devices of those addresses, and sends them the complete chain list via `forwardPrivateChainsToDevices`: [3](#0-2) [4](#0-3) 

`forwardPrivateChainsToDevices`/`sendPrivatePayments` sends the raw chain array (`{chains: arrChains}`) unfiltered to each resolved device [5](#0-4) . There is no per-chain filtering step matching each shared address to only the chain(s) it actually authored/is party to before this fan-out; the filtering is done once at the "batch" level (`arrAuthorAddresses`) but the forwarded payload is the unfiltered `arrChains`.

The same pattern also exists in `forwardPrivateChainsToOtherMembersOfOutputAddresses`, which aggregates `assocOutputAddresses` from *all* chains in the batch and then forwards the full `arrChains` to wallets/cosigners of any of those output addresses [6](#0-5) .

### Impact Explanation
A malicious private-payment counterparty (paired device) can bundle a victim's legitimate private chain together with one or more attacker-crafted/unrelated private chains (for a different asset, different amount, or different counterparty) in a single `private_payments`/`private_payment_chains` message. If the victim's device is a cosigner of a shared address that authored/received only one of the bundled chains, the forwarding logic will still relay the *entire* batch — including the unrelated chain's addresses, amounts, and asset — to every cosigner device of that shared address. Those cosigners were never a party to the unrelated payment and have no legitimate reason to see it, resulting in disclosure of private-payment content (title/asset/amount/address analog of the Discourse shared-draft title/excerpt leak) to unauthorized parties. This is an information-disclosure issue affecting the confidentiality guarantee of "private" assets/payments, which is a core security property of ocore's private-payment feature.

### Likelihood Explanation
Reachable purely through the device-messaging protocol from any existing private-payment counterparty/paired device — no special privilege beyond being a device correspondent is required, and `body.chains` is attacker-controlled (any nonempty array of well-formed chain objects passes the input checks in `handlePrivatePaymentChains`) [7](#0-6) . Constructing a batch that mixes a genuine chain with an unrelated one is straightforward for a counterparty who already exchanges private payments with the victim, making exploitation moderately easy once the pattern is understood.

### Recommendation
Filter `arrChains` per shared/output address before forwarding: for each destination shared address (or wallet), forward only the chains whose author (or output) address actually matches that shared/wallet address, rather than aggregating all author/output addresses across the batch and sending the union of chains to the union of cosigner devices. Apply this fix in both `forwardPrivateChainsToOtherMembersOfSharedAddresses`/`checkIfAllValidated` and `forwardPrivateChainsToOtherMembersOfOutputAddresses` in `wallet.js`.

### Proof of Concept
1. Attacker device D is a correspondent of victim device V and is also a cosigner (via `shared_address_signing_paths`) on shared address `S` together with V.
2. D sends V a `private_payments` message with `body.chains = [chain_S, chain_X]`, where `chain_S` is a legitimate private payment involving shared address `S`, and `chain_X` is an unrelated private payment between D and a third, uninvolved party (different asset/amount/addresses).
3. V's `handlePrivatePaymentChains` validates both chains (each independently well-formed) and, in `checkIfAllValidated`, collects `arrAuthorAddresses` including `S`, then calls `forwardPrivateChainsToOtherMembersOfSharedAddresses(arrChains, arrAuthorAddresses, ...)` passing the full `[chain_S, chain_X]` array.
4. All other cosigners of `S` (who never received or were shown `chain_X`) are sent the full `arrChains`, including `chain_X`, via `forwardPrivateChainsToDevices` → `sendPrivatePayments`, disclosing the unrelated party's private payment details to them.

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

**File:** wallet.js (L1007-1016)
```javascript
		if (!body.forwarded){
			if (from_address) emitNewPrivatePaymentReceived(from_address, arrChains, current_message_counter);
			// note, this forwarding won't work if the user closes the wallet before validation of the private chains
			var arrUnits = arrChains.map(function(arrPrivateElements){ return arrPrivateElements[0].unit; });
			db.query("SELECT address FROM unit_authors WHERE unit IN(?)", [arrUnits], function(rows){
				var arrAuthorAddresses = rows.map(function(row){ return row.address; });
				// if the addresses are not shared, it doesn't forward anything
				forwardPrivateChainsToOtherMembersOfSharedAddresses(arrChains, arrAuthorAddresses, from_address, true);
			});
		}
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

**File:** wallet.js (L2520-2533)
```javascript
function forwardPrivateChainsToOtherMembersOfSharedAddresses(arrChainsOfCosignerPrivateElements, arrPayingAddresses, excluded_device_address, bForwarded, conn, onDone){
	walletDefinedByAddresses.readAllControlAddresses(conn, arrPayingAddresses, function(arrControlAddresses, arrControlDeviceAddresses){
		arrControlDeviceAddresses = arrControlDeviceAddresses.filter(function(device_address) {
			return (device_address !== device.getMyDeviceAddress() && device_address !== excluded_device_address);
		});
		walletDefinedByKeys.readDeviceAddressesControllingPaymentAddresses(conn, arrControlAddresses, function(arrMultisigDeviceAddresses){
			arrMultisigDeviceAddresses = _.difference(arrMultisigDeviceAddresses, arrControlDeviceAddresses);
			// counterparties on shared addresses must forward further, that's why bForwarded=false
			walletGeneral.forwardPrivateChainsToDevices(arrControlDeviceAddresses, arrChainsOfCosignerPrivateElements, bForwarded, conn, function(){
				walletGeneral.forwardPrivateChainsToDevices(arrMultisigDeviceAddresses, arrChainsOfCosignerPrivateElements, true, conn, onDone);
			});
		});
	});
}
```

**File:** wallet_general.js (L19-40)
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
}
```
