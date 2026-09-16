### Title
Malicious paired device can get automatically forwarded historical private-payment chains by injecting a shared-address membership record - (File: wallet_defined_by_addresses.js)

### Summary
This is analogous to GHSA-qcvh-p9jq-wp8v: instead of a homeserver injecting a device into a room to receive historical message keys "on invite," a paired ocore device can send a `new_shared_address` message that records itself as a controlling device of an address, causing the recipient's wallet to subsequently and automatically forward full historical private-payment chains (blinding factors, amounts, and the whole spend history) to that device whenever a private-asset payment later touches that address.

### Finding Description
When ocore receives a private payment chain, either as the direct payee/cosigner or by simply observing an output address, it automatically re-forwards the entire chain (not just the new output, but the full chronological chain of `arrPrivateElements`, including blinding factors) to every device address that the local database considers a "controller" of that address: [1](#0-0) 

`forwardPrivateChainsToOtherMembersOfOutputAddresses` resolves controllers via `walletDefinedByAddresses.forwardPrivateChainsToOtherMembersOfAddresses`, which queries the `shared_address_signing_paths` table for any device correspondent associated with the address and unconditionally forwards the chain to it: [2](#0-1) 

Similarly, `forwardPrivateChainsToOtherMembersOfSharedAddresses` treats the *author* addresses of a received private-payment unit as potential "shared addresses" and forwards to every device listed as controlling them, again without checking whether that device was part of the original transaction: [3](#0-2) 

The `shared_address_signing_paths` table that drives this forwarding is populated from **unsolicited peer-supplied data**. A paired device can send a `new_shared_address` message (handled without requiring the local user's initiation or consent) that is inserted directly into this table: [4](#0-3) [5](#0-4) 

The only checks performed are that `body.address` really is the chash160 of `body.definition`, and that referenced member addresses match the definition — there is no check that the *local user* ever agreed to add this new peer device as a "signer"/"member" of any of their addresses, nor that the private-payment-forwarding trust relationship is desired. Once such a shared-address record exists that references one of the victim's own addresses as a "member," subsequent private-asset payments touching that address are forwarded — via `forwardPrivateChainsToOtherMembersOfSharedAddresses` / `forwardPrivateChainsToOtherMembersOfAddresses` — to the attacker's device, exactly like the Matrix bug's "share historical keys on invite" pattern: an action that merely adds a party to a group/definition ends up automatically leaking the full history of private cryptographic payment data to that party.

This mirrors the root cause identified in the advisory: functionality that shares historical secret payment/session data is triggered automatically by a routine membership-management event (accepting/recording a new address definition / room invite) rather than by an explicit, minimal, need-to-know disclosure decision.

### Impact Explanation
Successful exploitation discloses the full historical private-payment chain (`arrPrivateElements`) for the victim's private-asset outputs to an attacker-controlled device: blinding factors, `output` addresses, amounts and the complete lineage of the private asset. This lets the attacker learn amounts/addresses of past private transactions belonging to the victim which were never intended to be shared with them, i.e., confidentiality loss over private-payment data (CWE-200 analog). It does not directly enable spending or double-spend because private elements without signing keys are informational for the ledger; the leak is confined to private-asset transaction history/amounts, matching the "medium/high, no direct spend" character of the original CVE-2024-47824 (CVSS: C:N/I:N/A:N — high confidentiality-only class, matching an information-disclosure severity).

### Likelihood Explanation
The forwarding functions are reached by any already-paired correspondent device without requiring hub/network compromise — sending a `new_shared_address` (device message) and later observing/triggering a private-asset payment. This is reachable by a normal correspondent ("paired device"), which is in scope per the analysis rules. However, exploitation requires that the victim's wallet actually engages in a private-asset transaction on an address that got polluted by the forged shared-address record, and requires knowledge of/collision on chash160 constraints that limit which existing address can be targeted — this substantially reduces likelihood versus a purely automatic leak, since (per code) the newly created `shared_address` is a fresh multisig hash the definition produces, and the victim's *existing* private-asset address can only become "controlled" by an attacker device if the local wallet is tricked into treating that specific existing address as a shared/member address, which the code paths shown allow via `shared_address_signing_paths` insertion referencing an already-existing member address without requiring prior consent to associate the attacker's device.

### Recommendation
- Require explicit local-user confirmation before creating a `shared_address_signing_paths` binding that associates a peer device as controller/cosigner of one of the local wallet's existing addresses (`handleNewSharedAddress` / `addNewSharedAddress`).
- Before automatically forwarding private-payment chains in `forwardPrivateChainsToOtherMembersOfOutputAddresses`, `forwardPrivateChainsToOtherMembersOfAddresses`, and `forwardPrivateChainsToOtherMembersOfSharedAddresses`, verify that the destination device was actually a participant (author, or previously-approved cosigner with signing history) in the transaction chain being forwarded, not merely a database-recorded "member" that could have been added via an unsolicited peer message.
- Apply the same minimization principle referenced in the advisory: only forward the specific new increment of the private chain to a device that needs it to verify or countersign the immediate transaction, not the complete historical chain, unless the recipient explicitly requests/needs full history (e.g., wallet recovery flows).

### Proof of Concept
1. Attacker device D pairs with victim device V (a normal correspondent relationship, not requiring pre-existing shared address).
2. Attacker sends a `new_shared_address` message to V referencing V's already-controlled address `A` as a `signers` entry with `signing_path` mapped to `A`, and D's own address as another signer, producing `shared_address = chash160(definition)`. V's handler `handleNewSharedAddress` validates the chash and definition and calls `addNewSharedAddress`, inserting `shared_address_signing_paths` rows that associate address `A` (and D as `device_address`) with the new shared address record: [5](#0-4) 
3. Victim later sends or receives a private-asset payment through address `A`. `handlePrivatePaymentChains`/`forwardPrivateChainsToOtherMembersOfOutputAddresses` looks up devices "controlling" the address via `shared_address_signing_paths` and forwards the entire historical `arrPrivateElements` chain to D: [1](#0-0) [2](#0-1) 
4. D now has the full private-payment history for the victim's private-asset activity on `A`, disclosed without ever being an intended party to those transactions.

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

**File:** wallet_defined_by_addresses.js (L239-268)
```javascript
function addNewSharedAddress(address, arrDefinition, assocSignersByPath, bForwarded, onDone){
//	network.addWatchedAddress(address);
	db.query(
		"INSERT "+db.getIgnore()+" INTO shared_addresses (shared_address, definition) VALUES (?,?)", 
		[address, JSON.stringify(arrDefinition)], 
		function(){
			var arrQueries = [];
			for (var signing_path in assocSignersByPath){
				var signerInfo = assocSignersByPath[signing_path];
				db.addQuery(arrQueries, 
					"INSERT "+db.getIgnore()+" INTO shared_address_signing_paths \n\
					(shared_address, address, signing_path, member_signing_path, device_address) VALUES (?,?,?,?,?)", 
					[address, signerInfo.address, signing_path, signerInfo.member_signing_path, signerInfo.device_address]);
			}
			async.series(arrQueries, function(){
				console.log('added new shared address '+address);
				eventBus.emit("new_address-"+address);
				eventBus.emit("new_address", address);

				if (conf.bLight){
					db.query("INSERT " + db.getIgnore() + " INTO unprocessed_addresses (address) VALUES (?)", [address], onDone);
				} else if (onDone)
					onDone();
				if (!bForwarded)
					forwardNewSharedAddressToCosignersOfMyMemberAddresses(address, arrDefinition, assocSignersByPath);
			
			});
		}
	);
}
```

**File:** wallet_defined_by_addresses.js (L377-415)
```javascript
// {address: "BASE32", definition: [...], signers: {...}}
function handleNewSharedAddress(body, callbacks){
	if (!ValidationUtils.isArrayOfLength(body.definition, 2))
		return callbacks.ifError("invalid definition");
	if (typeof body.signers !== "object" || Object.keys(body.signers).length === 0)
		return callbacks.ifError("invalid signers");
	try {
		var addr = objectHash.getChash160(body.definition);
	}
	catch (e) {
		return callbacks.ifError("invalid definition: " + e);
	}
	if (body.address !== addr)
		return callbacks.ifError("definition doesn't match its c-hash");
	for (var signing_path in body.signers){
		var signerInfo = body.signers[signing_path];
		if (signerInfo.address && signerInfo.address !== 'secret' && !ValidationUtils.isValidAddress(signerInfo.address))
			return callbacks.ifError("invalid member address: " + JSON.stringify(signerInfo.address));
	}
	const assocDefinitionAddresses = extractAddressPathsFromDefinition(body.definition);
	for (let signing_path in body.signers) {
		const signerInfo = body.signers[signing_path];
		if (assocDefinitionAddresses[signing_path] !== signerInfo.address)
			return callbacks.ifError("signer address at path " + signing_path + " doesn't match definition");
	}
	for (let def_path in assocDefinitionAddresses) {
		if (!body.signers[def_path])
			return callbacks.ifError("no signer for definition address at path " + def_path);
	}
	determineIfIncludesMeAndRewriteDeviceAddress(body.signers, function(err){
		if (err)
			return callbacks.ifError(err);
		validateAddressDefinition(body.definition, function(err){
			if (err)
				return callbacks.ifError(err);
			addNewSharedAddress(body.address, body.definition, body.signers, body.forwarded, callbacks.ifOk);
		});
	});
}
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
