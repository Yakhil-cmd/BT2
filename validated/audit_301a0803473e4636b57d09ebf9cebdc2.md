This confirms the analog. Now let me verify the private-payment forwarding path that uses `shared_address_signing_paths` to send private chains to the newly-registered attacker device, and check `walletGeneral.forwardPrivateChainsToDevices` to close the loop on data exposure.### Title
Unsolicited `new_shared_address` device messages let a remote correspondent silently register a wallet's existing address into an attacker-controlled shared address, leaking private payment chains without consent - (File: wallet_defined_by_addresses.js)

### Summary
The `new_shared_address` device message handler accepts an unsolicited shared-address definition from any paired correspondent device and permanently registers it as a "shared address" the moment it references one of the recipient's own addresses — with no check that the recipient ever requested or agreed to that specific multisig arrangement. This mirrors the Mattermost flaw where an unsolicited invite referencing an existing local channel ID silently converts it into a shared resource without local admin consent.

### Finding Description
`wallet.js`'s `handleMessageFromHub` dispatches the `"new_shared_address"` subject straight to `walletDefinedByAddresses.handleNewSharedAddress(body, ...)` with no gating against a prior `pending_shared_addresses`/offer record (unlike the separate `approve_new_shared_address`/`reject_new_shared_address` flow, which is explicitly marked "unused"): [1](#0-0) 

`handleNewSharedAddress` only checks that (a) the definition hashes to the claimed address, (b) the referenced signer addresses match the definition, and (c) `determineIfIncludesMeAndRewriteDeviceAddress` finds that at least one signer address already exists in `my_addresses` or `shared_addresses`: [2](#0-1) 

The consent check itself, `determineIfIncludesMeAndRewriteDeviceAddress`, does not verify that the local user solicited this specific shared-address creation — it merely confirms the sender happened to name an address the recipient already controls (or an address already used in another shared address), then silently rewrites the device address to "me" and proceeds: [3](#0-2) 

Once accepted, `addNewSharedAddress` inserts the attacker-chosen definition into `shared_addresses` and records the attacker's device as a cosigner in `shared_address_signing_paths`, with no further user prompt: [4](#0-3) 

This registration has a direct, exploitable consequence for private payments: `forwardPrivateChainsToOtherMembersOfAddresses` and `forwardPrivateChainsToOtherMembersOfOutputAddresses` look up `shared_address_signing_paths` for any address involved in a private payment chain and forward the full private chain (amounts, blinding, prior chain history) to every device address listed there — which now includes the attacker's device, since it was inserted via the unsolicited message: [5](#0-4) [6](#0-5) [7](#0-6) 

`validateAddressDefinition` (called before saving) only checks that the oscript definition is well-formed, not that the recipient actually agreed to co-sign with this specific attacker or that the address was intentionally shared: [8](#0-7) 

The stray `// fix: 1. check that my address is referenced in the definition` comment above `validateAddressDefinition` indicates this consent gap was previously flagged and left unresolved.

### Impact Explanation
A paired correspondent (any device the victim has chatted/paired with, e.g. via a wallet pairing link, chatbot, or exchange) can send a single unsolicited `new_shared_address` message naming one of the victim's existing addresses as a member of a bogus multisig definition where the attacker is also a signer. The victim's wallet accepts this silently and now treats the attacker's device as a legitimate cosigner device of that address. Any subsequent private (non-public) payment involving that address — divisible or indivisible private asset transfer — is then forwarded to the attacker via `forwardPrivateChainsToOtherMembersOfAddresses`/`forwardPrivateChainsToDevices`, leaking the private transaction's payer/payee addresses and amounts to a party the user never intended to include. This is a confidentiality breach for private-asset holders (CWE-284, analogous to CVE-2024-39777's unauthorized exposure of local channel data), reachable purely by a chat/pairing correspondent with no operator, hub, or node privileges required.

### Likelihood Explanation
Likelihood is Medium: it requires the attacker to be a paired correspondent device of the victim (readily achievable via a pairing link, which many wallets share to receive payments) and requires the victim to actually hold private assets and transact them after the bogus shared-address is registered. No cryptographic breaking or race condition is required — a single crafted device message suffices to plant the malicious signer entry.

### Recommendation
Require an explicit, pre-existing solicitation record (e.g., a real `pending_shared_addresses` entry created by the local user via `createNewSharedAddressByTemplate`) before accepting an unsolicited `new_shared_address` message that references an address the user already owns, or surface an explicit UI confirmation prompt naming the newly proposed cosigner device before inserting into `shared_addresses`/`shared_address_signing_paths`. At minimum, do not include newly-learned, unconfirmed shared-address cosigners in `forwardPrivateChainsToOtherMembersOfAddresses` targets until the user affirmatively approves the shared address.

### Proof of Concept
1. Attacker device A pairs with victim device V (e.g., victim scans a pairing QR code to receive a payment — a common wallet UX flow).
2. Victim V already owns address `M` (present in `my_addresses`), which she uses to hold a private asset.
3. Attacker A sends a `new_shared_address` device message to V:
   `{"address": chash160(["and",[["address","M"],["address","A_ADDR"]]]), "definition": ["and",[["address","M"],["address","A_ADDR"]]], "signers": {"r.0": {"address":"M"}, "r.1": {"address":"A_ADDR","device_address": A}}}`
4. `handleNewSharedAddress` validates the hash/definition, `determineIfIncludesMeAndRewriteDeviceAddress` finds `M` in `my_addresses`, and `addNewSharedAddress` inserts the new shared address plus a `shared_address_signing_paths` row mapping `A_ADDR`/device `A` to the new shared address — with no prompt shown to V.
5. Later, V receives or sends a private payment involving address `M`. `forwardPrivateChainsToOtherMembersOfAddresses` queries `shared_address_signing_paths` for addresses in the chain, finds device `A` registered as a cosigner device, and forwards the full private payment chain to attacker device `A` via `walletGeneral.forwardPrivateChainsToDevices`, disclosing amounts and chain history that were meant to stay private between V and her real counterparty.

### Citations

**File:** wallet.js (L236-245)
```javascript
			case "new_shared_address":
				// {address: "BASE32", definition: [...], signers: {...}}
				walletDefinedByAddresses.handleNewSharedAddress(body, {
					ifError: callbacks.ifError,
					ifOk: function(){
						callbacks.ifOk();
						eventBus.emit('maybe_new_transactions');
					}
				});
				break;
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

**File:** wallet.js (L1135-1135)
```javascript
eventBus.on("new_direct_private_chains", forwardPrivateChainsToOtherMembersOfOutputAddresses);
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

**File:** wallet_defined_by_addresses.js (L281-315)
```javascript
function determineIfIncludesMeAndRewriteDeviceAddress(assocSignersByPath, handleResult){
	var assocMemberAddresses = {};
	var bHasMyDeviceAddress = false;
	for (var signing_path in assocSignersByPath){
		var signerInfo = assocSignersByPath[signing_path];
		if (signerInfo.device_address === device.getMyDeviceAddress())
			bHasMyDeviceAddress = true;
		if (signerInfo.address)
			assocMemberAddresses[signerInfo.address] = true;
	}
	var arrMemberAddresses = Object.keys(assocMemberAddresses);
	if (arrMemberAddresses.length === 0)
		return handleResult("no member addresses?");
	db.query(
		"SELECT address, 'my' AS type FROM my_addresses WHERE address IN(?) \n\
		UNION \n\
		SELECT shared_address AS address, 'shared' AS type FROM shared_addresses WHERE shared_address IN(?)", 
		[arrMemberAddresses, arrMemberAddresses],
		function(rows){
		//	handleResult(rows.length === arrMyMemberAddresses.length ? null : "Some of my member addresses not found");
			if (rows.length === 0)
				return handleResult("I am not a member of this shared address");
			var arrMyMemberAddresses = rows.filter(function(row){ return (row.type === 'my'); }).map(function(row){ return row.address; });
			// rewrite device address for my addresses
			if (!bHasMyDeviceAddress){
				for (var signing_path in assocSignersByPath){
					var signerInfo = assocSignersByPath[signing_path];
					if (signerInfo.address && arrMyMemberAddresses.indexOf(signerInfo.address) >= 0)
						signerInfo.device_address = device.getMyDeviceAddress();
				}
			}
			handleResult();
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

**File:** wallet_defined_by_addresses.js (L518-528)
```javascript
// fix:
// 1. check that my address is referenced in the definition
function validateAddressDefinition(arrDefinition, handleResult){
	var objFakeUnit = {authors: []};
	var objFakeValidationState = {last_ball_mci: MAX_INT32, bAllowUnresolvedInnerDefinitions: true};
	Definition.validateDefinition(db, arrDefinition, objFakeUnit, objFakeValidationState, null, false, function(err){
		if (err)
			return handleResult(err);
		handleResult();
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
