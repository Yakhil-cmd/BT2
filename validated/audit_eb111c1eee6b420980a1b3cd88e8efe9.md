### Title
Missing authenticity/structure validation of peer-supplied shared-address definitions allows unilateral fund theft from believed-to-be-joint addresses - (File: wallet_defined_by_addresses.js)

### Summary
The `new_shared_address` device message handler (`wallet_defined_by_addresses.js::handleNewSharedAddress`) accepts a shared-address definition and set of signer mappings from any paired correspondent device and stores it as a legitimate local "shared address" after only checking internal self-consistency (that the given address is the chash of the given definition) and that one of the leaf addresses belongs to the local wallet. It never validates that the received definition actually matches the joint-control agreement the user believes they created (e.g., an "and"/"r of set" multisig requiring cooperation of all named parties), analogous to `ArrakisV2Router` trusting a caller-supplied vault address without checking it was produced by `ArrakisV2Factory`.

### Finding Description
The legitimate flow for creating a shared address is: `create_new_shared_address` → `validateAddressDefinitionTemplate` → user approval → `approve_new_shared_address`, tracked via the `pending_shared_addresses` / `pending_shared_address_signing_paths` tables [1](#0-0) . However, the network handler for the *final* message, `new_shared_address`, dispatches straight into `handleNewSharedAddress` with no correlation back to any `pending_shared_addresses` record that the user actually approved [2](#0-1) .

`handleNewSharedAddress` performs only the following checks on the attacker-controlled `body`:
- `body.address === objectHash.getChash160(body.definition)` (self-consistency only, proves nothing about intent)
- each `signers[path].address` is a syntactically valid address
- the signer-to-address mapping in `signers` is consistent with the leaves extracted from `definition` via `extractAddressPathsFromDefinition`
- `determineIfIncludesMeAndRewriteDeviceAddress` only confirms that *some* leaf address in the definition belongs to the local wallet (`my_addresses`) or is a known shared address [3](#0-2) [4](#0-3) 

None of these checks constrain the *boolean structure* (`and`/`or`/`r of set`/`weighted and`) of the definition. A malicious paired device can send a `new_shared_address` message whose definition is, e.g., `["or", [["address", "<victim's own address>"], ["address", "<attacker address>"]]]`. This passes every check: the address correctly hashes to the definition, the victim's address is a real leaf that belongs to the victim, and there's a signer entry for every leaf. `addNewSharedAddress` then records this as a normal "shared address" the victim's wallet tracks [5](#0-4) .

Because the definition uses `or` instead of `and`/`r of set`, spending from this "shared" address requires **only one** signature — the attacker's — even though the wallet UI/flows (e.g. `prosaic_contract.js`/`arbiter_contract.js`, which independently re-derive and compare the shared address hash but never inspect the underlying join semantics either) present it to the user as a jointly-controlled multisig/escrow address [6](#0-5) [7](#0-6) .

### Impact Explanation
If a user funds such a bogus "shared address" — believing cooperation of the counterparty (or an arbiter) is required to move funds, as is standard for prosaic/arbiter contracts and multi-signer wallets — the attacker who crafted the `or` definition can unilaterally sweep all funds sent to that address with only their own signature, since ocore's DAG-level `definition.js` validation only enforces the definition's actual boolean logic, not the victim's assumption of joint control. This is a direct unauthorized-spending / fund-loss vulnerability reachable purely by a paired correspondent device message, no privileged network position required.

### Likelihood Explanation
Any device that is paired with the victim (a routine, low-trust relationship in ocore, as pairing itself grants no elevated trust) can send this message unprompted. The exploit requires no race condition, no network position, and no privileged network role — only crafting a well-formed but structurally malicious definition, which is straightforward given `handleNewSharedAddress`'s validation is purely about hash/leaf consistency, not structural intent.

### Recommendation
`handleNewSharedAddress` (and the `new_shared_address` network handler) should not blindly trust arbitrary peer-supplied definitions as authentic shared addresses. At minimum:
- Require that a completed shared address correlate with a `pending_shared_addresses` / `pending_shared_address_signing_paths` record that the local user actually approved via `approve_new_shared_address`, rejecting unsolicited `new_shared_address` messages that don't match an approved template hash.
- When no such correlation is enforced (e.g., for addresses learned passively, like in `prosaic_contract.js`/`arbiter_contract.js`), independently validate that the top-level operator structurally requires cooperation of all expected parties (e.g., reject bare `or` combinations of the local key with unknown external addresses) before treating the address as "shared"/jointly controlled in UI or contract flows.

### Proof of Concept
1. Attacker pairs their device with the victim's wallet (a normal ocore pairing operation).
2. Attacker (or a compromised/malicious correspondent) sends a `new_shared_address` device message:
   ```
   {
     "address": "<chash160 of the definition below>",
     "definition": ["or", [["address","VICTIM_OWN_ADDRESS"], ["address","ATTACKER_ADDRESS"]]],
     "signers": {
       "r.0": {"address": "VICTIM_OWN_ADDRESS", "device_address": "<victim device>"},
       "r.1": {"address": "ATTACKER_ADDRESS", "device_address": "<attacker device>"}
     }
   }
   ```
3. `handleNewSharedAddress` accepts it: hash matches, signer mapping matches definition leaves, and `determineIfIncludesMeAndRewriteDeviceAddress` confirms `VICTIM_OWN_ADDRESS` is one of the victim's `my_addresses`, so it's stored via `addNewSharedAddress` into `shared_addresses`/`shared_address_signing_paths`.
4. Victim's wallet UI/contract flow (e.g., prosaic/arbiter contract escrow) presents this as a jointly-controlled address and the victim funds it.
5. Attacker independently signs a payment unit spending from this address, satisfying the `or` branch with only their own signature — no victim cooperation needed — and takes the funds.

### Citations

**File:** wallet.js (L197-226)
```javascript
			case "create_new_shared_address":
				// {address_definition_template: [...]}
				if (!ValidationUtils.isArrayOfLength(body.address_definition_template, 2))
					return callbacks.ifError("no address definition template");
				walletDefinedByAddresses.validateAddressDefinitionTemplate(
					body.address_definition_template, from_address, 
					function(err, assocMemberDeviceAddressesBySigningPaths){
						if (err)
							return callbacks.ifError(err);
						// this event should trigger a confirmatin dialog, user needs to approve creation of the shared address and choose his 
						// own address that is to become a member of the shared address
						eventBus.emit("create_new_shared_address", body.address_definition_template, assocMemberDeviceAddressesBySigningPaths);
						callbacks.ifOk();
					}
				);
				break;
			
			case "approve_new_shared_address":
				// {address_definition_template_chash: "BASE32", address: "BASE32", device_addresses_by_relative_signing_paths: {...}}
				if (!ValidationUtils.isValidAddress(body.address_definition_template_chash))
					return callbacks.ifError("invalid addr def c-hash");
				if (!ValidationUtils.isValidAddress(body.address))
					return callbacks.ifError("invalid address");
				if (typeof body.device_addresses_by_relative_signing_paths !== "object" 
						|| Object.keys(body.device_addresses_by_relative_signing_paths).length === 0)
					return callbacks.ifError("invalid device_addresses_by_relative_signing_paths");
				walletDefinedByAddresses.approvePendingSharedAddress(body.address_definition_template_chash, from_address, 
					body.address, body.device_addresses_by_relative_signing_paths);
				callbacks.ifOk();
				break;
```

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

**File:** prosaic_contract.js (L140-156)
```javascript
function handleReceivedSharedAddress(contract, shared_address, retry_count = 0) {
	console.log(`received shared address ${shared_address} for prosaic contract ${contract.hash} from peer`);
	db.query("SELECT 1 FROM shared_addresses WHERE shared_address=?", [shared_address], function (rows) {
		if (rows.length === 0) {
			if (retry_count >= 10)
				return console.log(`shared address ${shared_address} not found in db after 10 retries, giving up`);
			console.log(`shared address ${shared_address} not yet in db, waiting for 30 seconds and trying again`);
			return setTimeout(handleReceivedSharedAddress, 30000, contract, shared_address, retry_count + 1);
		}
		console.log(`shared address ${shared_address} found in db, deriving shared address definition to verify it matches the received one`);
		const { arrDefinition } = deriveSharedAddress(contract, false);
		const expected_shared_address = objectHash.getChash160(arrDefinition);
		if (expected_shared_address !== shared_address)
			return console.log(`expected shared address ${expected_shared_address} does not match received from offeror ${shared_address}`, JSON.stringify(arrDefinition, null, 2));
		console.log(`shared address ${expected_shared_address} matches the received one, saving it to the contract`);
		setField(contract.hash, "shared_address", shared_address);
	});
```

**File:** arbiter_contract.js (L632-658)
```javascript
function handleReceivedSharedAddress(hash, shared_address, from_cosigner, retry_count = 0) {
	console.log(`received shared address ${shared_address} for arbiter contract ${hash} from peer`);
	db.query("SELECT 1 FROM shared_addresses WHERE shared_address=?", [shared_address], function (rows) {
		if (rows.length === 0) {
			if (retry_count >= 10)
				return console.log(`shared address ${shared_address} not found in db after 10 retries, giving up`);
			console.log(`shared address ${shared_address} not yet in db, waiting for 30 seconds and trying again`);
			return setTimeout(handleReceivedSharedAddress, 30000, hash, shared_address, from_cosigner, retry_count + 1);
		}
		console.log(`shared address ${shared_address} found in db, deriving shared address definition to verify it matches the received one`);
		deriveSharedAddress(hash, false, function (err, arrDefinition, assocSignersByPath) {
			if (err) {
				if (retry_count >= 10)
					return console.log(`failed derivation of shared address ${shared_address} after 10 retries, giving up`, err);
				console.log("error deriving shared address definition, will retry in 30 seconds", err);
				return setTimeout(handleReceivedSharedAddress, 30000, hash, shared_address, from_cosigner, retry_count + 1);
			}
			const expected_shared_address = objectHash.getChash160(arrDefinition);
			if (expected_shared_address !== shared_address)
				return console.log(`expected shared address ${expected_shared_address} does not match received from offeror ${shared_address}`, JSON.stringify(arrDefinition, null, 2));
			console.log(`shared address ${expected_shared_address} matches the received one, setting it to the contract and sharing with cosigners`);
			setField(hash, "shared_address", shared_address, function (contract) {
				eventBus.emit("arbiter_contract_update", contract, "shared_address", shared_address);
			}, from_cosigner);
		});
	});
}
```
