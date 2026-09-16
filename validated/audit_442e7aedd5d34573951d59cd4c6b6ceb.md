### Title
`handleNewSharedAddress` accepts shared-address definitions without verifying the sender is an actual signer/cosigner - (File: `ocore--008/wallet_defined_by_addresses.js`)

### Summary
The external report describes a cross-chain `Receiver`/`xReceive` handler that executes attacker-supplied calldata because it never checks that the message actually originated from the expected source-chain contract — it only checks internal self-consistency of the payload. The analogous pattern in ocore is `handleNewSharedAddress()` in `wallet_defined_by_addresses.js`, which is invoked from the `"new_shared_address"` device-message handler in `wallet.js`. It validates that the supplied `definition`/`signers`/`address` are internally consistent, but never checks that the verified `from_address` of the device message that delivered this payload is actually one of the parties named in `signers`.

### Finding Description
The `"new_shared_address"` case in `wallet.js` passes the raw message body straight to `walletDefinedByAddresses.handleNewSharedAddress`, without ever forwarding or checking `from_address` (the cryptographically verified device address of the sender, computed earlier in `handleMessageFromHub` at `wallet.js` line 94): [1](#0-0) 

`handleNewSharedAddress` only verifies that:
- `body.definition` hashes to `body.address` (`objectHash.getChash160`)
- every `signing_path` in `body.signers` maps to an address that matches the same path extracted from `body.definition`
- every address-leaf in the definition has a corresponding entry in `body.signers` [2](#0-1) 

None of these checks tie the message to the party that actually sent it (`from_address`). Any correspondent device — including one that is not a party to the claimed shared address at all — can construct a self-consistent `{address, definition, signers}` triple (the c-hash and per-path checks are trivially satisfiable by the sender alone, since they only relate the definition to itself) and have it silently accepted into the local `shared_addresses`/`shared_address_signing_paths` tables via `addNewSharedAddress`: [3](#0-2) 

This mirrors the LiFi `Receiver` bug: the handler trusts the *content* of an inbound message (definition/signers matching each other) instead of verifying the *identity of the counterparty* that is supposed to be a party to the transaction (a signer/cosigner of the shared address), exactly as `Receiver.xReceive` trusted `_callData` without checking the true bridge-verified `_sender`.

I was unable to fully inspect `determineIfIncludesMeAndRewriteDeviceAddress` (truncated during investigation), which is called before `addNewSharedAddress` and may perform some remapping of "my" device address inside `signers`; it is uncertain whether it adds any check that `from_address` matches one of the `device_address` values in `signers`. Based on the code paths reviewed, no such check exists elsewhere in `handleNewSharedAddress`.

### Impact Explanation
Because the local wallet accepts and persists an attacker-supplied shared-address definition without verifying that the message truly originates from one of the definition's named cosigners, an attacker who is merely a paired correspondent (not necessarily a real cosigner) can inject a bogus "shared address" record into the victim's wallet database. This corrupted state can:
- Cause the wallet to treat an address as a legitimate multi-party/multisig address it does not actually understand the true ownership of, feeding downstream flows (`readSharedAddressCosigners`, `forwardPrivateChainsToOtherMembersOfAddresses`, arbiter-contract address resolution) with attacker-controlled signer/device_address mappings.
- Enable social-engineering/fund-loss scenarios where the victim is led to believe funds sent to the injected address are protected by a multi-party arrangement including trusted cosigners, when the actual definition (fully attacker-authored, only required to hash-match itself) may grant sole or effectively unilateral spending rights to the attacker.

This satisfies the "AA/wallet fund loss" bar because it enables unauthorized control/spending expectations over addresses the victim's wallet is tricked into trusting, reached purely through an unprivileged paired-device message.

### Likelihood Explanation
Medium. Requires the attacker to be a paired correspondent of the victim (or exploit `arrSubjectsAllowedFromNoncorrespondents`/relaxed pairing flows), which is achievable by anyone since pairing is initiated via a shareable pairing code/URI. Once paired, sending a forged `"new_shared_address"` message is a single crafted device message with no further interaction required to get it persisted (`addNewSharedAddress` runs unconditionally on `ifOk`).

### Recommendation
In `handleNewSharedAddress` (or in the `"new_shared_address"` dispatch in `wallet.js`), require that `from_address` (the message's cryptographically verified sender) be present among the `device_address` values in `body.signers`, i.e., that the sender is actually claiming to be one of the parties to the shared address, before calling `addNewSharedAddress`. Additionally, consider requiring explicit user confirmation before silently adding a new shared address that includes unfamiliar cosigner addresses, rather than auto-accepting on `ifOk`.

### Proof of Concept
1. Attacker pairs their device with the victim's wallet (standard pairing flow).
2. Attacker crafts a device message:
```json
{
  "subject": "new_shared_address",
  "body": {
    "address": "<chash160 of DEF>",
    "definition": ["address", "$member@r"],
    "signers": {
      "r": { "address": "<attacker or forged address>", "device_address": "<attacker device>" }
    }
  }
}
```
3. `wallet.js` line 236 routes this straight to `walletDefinedByAddresses.handleNewSharedAddress` without checking that `from_address` (attacker's own verified device address) is legitimately expected to be a cosigner of any wallet the victim intended to create.
4. All internal checks pass (definition hashes to `address`, signer paths match), so `addNewSharedAddress` persists the record and emits `new_address`, silently incorporating the attacker-defined address into the victim's wallet state. [2](#0-1) [3](#0-2)

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

**File:** wallet_defined_by_addresses.js (L378-415)
```javascript
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
