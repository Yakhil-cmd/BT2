## Finding

The sender-binding gap in `matrix-sdk-crypto` (trusting a self-asserted identity field inside an encrypted payload instead of the cryptographically-verified sender) has a direct structural analog in ocore's paired-device message handling for shared (multisig) address setup.

### Title
Missing sender-binding check in `new_shared_address` handling allows a paired correspondent device to forge co-signer device mappings for shared/multisig addresses - (File: `wallet_defined_by_addresses.js`)

### Summary
`device.js`'s `handleJustsaying`/`hub/message` path correctly binds every incoming device message to the cryptographically verified sender: it derives `from_address` from the ECDSA-verified `pubkey` and cross-checks it against the encrypted `json.from` field before dispatching the message. [1](#0-0) 

`wallet.js`'s `handleMessageFromHub` then computes `from_address` from the verified `device_pubkey` for use by all subject handlers. [2](#0-1) 

Several handlers explicitly re-bind self-asserted identity fields in the body to this verified `from_address` (e.g. `body.peer_device_address = from_address` for prosaic contracts, and the explicit `from_address !== objContract.peer_device_address` check in `arbiter_contract_update`). [3](#0-2) [4](#0-3) 

Likewise, the *offer* phase of shared-address creation (`create_new_shared_address` → `validateAddressDefinitionTemplate`) explicitly requires that the verified sender be one of the device addresses referenced in the proposed definition: [5](#0-4) 

However, the *delivery* phase — subject `new_shared_address`, which is the step that actually commits a shared-address definition and its `signers` (device_address-per-signing-path) map to the local database — never receives or checks `from_address` at all: [6](#0-5) [7](#0-6) 

### Finding Description
`handleNewSharedAddress(body, callbacks)` validates that:
- `body.definition` hashes to `body.address` (chash160 check),
- each `signerInfo.address` in `body.signers` is a syntactically valid address or `'secret'`,
- the address at each signing path in `body.signers` matches the literal address embedded in `body.definition` at that path,
- every address-leaf in the definition has a corresponding signer entry,
- the local device is a member of the definition (`determineIfIncludesMeAndRewriteDeviceAddress`),
- the definition itself is structurally valid (`validateAddressDefinition`).

None of these checks constrain the **`device_address`** values inside `body.signers` — i.e., which network device is authoritative for producing a co-signature for each member address/path. That field is purely a routing hint recorded verbatim into `shared_address_signing_paths.device_address` by `addNewSharedAddress`. [8](#0-7) 

Because `wallet.js`'s dispatcher never passes the verified `from_address` into `handleNewSharedAddress`, and the function never checks that the sender of this message is even one of the devices named in `signers`, **any already-paired correspondent** can send a `new_shared_address` message defining a brand-new multisig address that includes the victim's own address as a member, while mapping the *other* member's `device_address` to an address of the attacker's choosing (e.g., the attacker's own device) instead of the real co-signer's device.

This is the direct analog of the reported CVE: the transport layer's sender-authentication ("who signed the outer message") is correctly verified, but a nested, self-asserted identity claim used for downstream trust decisions (which device speaks for which signing path) is accepted without being cross-checked against that verified identity — exactly the "sender-binding gap" pattern in GHSA-wfq4-36m3-9g42.

Compare this against `validateAddressDefinitionTemplate`, used one step earlier in the same feature (`create_new_shared_address`), which performs precisely the missing check ("sender device address not mentioned in the definition"): [9](#0-8) 

The equivalent check is absent from the handler that actually persists the routing map, `handleNewSharedAddress`.

### Impact Explanation
Because `shared_address_signing_paths.device_address` determines where the wallet routes future `sign` requests for that shared address (see `findAddress`'s `ifRemote` branch in `wallet.js`, which forwards signing requests to the recorded `device_address` and only checks that the *requester* is in that list — not that the list itself was set by a legitimate party): [10](#0-9) 

a malicious paired correspondent can cause the victim to register a co-signer mapping for a new multisig address that points to the wrong (attacker-controlled or otherwise incorrect) device. When the victim later needs a real co-signature to spend from that address, the signing request is misrouted and never reaches the genuine co-signer, so a payment from that shared/multisig address can never be completed — a fund-freezing condition for the affected multisig address, achieved purely by exploiting the absence of sender-binding in the delivery handler, without needing to break any cryptography.

### Likelihood Explanation
Exploitation requires only that the attacker already be an accepted correspondent device of the victim (a paired peer) — the `hub/message` correspondent-known gate permits `new_shared_address` only from already-paired devices, which is directly analogous to the CVE's own precondition that the attacker "colludes with (or is) the [trusted party]." No cryptographic break, no unpaired/anonymous access, and no hub cooperation is required beyond normal message relay — this raises likelihood for any already-paired malicious or compromised correspondent.

### Recommendation
In `handleNewSharedAddress` (`wallet_defined_by_addresses.js`), require and thread through the verified `from_address` from `wallet.js`'s `new_shared_address` case, and reject the message unless `from_address` is one of the `device_address` values present in `body.signers` (mirroring the check already present in `validateAddressDefinitionTemplate`). Additionally, consider validating that other `device_address` entries for third-party members are either already-known correspondents with a prior relationship to those specific addresses, or otherwise require corroboration before being trusted for signature routing.

### Proof of Concept
1. Attacker `D_atk` is a paired correspondent of victim `V` (normal, already-trusted pairing).
2. `D_atk` crafts `arrDefinitionTemplate`/`arrDefinition` = `["and", [["address", V_addr], ["address", X_addr]]]` where `V_addr` is victim's real address and `X_addr` is any valid-looking address literal.
3. `D_atk` sends device message `{subject: "new_shared_address", body: {address: chash160(arrDefinition), definition: arrDefinition, signers: {"r.0": {address: V_addr}, "r.1": {address: X_addr, device_address: D_atk_or_bogus_device}}}}`.
4. `wallet.js`'s dispatcher calls `walletDefinedByAddresses.handleNewSharedAddress(body, callbacks)` without ever consulting `from_address`. [6](#0-5) 
5. All structural checks pass (hash matches, addresses match template, victim is a member via `V_addr` in `my_addresses`), so `addNewSharedAddress` commits `shared_address_signing_paths` with `device_address = D_atk_or_bogus_device` for path `r.1`, even though `D_atk` never legitimately represents `X_addr`.
6. If `V` later attempts to spend from this shared address requiring signature at `r.1`, the request is routed to `D_atk_or_bogus_device`, which never returns a valid signature — funds sent to this shared address become permanently unspendable.

### Citations

**File:** device.js (L185-189)
```javascript
			// who is the sender
			var from_address = objectHash.getDeviceAddress(objDeviceMessage.pubkey);
			// the hub couldn't mess with json.from as it was encrypted, but it could replace the objDeviceMessage.pubkey and re-sign. It'll be caught here
			if (from_address !== json.from) 
				return respondWithError("wrong message signature");
```

**File:** wallet.js (L94-94)
```javascript
		var from_address = objectHash.getDeviceAddress(device_pubkey);
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

**File:** wallet.js (L374-391)
```javascript
					ifRemote: function(device_address, other_device_addresses){
						if (device_address === from_address)
							return callbacks.ifError("looping signing request for address "+body.address+", path "+body.signing_path);
						if (!other_device_addresses.includes(from_address))
							return callbacks.ifError("you are not listed as a cosigner for this address "+body.address);
						try {
							var text_to_sign = objectHash.getUnitHashToSign(body.unsigned_unit).toString("base64");
						}
						catch (e) {
							return callbacks.ifError("unit hash failed: " + e.toString());
						}
						// I'm a proxy, wait for response from the actual signer and forward to the requestor
						eventBus.once("signature-"+device_address+"-"+body.address+"-"+body.signing_path+"-"+text_to_sign, function(sig){
							sendSignature(from_address, text_to_sign, sig, body.signing_path, body.address);
						});
						// forward the offer to the actual signer
						device.sendMessageToDevice(device_address, subject, body);
						callbacks.ifOk();
```

**File:** wallet.js (L456-456)
```javascript
				body.peer_device_address = from_address;
```

**File:** wallet.js (L687-690)
```javascript
					db.query("SELECT 1 FROM wallet_signing_paths JOIN my_addresses USING(wallet) WHERE device_address=? AND address=?", [from_address, objContract.my_address], function(rows) {
						const from_cosigner = (rows.length && objContract.me_is_cosigner);
						if (from_address !== objContract.peer_device_address && !from_cosigner && !(from_address === objContract.arbstore_device_address && objContract.status === 'in_appeal' && body.field === 'status'))
							return callbacks.ifError("not an owner");
```

**File:** wallet_defined_by_addresses.js (L239-252)
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

**File:** wallet_defined_by_addresses.js (L481-494)
```javascript
function validateAddressDefinitionTemplate(arrDefinitionTemplate, from_address, handleResult){
	try{
		var assocMemberDeviceAddressesBySigningPaths = getMemberDeviceAddressesBySigningPaths(arrDefinitionTemplate);
	}
	catch (e) {
		return handleResult("failed to get member device addresses of new shared address: " + e.toString());
	}
	var arrDeviceAddresses = _.uniq(_.values(assocMemberDeviceAddressesBySigningPaths));
	if (arrDeviceAddresses.length < 2)
		return handleResult("less than 2 member devices");
	if (arrDeviceAddresses.indexOf(device.getMyDeviceAddress()) === - 1)
		return handleResult("my device address not mentioned in the definition");
	if (arrDeviceAddresses.indexOf(from_address) === - 1)
		return handleResult("sender device address not mentioned in the definition");
```
