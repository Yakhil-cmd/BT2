### Title
Identity spoofing via unverified `device_address` in `handleNewSharedAddress` allows a malicious paired device to redirect signing requests for a shared (multisig) address - ([File: wallet_defined_by_addresses.js])

### Summary
The Apache APISIX opa-plugin bug lets an attacker relay spoofed identity headers to an upstream service that trusts them without verifying they originate from the real authenticated principal, letting the attacker act with someone else's privileges. The closest reachable analog in ocore is `handleNewSharedAddress()` in `wallet_defined_by_addresses.js`, which is invoked by an already-paired device sending a `new_shared_address` message over the wallet chat channel [1](#0-0) . This handler cryptographically validates the *address* definition (its c-hash) and the mapping of member-addresses to signing paths, but it never validates that the claimed `device_address` for each signing path actually belongs to the device that supposedly controls it - that value is taken as-is from the message body and stored as the trusted routing/identity target for future signing requests.

### Finding Description
`handleNewSharedAddress(body, callbacks)` receives `body = {address, definition, signers}` where `signers` is an object keyed by signing path, each entry containing `{address, device_address, member_signing_path}` [2](#0-1) .

The function verifies:
- that `body.address` matches the c-hash of `body.definition` [3](#0-2) 
- that each `signerInfo.address` is syntactically valid [4](#0-3) 
- that the `address` at each `signing_path` matches what `extractAddressPathsFromDefinition` derives from the definition tree [5](#0-4) 

Crucially, **none of these checks touch `signerInfo.device_address`**. The value is only used to decide "did the message reach a device that owns one of the member addresses" via `determineIfIncludesMeAndRewriteDeviceAddress`, which only rewrites the device address for signing paths matching *my own* known addresses [6](#0-5) . For every other signing path (i.e. any other cosigner), the attacker-supplied `device_address` is accepted verbatim and persisted into `shared_address_signing_paths` by `addNewSharedAddress()` [7](#0-6) .

This `device_address` is later used as the trusted routing target whenever this wallet needs a signature from that cosigner: `findAddress()` walks `shared_address_signing_paths` and, upon finding a match, invokes `callbacks.ifRemote(row.device_address, ...)`, which forwards to-be-signed unsigned units (and, in the private-asset case, private payment chains) directly to that `device_address` [8](#0-7) , [9](#0-8) . Because a paired correspondent device fully controls the free-form `body.signers[*].device_address` field of a `new_shared_address` message it sends, it can register itself (or any device address it controls) as the "owner" of a *different, real* cosigner's address in the shared-address record, as long as the address itself passes the definition-consistency checks (e.g. an address the attacker doesn't control, or worse, one of the local user's own addresses used in a nested multisig).

This is the structural equivalent of the OPA-plugin bug: a value that is supposed to encode "who legitimately speaks for this identity" (the OPA identity header / here, the device that should receive signing requests for a shared-address member) is taken from an untrusted, non-cryptographically-bound field and trusted for subsequent privileged interactions (forwarding unsigned units/private payloads that would otherwise require the real cosigner's confirmation and private key).

### Impact Explanation
If a shared/multisig address is later used to send funds, the wallet will forward the unsigned unit (and any private-asset payloads that are part of it, per `body.private_payloads` handling in the "sign" message path [10](#0-9) ) to whatever `device_address` was recorded for that cosigner path. If an attacker manages to get their own (or a wrong) `device_address` associated with a legitimate cosigner's signing path via a spoofed `new_shared_address` message, they can:
- intercept private payment payloads/outputs intended only for the real cosigner (private-payment confidentiality loss for a private-payment counterparty scenario), and/or
- disrupt the multisig flow by never returning a valid signature (funds freezing for that shared address), and/or
- potentially social-engineer/confirm bogus signing requests routed to a device under their control, aiding a subsequent unauthorized-spend attempt against the shared address.

This matches the "AA fund loss or freezing" / unauthorized spending impact classes required by the validation rubric, reached entirely through the paired-device message channel by an already-paired but semi-trusted correspondent (no hub/node compromise required).

### Likelihood Explanation
Likelihood is moderate: the attacker must already be a paired device that is a genuine member of a proposed shared-address definition (own device address included in the definition, per `includesMyDeviceAddress`/`validateAddressDefinitionTemplate` checks), but nothing stops that attacker from also declaring a bogus `device_address` for one of the *other* cosigner slots in the same `new_shared_address` message, since only the `address` field (not `device_address`) is checked against the definition. This requires no hub or node compromise, no cryptographic break, and is fully reachable via the standard multisig/shared-address pairing flow used by any wallet feature that creates joint (multi-device) addresses.

### Recommendation
In `handleNewSharedAddress()`, cross-check the asserted `device_address` for every signing path against known, previously-established correspondent relationships (e.g., require that any `device_address` other than the sender's own already be a confirmed correspondent independently learned/verified, or require an explicit signed acknowledgment from that device before persisting it in `shared_address_signing_paths`), instead of trusting the value supplied inside the same untrusted message. At minimum, warn/require user confirmation whenever a `new_shared_address` message assigns a `device_address` that the receiving wallet has not independently verified as belonging to the corresponding member address.

### Proof of Concept
1. Attacker device A pairs normally with victim device V and is a legitimate participant in a proposed shared address whose definition includes addresses `Addr_A` (A's) and `Addr_B` (a third-party cosigner B's, whose real device is `Dev_B`).
2. A crafts and sends `new_shared_address` with `body.signers = { "r.0": {address: Addr_A, device_address: Dev_A}, "r.1": {address: Addr_B, device_address: Dev_Evil} }`, where `Dev_Evil` is a device A controls instead of the real `Dev_B`.
3. `handleNewSharedAddress()` on V's wallet validates that `Addr_A`/`Addr_B` match the definition paths (they do) and that `body.address` matches the definition c-hash (it does) — it never checks that `Dev_Evil` is actually reachable/associated with `Addr_B` [11](#0-10) .
4. V's wallet stores `shared_address_signing_paths` with `device_address = Dev_Evil` for `Addr_B`'s path via `addNewSharedAddress()` [7](#0-6) .
5. When V later spends from the shared address, `findAddress()` resolves `Addr_B`'s signing path to `Dev_Evil` and forwards the unsigned unit (and any associated private payloads) to the attacker's device instead of the real cosigner B [8](#0-7) .

Note: full exploitation depends on downstream code (not fully traced here) that decides which stored `shared_address_signing_paths` row "wins" when multiple wallets independently learn about the same shared address, and on whether `is_confirmed`/correspondent checks elsewhere in the pairing flow would block delivery to an unknown `Dev_Evil`. Given index/size limits on the retrieved codebase, verifying every downstream consumer of `shared_address_signing_paths.device_address` (e.g., signature aggregation and confirmation dialogs in the UI layer) was not fully possible in this session; a full Devin session with complete repository access is recommended to confirm end-to-end exploitability before treating this as a confirmed, exploitable vulnerability rather than a design weakness.

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

**File:** wallet.js (L278-313)
```javascript
				var assocPrivatePayloads = body.private_payloads;
				if ("private_payloads" in body){
					if (!isNonemptyObject(assocPrivatePayloads))
						return callbacks.ifError("bad private payloads");
					if (!ValidationUtils.isNonemptyArray(objUnit.messages))
						return callbacks.ifError("private payloads require messages");
					const sent_pp_hashes = Object.keys(assocPrivatePayloads).sort();
					const expected_pp_hashes = objUnit.messages.filter(m => m.payload_location === "none" && m.app === "payment").map(m => m.payload_hash).sort();
					if (!_.isEqual(sent_pp_hashes, expected_pp_hashes))
						return callbacks.ifError("private payloads are not the same as in the messages");
					for (var payload_hash in assocPrivatePayloads){
						try {
							const payload = assocPrivatePayloads[payload_hash];
							if (!ValidationUtils.isNonemptyArray(payload.outputs) || !payload.outputs.every(o => ValidationUtils.isValidAddress(o.address) && ValidationUtils.isNonemptyString(o.blinding) && ValidationUtils.isPositiveInteger(o.amount)))
								return callbacks.ifError("bad private payload outputs");
							if (!ValidationUtils.isNonemptyArray(payload.inputs) || !payload.inputs.every(i => ("type" in i) || (ValidationUtils.isNonemptyString(i.unit) && ValidationUtils.isNonnegativeInteger(i.message_index) && ValidationUtils.isNonnegativeInteger(i.output_index))))
								return callbacks.ifError("bad private payload inputs");
							const hidden_payload = _.cloneDeep(payload);
							if (payload.denomination) { // indivisible asset.  In this case, payload hash is calculated based on output_hash rather than address and blinding
								if (!payload.outputs.every(o => o.output_hash === objectHash.getBase64Hash({ address: o.address, blinding: o.blinding })))
									return callbacks.ifError("output hash mismatch");
								hidden_payload.outputs.forEach(function (o) {
									delete o.address;
									delete o.blinding;
								});
							}
							var calculated_payload_hash = objectHash.getBase64Hash(hidden_payload, bJsonBased);
						}
						catch (e) {
							return callbacks.ifError("hidden payload hash failed: " + e.toString());
						}
						if (payload_hash !== calculated_payload_hash)
							return callbacks.ifError("private payload hash does not match");
						if (objUnit.messages.filter(function(objMessage){ return (objMessage && objMessage.payload_hash === payload_hash); }).length !== 1)
							return callbacks.ifError("no such payload hash in the messages");
					}
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

**File:** wallet.js (L1263-1288)
```javascript
			//	"SELECT address, device_address, member_signing_path FROM shared_address_signing_paths WHERE shared_address=? AND signing_path=?", 
				// look for a prefix of the requested signing_path
				"SELECT address, device_address, signing_path FROM shared_address_signing_paths \n\
				WHERE shared_address=? AND ( signing_path=? OR " + prefix + "=SUBSTR(?, 1, LENGTH(signing_path)+1) )", 
				[address, signing_path, signing_path],
				async function(sa_rows){
					if (sa_rows.length > 1)
						throw Error("more than 1 member address found for shared address "+address+" and signing path "+signing_path);
					if (sa_rows.length === 1) {
						var objSharedAddress = sa_rows[0];
						var relative_signing_path = 'r' + signing_path.substr(objSharedAddress.signing_path.length);
						var bLocal = (objSharedAddress.device_address === device.getMyDeviceAddress()); // local keys
						if (objSharedAddress.address === '') {
							return callbacks.ifMerkle(bLocal);
						} else if(objSharedAddress.address === 'secret') {
							return callbacks.ifSecret();
						}
						let newFallbackInfo = null;
						if (!bLocal) {
							newFallbackInfo = {};
							newFallbackInfo.device_address = objSharedAddress.device_address;
							const other_rows = await db.query("SELECT DISTINCT device_address FROM shared_address_signing_paths WHERE shared_address=? AND device_address!=?", [address, objSharedAddress.device_address]);
							newFallbackInfo.other_device_addresses = other_rows.map(r => r.device_address);
						}
						return findAddress(objSharedAddress.address, relative_signing_path, callbacks, newFallbackInfo);
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

**File:** wallet_defined_by_addresses.js (L279-315)
```javascript
// Checks if any of my payment addresses is mentioned.
// It is possible that my device address is not mentioned in the definition if I'm a member of multisig address, one of my cosigners is mentioned instead
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
