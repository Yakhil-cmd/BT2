### Title
Disabled indirect-correspondent trust check allows unauthorized device messages to be processed as fully-trusted - ([File: wallet.js])

### Summary
The Linux CVE discards disassoc/deauth frames that don't originate from the address the STA is actually associated with, because the firmware/driver failed to verify the sender identity before acting on it. The ocore analog is `handleMessageFromHub()` in `wallet.js`, which is supposed to restrict the set of message `subject`s that may be trusted from an "indirect" correspondent (a paired device known only transitively, e.g. through shared-address propagation), but the enforcing check is commented out, so every subject is now treated as if it came from a directly-paired, fully-trusted device.

### Finding Description
`handleMessageFromHub(ws, json, device_pubkey, bIndirectCorrespondent, callbacks)` receives `bIndirectCorrespondent`, a flag indicating the sender is only an indirect correspondent (looked up via `is_indirect` in `correspondent_devices`, populated by `addIndirectCorrespondents` in `device.js`). The intended access-control gate is: [1](#0-0) 
```js
//if (bIndirectCorrespondent && ["cancel_new_wallet", "my_xpubkey", "new_wallet_address"].indexOf(subject) === -1)
//    return callbacks.ifError("you're indirect correspondent, cannot trust "+subject+" from you");
```
This line is entirely commented out, so the whole `switch(subject)` block in `doHandle()` executes unconditionally for indirect correspondents: [2](#0-1) 

With the check disabled, an indirect correspondent — a device that is not personally paired with the local wallet, and was intended to be trusted only for the 3 narrow wallet-provisioning subjects — can now send and have processed any of the other privileged subjects handled in this switch, e.g.:
- `"sign"` — requesting the wallet to co-sign a unit (`wallet.js` around line 251+), where the recipient's private key is used to sign whatever `unsigned_unit`/`signing_path` the sender supplies (subject to `findAddress` checks) [3](#0-2) 
- `"removed_paired_device"` — instructing the wallet to drop a correspondent [4](#0-3) 
- `"arbiter_contract_response"` / `"prosaic_contract_response"` — driving contract state transitions [5](#0-4) 
- `"new_shared_address"`, `"approve_new_shared_address"`, etc. in `wallet_defined_by_addresses.js`, which create/confirm shared payment addresses [6](#0-5) 

This is structurally the same bug class as CVE-2025-38505: a message-processing path fails to verify that the message legitimately originates from a peer that the receiver should trust for that specific action, letting an under-privileged sender (here, an indirect correspondent instead of the associated AP) drive state machines/mutations that were reserved for a narrower, more-trusted set of senders.

### Impact Explanation
Because `from_address` is still derived correctly from the signed `device_pubkey` (message authenticity/integrity is fine), this is not a full spoofing bug — the attacker must genuinely be a known indirect correspondent (e.g., a cosigner-of-a-cosigner introduced via shared address creation). But such an indirect correspondent was never supposed to be trusted for wallet-address derivation confirmations, contract state changes, shared-address creation, or (most importantly) triggering the wallet's `"sign"` flow which surfaces a signing confirmation using attacker-supplied `unsigned_unit`/`signing_path`/`address` data. Depending on downstream handling (e.g., `findAddress`'s `ifRemote`/`ifLocal` branches and UI auto-approval flows), this expands the attack surface for tricking a wallet into co-signing transactions or corrupting shared-address/contract state — i.e., potential unauthorized spending or fund loss for AA/contract counterparties and cosigners, and denial of legitimate wallet operations (e.g., unauthorized `removed_paired_device` or wallet cancellation). This satisfies "concrete unauthorized spending / AA fund loss" criteria depending on which subject is abused, and warrants a High severity given the breadth of subjects now reachable by a lesser-trusted peer.

### Likelihood Explanation
Likelihood is High: any device that has ever become an indirect correspondent (a routine occurrence in normal multi-signature/shared-address workflows, tracked via `is_indirect` in `correspondent_devices`) can immediately exploit this with no additional privilege escalation, since the gating check is simply commented out rather than conditionally bypassed — it never executes for any subject.

### Recommendation
Re-enable the indirect-correspondent restriction in `wallet.js`:
```js
if (bIndirectCorrespondent && ["cancel_new_wallet", "my_xpubkey", "new_wallet_address"].indexOf(subject) === -1)
    return callbacks.ifError("you're indirect correspondent, cannot trust "+subject+" from you");
```
Audit all subjects handled after this point to confirm the current whitelist (`cancel_new_wallet`, `my_xpubkey`, `new_wallet_address`) is still correct and add any subjects that should also be safely reachable by indirect correspondents (e.g. `pairing`, `wallet_fully_approved`, which are separately marked "allowed from non-correspondents"), while keeping high-impact subjects (`sign`, `removed_paired_device`, `new_shared_address`, `arbiter_contract_response`, etc.) restricted to directly-paired, fully-trusted correspondents only.

### Proof of Concept
1. Establish an indirect correspondence: Device C becomes known to Device A's wallet as an indirect correspondent through the normal shared-address cosigner propagation logic in `wallet_defined_by_addresses.js` (`forwardNewSharedAddressToCosignersOfMyMemberAddresses` / `addIndirectCorrespondents` in `device.js`), setting `correspondent_devices.is_indirect = 1` for C on A's node.
2. Device C sends a `hub/message` to A's hub with `subject: "sign"` (or `"removed_paired_device"`, `"arbiter_contract_response"`, etc.) and a `body` crafted to exercise that handler.
3. A's `device.js` `handleJustsaying` verifies signature/hash and dispatches to `eventBus.emit("handle_message_from_hub", ws, json, pubkey, /*bIndirectCorrespondent=*/true, callbacks)` since C is only an indirect correspondent (`device.js` lines ~204-219).
4. In `wallet.js`, because the `bIndirectCorrespondent` gate is commented out, `doHandle()` proceeds directly into the `switch(subject)` and processes the `"sign"`/other privileged subject exactly as if C were a fully trusted, directly-paired correspondent — despite the code's own intent (visible in the commented-out line) that only `cancel_new_wallet`, `my_xpubkey`, and `new_wallet_address` should be trusted from such a sender.

### Citations

**File:** wallet.js (L84-96)
```javascript
	function doHandle() {

		var subject = json.subject;
		var body = json.body;
		if (!subject || typeof body == "undefined" || body === null)
			return callbacks.ifError("no subject or body");
		if (typeof subject !== "string")
			return callbacks.ifError("subject is not a string");
		//if (bIndirectCorrespondent && ["cancel_new_wallet", "my_xpubkey", "new_wallet_address"].indexOf(subject) === -1)
		//    return callbacks.ifError("you're indirect correspondent, cannot trust "+subject+" from you");
		var from_address = objectHash.getDeviceAddress(device_pubkey);
		
		switch (subject){
```

**File:** wallet.js (L124-142)
```javascript
			case "removed_paired_device":
			//	if(conf.bIgnoreUnpairRequests) {
			//		// unpairing is ignored
			//		callbacks.ifError("removed_paired_device ignored: "+from_address);
			//	} else {
					determineIfDeviceCanBeRemoved(from_address, function(bRemovable){
						if (!bRemovable)
							return callbacks.ifError("device "+from_address+" is not removable");
						if (conf.bIgnoreUnpairRequests){
							db.query("UPDATE correspondent_devices SET is_blackhole=1 WHERE device_address=?", [from_address]);
							return callbacks.ifOk();
						}
						device.removeCorrespondentDevice(from_address, function(){
							eventBus.emit("removed_paired_device", from_address);
							callbacks.ifOk();
						});
					});
			//	}
				break;
```

**File:** wallet.js (L251-278)
```javascript
			case "sign":
				// {address: "BASE32", signing_path: "r.1.2.3", unsigned_unit: {...}}
				if (!ValidationUtils.isValidAddress(body.address))
					return callbacks.ifError("no address or bad address");
				if (!ValidationUtils.isNonemptyString(body.signing_path) || !/^r(\.\d+)*$/.test(body.signing_path))
					return callbacks.ifError("bad signing path");
				var objUnit = body.unsigned_unit;
				if (typeof objUnit !== "object" || objUnit === null)
					return callbacks.ifError("no unsigned unit");
				if (!ValidationUtils.isNonemptyArray(objUnit.authors))
					return callbacks.ifError("no authors array");
				var bJsonBased = (objUnit.version !== constants.versionWithoutTimestamp);
				// replace all existing signatures with placeholders so that signing requests sent to us on different stages of signing become identical,
				// hence the hashes of such unsigned units are also identical
				try {
					objUnit.authors.forEach(function (author) {
						var authentifiers = author.authentifiers;
						for (var path in authentifiers)
							authentifiers[path] = authentifiers[path].replace(/./g, '-');
					});
					const authorAddresses = objUnit.authors.map(author => author.address);
					if (!authorAddresses.includes(body.address))
						return callbacks.ifError("address not found among authors");
				}
				catch (e) {
					return callbacks.ifError("invalid authors: " + e.toString());
				}
				var assocPrivatePayloads = body.private_payloads;
```

**File:** wallet.js (L864-922)
```javascript
			// sent by peer
			case 'arbiter_contract_response':
				if (!ValidationUtils.isNonemptyString(body.hash))
					return callbacks.ifError("no contract hash");
				if (body.status !== "accepted" && body.status !== "declined")
					return callbacks.ifError("wrong status supplied");

				arbiter_contract.getByHash(body.hash, function(objContract){
					if (!objContract)
						return callbacks.ifError("wrong contract hash");
					if (body.status === "accepted" && !body.signed_message)
						return callbacks.ifError("response is not signed");
					if (from_address !== objContract.peer_device_address)
						return callbacks.ifError("response is from wrong device");
					if (objContract.is_incoming)
						return callbacks.ifError("this contract is incoming, cannot accept your own offer");
					var processResponse = function(objSignedMessage) {
						if (body.authors && body.authors.length && objSignedMessage) {
							if (body.authors.length !== 1)
								return callbacks.ifError("wrong number of authors received");
							var author = body.authors[0];
							try {
								if (author.definition && (author.address !== objectHash.getChash160(author.definition)))
									return callbacks.ifError("incorrect definition received");
							}
							catch (e) {
								return callbacks.ifError("invalid definition: " + e);
							}
							if (!ValidationUtils.isValidAddress(author.address) || author.address !== objContract.peer_address)
								return callbacks.ifError("incorrect author address");
							// this can happen when acceptor and offerer have same device in cosigners
							db.query('SELECT 1 FROM my_addresses WHERE address=? \n\
								UNION SELECT 1 FROM shared_addresses WHERE shared_address=?', [author.address, author.address], function(rows) {
									if (rows.length)
										return;
									db.query("INSERT "+db.getIgnore()+" INTO peer_addresses (address, device_address, signing_paths, definition) VALUES (?, ?, ?, ?)",
										[author.address, from_address, JSON.stringify(Object.keys(objSignedMessage.authors[0].authentifiers)), JSON.stringify(author.definition)],
										function(res) {
											if (res.affectedRows == 0)
												db.query("UPDATE peer_addresses SET signing_paths=?, definition=? WHERE address=?", [JSON.stringify(Object.keys(objSignedMessage.authors[0].authentifiers)), JSON.stringify(author.definition), author.address]);
										}
									);
								}
							);
						}
						var isAllowed = objContract.status === "pending" || (objContract.status === 'accepted' && body.status === 'accepted');
						if (!isAllowed)
							return callbacks.ifError("contract is not active, current status: " + objContract.status);
						var objDateCopy = new Date(objContract.creation_date_obj);
						if (objDateCopy.setHours(objDateCopy.getHours(), objDateCopy.getMinutes(), (objDateCopy.getSeconds() + objContract.ttl * 60 * 60)|0) < Date.now())
							return callbacks.ifError("contract already expired");
						if (body.my_pairing_code && typeof body.my_pairing_code === 'string')
							arbiter_contract.setField(objContract.hash, "peer_pairing_code", body.my_pairing_code);
						if (body.my_contact_info && typeof body.my_contact_info === 'string')
							arbiter_contract.setField(objContract.hash, "peer_contact_info", body.my_contact_info);
						arbiter_contract.setField(objContract.hash, "status", body.status, function(objContract){
							eventBus.emit("arbiter_contract_response_received", objContract);
						});
						callbacks.ifOk();
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
