### Title
Indirect correspondents receive full trusted-device message privileges due to disabled trust-boundary check - ([File: wallet.js])

### Summary
`wallet.js`'s `handleMessageFromHub()` contains a check, meant to restrict what an "indirect" (not directly paired) device correspondent may request, that has been commented out. As a result, any device that becomes an *indirect* correspondent — added automatically and without an explicit pairing handshake whenever it appears as a cosigner in a shared-address/multisig setup — is treated exactly like a fully paired, explicitly trusted correspondent for every message subject, including signing requests. This mirrors the JupyterHub CWE-352 pattern: a check intended to gate a privileged action based on the trust level/origin of the request was disabled, so requests that should be rejected as insufficiently authenticated/trusted are processed as if they came from a fully trusted party.

### Finding Description
`device.js`'s `addIndirectCorrespondents()` inserts a `correspondent_devices` row with `is_indirect=1` for every cosigner address named in shared-address setup data received from a peer, with no pairing-secret verification: [1](#0-0) 

When a message subsequently arrives from such a device via the hub, `handleJustsaying()`'s `'hub/message'` handler only checks whether the sender is a *known* correspondent (`SELECT hub, is_indirect FROM correspondent_devices WHERE device_address=?`); if found — whether direct or indirect — it is dispatched to `handleMessage(rows[0].is_indirect)` and treated as "known", bypassing the stricter whitelist (`["pairing","my_xpubkey","wallet_fully_approved"]`) that applies only to completely unknown correspondents: [2](#0-1) 

The `bIndirectCorrespondent` flag is passed through to `wallet.js`'s `handleMessageFromHub()`, where the code that was supposed to restrict indirect correspondents to a small safe subset of subjects (`cancel_new_wallet`, `my_xpubkey`, `new_wallet_address`) is commented out: [3](#0-2) 

Because this check is disabled, an indirect correspondent can send **any** subject handled by `doHandle()` — including `sign` (which triggers the `signing_request` event and a signing confirmation dialog on the victim's device), `create_new_shared_address`, `new_shared_address`, `removed_paired_device`, etc. — with the same trust level as an explicitly, secret-based paired device: [4](#0-3) [5](#0-4) 

### Impact Explanation
An indirect correspondent is introduced automatically as a side effect of ordinary multisig/shared-address workflows (e.g. `forwardNewSharedAddressToCosignersOfMyMemberAddresses`), without the out-of-band pairing-secret exchange that normally establishes trust between two devices. With the trust-boundary check disabled, such a loosely-introduced device can send a crafted `sign` request for an address the victim co-owns, causing the victim's wallet to raise a signing confirmation dialog for an attacker-supplied unit/payment (potential fund loss if approved), or send other privileged subjects (`create_new_shared_address`, `new_shared_address`) that manipulate the victim's shared-address state — all impersonating a fully trusted, explicitly paired peer. This is a wallet/contract message-handling authorization bypass reachable by any counterparty introduced through normal multisig/shared-address setup.

### Likelihood Explanation
Becoming an indirect correspondent requires no privileged access — any device that participates in (or is named as a cosigner in) a shared-address/multisig template sent to the victim becomes an indirect correspondent automatically via `addIndirectCorrespondents`. Once that row exists, the attacker fully controls the crafted message content sent through the hub, and the disabled check means there is no further gating on message subject.

### Recommendation
Re-enable and enforce the trust-boundary check in `wallet.js` (currently commented out) so that indirect correspondents are restricted to the intended safe whitelist of subjects, and/or require indirect correspondents to complete an explicit pairing-secret handshake (as with `handlePairingMessage`) before being granted full trusted-correspondent privileges such as `sign` requests.

### Proof of Concept
1. Attacker device D is named as a cosigner in a shared-address definition template together with victim device V (e.g. via a normal `create_new_shared_address` / `approve_new_shared_address` flow involving another party who forwards the template to V).
2. V's node calls `device.addIndirectCorrespondents()`, inserting D into `correspondent_devices` with `is_indirect=1`, without any pairing secret ever being exchanged between V and D directly. [1](#0-0) 
3. D sends V a `hub/message` with `subject: "sign"` and a crafted `unsigned_unit`/`private_payloads` for an address V co-controls.
4. `device.js` accepts the message because D is "known" (`is_indirect=1` counts): [6](#0-5) 
5. `wallet.js handleMessageFromHub()` processes the `sign` subject fully because the `bIndirectCorrespondent` restriction is disabled: [3](#0-2) 
6. V's wallet raises a signing confirmation dialog / proceeds with `signing_request`, exactly as if D were a fully, explicitly paired correspondent — despite D never having completed the intended out-of-band trust establishment.

### Citations

**File:** device.js (L203-221)
```javascript
			// check that we know this device
			db.query("SELECT hub, is_indirect FROM correspondent_devices WHERE device_address=?", [from_address], function(rows){
				if (rows.length > 0){
					if (json.device_hub && typeof json.device_hub === 'string' && json.device_hub.length <= 200 && network.isValidWsUrl(conf.WS_PROTOCOL + json.device_hub) && json.device_hub !== rows[0].hub) // update correspondent's home address if necessary
						db.query("UPDATE correspondent_devices SET hub=? WHERE device_address=?", [json.device_hub, from_address], function(){
							handleMessage(rows[0].is_indirect);
						});
					else
						handleMessage(rows[0].is_indirect);
				}
				else{ // correspondent not known
					var arrSubjectsAllowedFromNoncorrespondents = ["pairing", "my_xpubkey", "wallet_fully_approved"];
					if (arrSubjectsAllowedFromNoncorrespondents.indexOf(json.subject) === -1){
						respondWithError("correspondent not known and not whitelisted subject");
						return;
					}
					handleMessage(false);
				}
			});
```

**File:** device.js (L906-919)
```javascript
function addIndirectCorrespondents(arrOtherCosigners, onDone){
	async.eachSeries(arrOtherCosigners, function(correspondent, cb){
		if (correspondent.device_address === my_device_address)
			return cb();
		if (!ValidationUtils.isNonemptyString(correspondent.hub) || !network.isValidWsUrl(conf.WS_PROTOCOL + correspondent.hub))
			return cb(); // ignore silently and continue eachSeries
		db.query(
			"INSERT "+db.getIgnore()+" INTO correspondent_devices (device_address, hub, name, pubkey, is_indirect) VALUES(?,?,?,?,1)", 
			[correspondent.device_address, correspondent.hub, correspondent.name, correspondent.pubkey],
			function(){
				cb();
			}
		);
	}, onDone);
```

**File:** wallet.js (L63-99)
```javascript
// one of callbacks MUST be called, otherwise the mutex will stay locked
function handleMessageFromHub(ws, json, device_pubkey, bIndirectCorrespondent, callbacks){
	if (isTooDeeplyNestedOrHasTooManyNodes(json, 20, 100000))
		return callbacks.ifError("message from hub is too deeply nested or has too many nodes");

	// serialize all messages from hub
	mutex.lock(["from_hub"], function(unlock){
		var oldcb = callbacks;
		callbacks = {
			ifOk: function(){oldcb.ifOk(); unlock();},
			ifError: function(err){oldcb.ifError(err); unlock();}
		};
		try {
			doHandle();
		}
		catch (e) {
			callbacks.ifError("exception in handleMessageFromHub: " + e.toString());
		}
	});

		
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
			case "pairing":
				device.handlePairingMessage(json, device_pubkey, callbacks);
				break;
```

**File:** wallet.js (L251-277)
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
```
