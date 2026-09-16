## Analysis

The ASF bug class is: a proxy-style command that specifies a *target* different from the *sender/handler*, where the access-control check is performed against the wrong entity (the handler bot instead of the actual target bot). The closest reachable analog in ocore's paired-device / wallet message-handling code is in the shared/multisig address resolution logic used by the `sign` proxy command.

### Title
Inadequate access verification when relaying a `sign` proxy command for a nested shared address - (File: wallet.js)

### Summary
`findAddress()` in `wallet.js` resolves the device(s) responsible for signing on behalf of a (possibly deeply nested) shared/multisig address. When the resolution reaches a leaf address that this device does not know a direct signer for (`peer_addresses` returns no match), the code falls back to `fallbackInfo`, which is populated from the **parent** shared address's cosigner set rather than the actual signer/cosigner set of the address being resolved (`body.address`/`signing_path` that was requested).

### Finding Description
In `findAddress`, when recursing into a member of a shared address, `newFallbackInfo` is built from the *current* (outer) shared address's cosigners, excluding the device that manages the specific member path: [1](#0-0) 
That `fallbackInfo` is only consumed several levels deeper, when the recursion cannot resolve the address at all via `peer_addresses`: [2](#0-1) 
At that point, `callbacks.ifRemote(fallbackInfo.device_address, fallbackInfo.other_device_addresses)` hands back a device/cosigner list that belongs to an **ancestor** shared address in the definition tree, not to the actual address for which the signature was requested.

This value flows directly into the access check of the `sign` proxy-command handler in `handleMessageFromHub`: [3](#0-2) 
The check `other_device_addresses.includes(from_address)` is the sole authorization gate deciding whether a peer device is allowed to have its `sign` request relayed on to the actual key-holding device via `device.sendMessageToDevice`. Because `other_device_addresses` can be the cosigner list of a *different* (ancestor) address rather than of the address actually named in `body.address`, a device that is a legitimate cosigner of one address in a multi-level shared-address definition can pass the check for a *different* address it is not entitled to request signatures for, exactly mirroring the ASF flaw where a proxy-style access check validated against the wrong target entity.

### Impact Explanation
Passing this check causes the local device to forward the unsigned unit to `device_address` (the device believed to hold the target key), waiting for a signature that will then be relayed back to the (unauthorized) requester. Depending on that remote device's own confirmation flow, this can be used to solicit signatures/confirmation dialogs for addresses the caller has no legitimate relationship to, and to probe/confirm the existence and reachability of member addresses/devices outside the caller's designated cosigning role, undermining the confidentiality/authorization guarantees of the shared-address structure. If the remote device auto-approves based on device-address trust rather than a strict per-address cosigner check, this could contribute to unauthorized co-signing flows in a multisig wallet.

### Likelihood Explanation
Exploitation requires that the attacker already controls a paired device that is a legitimate cosigner of *some* shared address that is an ancestor of the targeted member address in the definition tree — i.e., significant pre-existing access, similar to the ASF advisory's requirement that the attacker already control a bot in the process. This matches the "AC:H/PR:H" characteristics of the original CVE (Medium severity), since it is not exploitable by a fully unprivileged party.

### Recommendation
When falling back after `peer_addresses` lookup fails, do not reuse a stale `fallbackInfo` computed for an ancestor shared address. Instead, either fail closed (return `ifUnknownAddress`) when no direct/legitimate signer/cosigner set can be established for the exact leaf address and signing path, or recompute the authorized device list scoped strictly to the address/signing_path actually being resolved at each recursion level.

### Proof of Concept
1. Device D1 constructs a multi-level shared address `S` whose definition nests member address `M` (managed via device D3), and includes D2 as a cosigner of `S` (but not of `M`).
2. D1 has full knowledge of `S`'s cosigners (via `shared_address_signing_paths`) but only partial/no direct knowledge of how `M` is ultimately reachable through `peer_addresses`.
3. D2 (attacker-controlled, a legitimate cosigner of `S` only) sends a `sign` command to D1 for `address = M`, `signing_path` pointing at the nested member.
4. `findAddress` recurses through `S` into `M`, fails to resolve `M` via `peer_addresses`, and falls back to `fallbackInfo` populated with `S`'s cosigner list (which includes D2).
5. The `sign` handler's check `other_device_addresses.includes(from_address)` passes for D2 even though D2 has no designated signing role for `M`, and the request is forwarded to D3. [4](#0-3)

### Citations

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

**File:** wallet.js (L1233-1316)
```javascript
function findAddress(address, signing_path, callbacks, fallbackInfo){
	db.query(
		"SELECT wallet, account, is_change, address_index, full_approval_date, device_address \n\
		FROM my_addresses JOIN wallets USING(wallet) JOIN wallet_signing_paths USING(wallet) \n\
		WHERE address=? AND signing_path=?",
		[address, signing_path],
		async function(rows){
			if (rows.length > 1)
				throw Error("more than 1 address found");
			if (rows.length === 1){
				var row = rows[0];
				if (!row.full_approval_date)
					return callbacks.ifError("wallet of address "+address+" not approved");
				if (row.device_address !== device.getMyDeviceAddress()) {
					const other_rows = await db.query("SELECT DISTINCT device_address FROM wallet_signing_paths WHERE wallet=? AND device_address!=?", [row.wallet, row.device_address]);
					const other_device_addresses = other_rows.map(r => r.device_address);
					return callbacks.ifRemote(row.device_address, other_device_addresses);
				}
				var objAddress = {
					address: address,
					wallet: row.wallet,
					account: row.account,
					is_change: row.is_change,
					address_index: row.address_index
				};
				callbacks.ifLocal(objAddress);
				return;
			}
			const prefix = conf.storage === 'sqlite' ? "signing_path||'.'" : "CONCAT(signing_path, '.')";
			db.query(
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
					db.query(
						"SELECT device_address, signing_paths FROM peer_addresses WHERE address=?", 
						[address],
						function(pa_rows) {
							if (pa_rows.length > 1)
								throw Error("more than 1 peer address found for address "+address);
							var candidate_addresses = [];
							for (var i = 0; i < pa_rows.length; i++) {
								var row = pa_rows[i];
								JSON.parse(row.signing_paths).forEach(function(signing_path_candidate){
									if (signing_path_candidate === signing_path)
										candidate_addresses.push(row.device_address);
								});
							}
							if (candidate_addresses.length > 1)
								throw Error("more than 1 candidate device address found for peer address "+address+" and signing path "+signing_path);
							if (candidate_addresses.length == 1)
								return callbacks.ifRemote(candidate_addresses[0], []);
							if (fallbackInfo)
								return callbacks.ifRemote(fallbackInfo.device_address, fallbackInfo.other_device_addresses);
							return callbacks.ifUnknownAddress();
						}
					);
				}
			);
		}
	);
}
```
