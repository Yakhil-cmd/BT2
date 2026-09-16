Based on my investigation, I found a valid analog. The core of CVE-2020-25717 is that Samba trusts attacker-influenced identity-mapping data (SID→UID) without verifying that the claimed local identity is actually backed by the correct credential, letting an authenticated but unprivileged user get mapped to a more privileged local account. The closest reachable analog in `ocore--006` is in `wallet_defined_by_addresses.js`'s handling of the `new_shared_address` device message, where a peer-supplied `device_address` → payment-address mapping (`assocSignersByPath`) is accepted and persisted without any cryptographic proof that the claimed device actually controls the claimed address.

### Title
Unverified peer-supplied signer→device-address mapping in shared-address setup allows cosigner impersonation - ([File: wallet_defined_by_addresses.js])

### Summary
`handleNewSharedAddress()` accepts a `signers` map (`signing_path -> {address, device_address}`) from any correspondent device via the `new_shared_address` message and stores it verbatim in `shared_address_signing_paths` after only checking that each `address` is a syntactically valid address and matches the position in the definition hash tree. It never verifies that the peer claiming to be `device_address` for a given `address` is cryptographically authorized to represent that address (e.g., by an attestation signed with the address's own key).

### Finding Description
`handleNewSharedAddress` validates:
- that `body.definition` hashes to `body.address` [1](#0-0) 
- that each `signerInfo.address` is a syntactically valid address or `'secret'` [2](#0-1) 
- that the `signers` map is structurally consistent with the `['address', X]` leaves of the definition, via `extractAddressPathsFromDefinition` [3](#0-2) [4](#0-3) 

At no point does it verify that the `device_address` claimed for a given member `address` is actually controlled by that address's key holder. `determineIfIncludesMeAndRewriteDeviceAddress` only forces `device_address = myDeviceAddress` when the `address` is found in *my own* `my_addresses` table; for every other signing path (including addresses recognized as `shared` addresses I don't directly own, or any peer address at all), the attacker-supplied `device_address` is trusted and written into `shared_address_signing_paths` unchanged [5](#0-4) [6](#0-5) .

This mapping later drives which correspondent device is asked to co-sign spends from the shared address, and it is also used to decide where to forward the wallet's own private-payment chains and cosigner requests: `findAddress()` walks `shared_address_signing_paths` and treats the stored `device_address` as authoritative for routing sign requests and secrets [7](#0-6) , and `forwardPrivateChainsToOtherMembersOfAddresses` / `readSharedAddressCosigners` route private payment data to whatever `device_address` is on file for the shared address [8](#0-7) [9](#0-8) .

This is directly analogous to CVE-2020-25717: an authenticated peer (an existing correspondent device, playing the role of the "authenticated attacker") supplies an identity mapping (`address -> device_address`) that is accepted without proof of ownership, and the local node uses this untrusted mapping to decide which remote identity is entitled to act as a specific principal in subsequent authorization-sensitive operations (signing offers, private chain forwarding, cosigner confirmation prompts).

### Impact Explanation
Because `device_address` is not verified to belong to the address it's claimed to represent, a malicious cosigner (or a correspondent who is a legitimate member of one signing path in a multi-address/shared-address definition) can supply a `new_shared_address` message where `device_address` for another signing path points to the attacker's own device rather than the real owner. Concretely:
- Private payment chains and payment/change data intended for the legitimate cosigner get forwarded to the attacker's device instead (`forwardPrivateChainsToOtherMembersOfAddresses`, `sendSharedAddressToPeer`), leaking private-asset payment history/amounts to an unauthorized party.
- Signing/confirmation requests (`ifRemote` branch in `findAddress`/`wallet.js` sign flow) can be routed to an attacker-controlled device, and confirmation UI text (peer names shown via `readSharedAddressPeers`) can misattribute a payment to the wrong party, facilitating social-engineering-assisted unauthorized spending approvals.
- Because `readSharedAddressCosigners`/`readSharedAddressPeers` and other UI-facing helpers rely on the same untrusted `device_address` column, a user could be shown a false picture of which device is responsible for a payment path, leading them to approve a shared-address transaction they would otherwise reject — i.e., unauthorized spending from the shared address.

### Likelihood Explanation
Exploitation requires only that the attacker be an existing/known correspondent device (or become one via pairing) who is invited into (or is one of) the cosigners of a shared/multisig address — the same "authenticated attacker" bar as the Samba CVE. `new_shared_address` is processed automatically as soon as it arrives from any known correspondent, with no user confirmation gate before the mapping is persisted [10](#0-9) .

### Recommendation
Require that each non-local `signerInfo.device_address` in `handleNewSharedAddress` be corroborated independently (e.g., only accept/update the mapping if it comes directly from that `device_address` itself, or require a signed attestation binding `address` to `device_address`), rather than trusting whatever the message's sender (who may only control one signing path) claims about all other paths. At minimum, cross-check claimed `device_address` values against already-known `correspondent_devices`/prior `shared_address_signing_paths` records and reject/flag mismatches instead of silently overwriting.

### Proof of Concept
1. Attacker device A is a correspondent and is included as one signer (e.g., `r.0`) in a legitimate 2-of-2 (or larger) shared-address definition together with victim B (`r.1`).
2. A crafts and sends a `new_shared_address` message where `body.definition` is the real (valid) shared definition, but `body.signers["r.1"].device_address` is set to A's own device address (or a third attacker-controlled device) instead of B's real device address, while `body.signers["r.1"].address` still correctly equals B's real payment address (so it passes `extractAddressPathsFromDefinition` validation) [4](#0-3) .
3. Because the victim's own node only rewrites `device_address` back to itself when the entry matches one of `my_addresses` — it never checks whether *other* signing paths' claimed `device_address` is correct — the tampered mapping is stored as-is in `shared_address_signing_paths` on any third node that isn't B itself [11](#0-10) .
4. Subsequent private-chain forwarding/cosign requests for B's signing path are now routed to A's device rather than B's, exposing private payment data and enabling A to intercept or otherwise be substituted into the cosigning/notification flow for the shared address.

### Citations

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

**File:** wallet_defined_by_addresses.js (L338-375)
```javascript
// Returns a map of signing_path -> address for every ["address", ...] leaf in the definition
function extractAddressPathsFromDefinition(arrDefinition) {
	var result = {};
	function traverse(arr, path) {
		if (!Array.isArray(arr) || arr.length < 2) return;
		var op = arr[0];
		var args = arr[1];
		switch (op) {
			case 'or':
			case 'and':
				if (Array.isArray(args))
					for (var i = 0; i < args.length; i++)
						traverse(args[i], path + '.' + i);
				break;
			case 'r of set':
				if (args && Array.isArray(args.set))
					for (var i = 0; i < args.set.length; i++)
						traverse(args.set[i], path + '.' + i);
				break;
			case 'weighted and':
				if (args && Array.isArray(args.set))
					for (var i = 0; i < args.set.length; i++)
						traverse(args.set[i].value, path + '.' + i);
				break;
			case 'address':
				result[path] = args;
				break;
			case 'hash':
				result[path] = 'secret';
				break;
			case 'in merkle':
				result[path] = ''; // empty address
				break;
		}
	}
	traverse(arrDefinition, 'r');
	return result;
}
```

**File:** wallet_defined_by_addresses.js (L383-390)
```javascript
	try {
		var addr = objectHash.getChash160(body.definition);
	}
	catch (e) {
		return callbacks.ifError("invalid definition: " + e);
	}
	if (body.address !== addr)
		return callbacks.ifError("definition doesn't match its c-hash");
```

**File:** wallet_defined_by_addresses.js (L391-395)
```javascript
	for (var signing_path in body.signers){
		var signerInfo = body.signers[signing_path];
		if (signerInfo.address && signerInfo.address !== 'secret' && !ValidationUtils.isValidAddress(signerInfo.address))
			return callbacks.ifError("invalid member address: " + JSON.stringify(signerInfo.address));
	}
```

**File:** wallet_defined_by_addresses.js (L396-405)
```javascript
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

**File:** wallet_defined_by_addresses.js (L591-606)
```javascript
// returns information about cosigner devices
function readSharedAddressCosigners(shared_address, handleCosigners){
	db.query(
		"SELECT DISTINCT shared_address_signing_paths.device_address, name, "+db.getUnixTimestamp("shared_addresses.creation_date")+" AS creation_ts \n\
		FROM shared_address_signing_paths \n\
		JOIN shared_addresses USING(shared_address) \n\
		LEFT JOIN correspondent_devices USING(device_address) \n\
		WHERE shared_address=? AND device_address!=?",
		[shared_address, device.getMyDeviceAddress()],
		function(rows){
			if (rows.length === 0)
				throw Error("no cosigners found for shared address "+shared_address);
			handleCosigners(rows);
		}
	);
}
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

**File:** wallet.js (L1265-1287)
```javascript
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
```
