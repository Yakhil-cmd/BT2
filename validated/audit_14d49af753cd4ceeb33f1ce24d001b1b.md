## Analysis

The GHSA-q44r-f2hm-v76v bug class is: **a security-critical field is not restricted against control/ANSI-escape characters before being shown to a human who makes a trust decision based on what they see**, allowing the attacker to spoof the displayed value and trick the reviewer into approving something malicious.

In `ocore`, the analogous flow is the multi-signature (shared) wallet creation handshake between paired devices. When device A invites device B to co-sign a new shared wallet, it sends a `wallet_name` and a list of `other_cosigners` (each with a `name`) over the device-message channel. The recipient's wallet handler `handleOfferToCreateNewWallet` in `wallet_defined_by_keys.js` only strips `<` and `>` characters and enforces a length limit — it does not restrict any other characters, including terminal control sequences, ANSI escape codes, or bidirectional/formatting Unicode characters: [1](#0-0) 

Specifically:
- `body.wallet_name = body.wallet_name.replace(/[<>]/g, '')` [2](#0-1) 
- `cosigner.name = cosigner.name.replace(/[<>]/g, '')` [3](#0-2) 

These fields flow unmodified into `eventBus.emit("create_new_wallet", ...)`, which the wallet UI is expected to display to the user so they can decide whether to approve joining the multisig wallet (via `approveWallet`) with the listed cosigners: [4](#0-3)  and [5](#0-4) . `readCosigners` similarly returns the raw `name` field for display in existing multisig wallets: [6](#0-5) . Likewise, `correspondent_devices.name` (set from an attacker-controlled `body.device_name` in `handlePairingMessage`, only filtered by `.replace(/<[^>]*>?/g, '')`) is the same field surfaced back through `readSharedAddressCosigners`/`readSharedAddressPeers`: [7](#0-6) [8](#0-7) .

### Why this matches the CVE's bug class
Just as an unrestricted CSR Common Name let an attacker use ANSI control sequences to alter what a certificate-signing admin visually perceives, an attacker-controlled paired device can supply a `wallet_name` or `cosigner.name` containing ANSI escape sequences (or Unicode right-to-left override / zero-width characters) that:
- Overwrite/hide preceding terminal output in CLI-based wallet displays, or
- Visually reorder/mask the real device name/address so it appears to be a trusted cosigner,

causing the victim to approve joining a multi-signature address where the actual composed cosigner set (which is cryptographically verified only by device address, not by the spoofed name) differs from what they believe they approved. Since shared-address co-signers control spending authority over any funds later sent to that address, an approval obtained via a spoofed name can result in an unintended/malicious party gaining spending control — i.e., loss of funds when the shared address is used, directly reachable by any paired device (correspondent) with no special privilege, matching the "wallet and contract message handling" reachable-path category.

### Title
Insufficient sanitization of `wallet_name`/cosigner `name` in shared-wallet creation offer permits ANSI/control-character spoofing to trick users into approving malicious co-signers - (File: `wallet_defined_by_keys.js`)

### Summary
`handleOfferToCreateNewWallet` (and the pairing name handler in `device.js`) only strip the characters `<` and `>` from attacker-supplied `wallet_name`/`cosigner.name`/`device_name` fields before they are stored and later displayed to the user for an approval decision (`approveWallet`). No filtering is applied to ANSI escape sequences, other control characters, or bidirectional Unicode formatting characters.

### Finding Description
A remote, paired (but otherwise unprivileged) device can initiate a shared multisig wallet creation offer (`create_new_wallet`) with a crafted `wallet_name` or `other_cosigners[i].name` containing terminal control/escape sequences. `handleOfferToCreateNewWallet` only removes `<`/`>` characters: [9](#0-8) . These strings are propagated as-is to the UI-facing `create_new_wallet` event and later persisted/queried via `readCosigners`, to be rendered when the user is asked whether to approve joining the wallet: [10](#0-9) [6](#0-5) . Because the real cryptographic binding of a co-signer is only its `device_address` (derived from its pubkey), while the human-facing trust decision is made by reading the (spoofable) `name` field, an attacker can make the confirmation prompt visually claim a trustworthy identity while the underlying `device_address` belongs to the attacker.

### Impact Explanation
If the victim approves the offer based on the spoofed display, the attacker's device becomes a legitimate co-signer of the resulting shared address, gaining the ability to co-sign/spend any funds later deposited into that address alongside (or instead of) the intended parties — a concrete path to loss of funds for anyone who funds the shared address believing it to be controlled by trusted parties.

### Likelihood Explanation
Any device that another user has paired with (a normal, low-privilege interaction — pairing is routinely done to transact) can send this offer; no network, hub, or node compromise is required, only social engineering enabled by the missing sanitization, which mirrors the "user-assisted remote attacker" scenario in the original CVE.

### Recommendation
Sanitize `wallet_name`, `cosigner.name`, and `device_name` by stripping/rejecting all non-printable and control characters (e.g., allow only a safe printable-character allowlist), not just `<`/`>`, before storage and display, consistent with how `data_feed` names/values are restricted elsewhere in the codebase (e.g., rejecting `\n` in `aa_validation.js`): [11](#0-10) .

### Proof of Concept
1. Device A pairs with victim device B.
2. Device A calls `createWalletByDevices`/`sendOfferToCreateNewWallet` with `walletName` or an `other_cosigners[i].name` equal to a string containing ANSI escape sequences (e.g., `\x1b[2K\x1b[1G` to erase/rewrite a line, or a right-to-left override character) designed to make the displayed cosigner identity/name appear as a trusted contact.
3. `handleOfferToCreateNewWallet` on B only strips `<`/`>`, leaving the escape sequences intact: [9](#0-8) .
4. B's wallet UI renders the manipulated name in the "approve new wallet" prompt; B approves believing the co-signer is a known trusted party.
5. `approveWallet` finalizes the shared address with the attacker's real `device_address` as an authorized co-signer: [5](#0-4) .

### Citations

**File:** wallet_defined_by_keys.js (L65-96)
```javascript
function handleOfferToCreateNewWallet(body, from_address, callbacks){
	if (!ValidationUtils.isNonemptyString(body.wallet))
		return callbacks.ifError("no wallet");
	if (!ValidationUtils.isNonemptyString(body.wallet_name))
		return callbacks.ifError("no wallet_name");
	if (body.wallet.length > constants.HASH_LENGTH)
		return callbacks.ifError("wallet too long");
	if (body.wallet_name.length > 200)
		return callbacks.ifError("wallet_name too long");
	body.wallet_name = body.wallet_name.replace(/[<>]/g, '');
	if (!ValidationUtils.isArrayOfLength(body.wallet_definition_template, 2))
		return callbacks.ifError("no definition template");
	if (!ValidationUtils.isNonemptyArray(body.other_cosigners))
		return callbacks.ifError("no other_cosigners");
	for (var i=0; i<body.other_cosigners.length; i++){
		var cosigner = body.other_cosigners[i];
		if (!ValidationUtils.isNonemptyObject(cosigner))
			return callbacks.ifError("bad cosigner");
		if (!ValidationUtils.isStringOfLength(cosigner.pubkey, constants.PUBKEY_LENGTH))
			return callbacks.ifError("bad pubkey");
		if (cosigner.device_address !== objectHash.getDeviceAddress(cosigner.pubkey))
			return callbacks.ifError("bad cosigner device address");
		if (!ValidationUtils.isNonemptyString(cosigner.name))
			return callbacks.ifError("no cosigner name");
		if (cosigner.name.length > 100)
			return callbacks.ifError("cosigner name too long");
		cosigner.name = cosigner.name.replace(/[<>]/g, '');
		if (!ValidationUtils.isNonemptyString(cosigner.hub))
			return callbacks.ifError("no cosigner hub");
		if (cosigner.hub.length > 100)
			return callbacks.ifError("cosigner hub too long");
	}
```

**File:** wallet_defined_by_keys.js (L97-111)
```javascript
	// the wallet should have an event handler that requests user confirmation, derives (or generates) a new key, records it, 
	// and sends the newly derived xpubkey to other members
	validateWalletDefinitionTemplate(body.wallet_definition_template, from_address, function(err, arrDeviceAddresses){
		if (err)
			return callbacks.ifError(err);
		if (body.other_cosigners.length !== arrDeviceAddresses.length - 1)
			return callbacks.ifError("wrong length of other_cosigners");
		var arrOtherDeviceAddresses = _.uniq(body.other_cosigners.map(function(cosigner){ return cosigner.device_address; }));
		arrOtherDeviceAddresses.push(from_address);
		if (!_.isEqual(arrDeviceAddresses.sort(), arrOtherDeviceAddresses.sort()))
			return callbacks.ifError("wrong other_cosigners");
		eventBus.emit("create_new_wallet", body.wallet, body.wallet_definition_template, arrDeviceAddresses, body.wallet_name, body.other_cosigners, body.is_single_address);
		callbacks.ifOk();
	});
}
```

**File:** wallet_defined_by_keys.js (L289-302)
```javascript
// called from UI after user confirms creation of wallet initiated by another device
function approveWallet(wallet, xPubKey, account, arrWalletDefinitionTemplate, arrOtherCosigners, onDone){
	var arrDeviceAddresses = getDeviceAddresses(arrWalletDefinitionTemplate);
	device.addIndirectCorrespondents(arrOtherCosigners, function(){
		addWallet(wallet, xPubKey, account, arrWalletDefinitionTemplate, function(){
			arrDeviceAddresses.forEach(function(device_address){
				if (device_address !== device.getMyDeviceAddress())
					sendMyXPubKey(device_address, wallet, xPubKey);
			});
			if (onDone)
				onDone();
		});
	});
}
```

**File:** wallet_defined_by_keys.js (L395-413)
```javascript
function readCosigners(wallet, handleCosigners){
	db.query(
		"SELECT extended_pubkeys.device_address, name, approval_date, extended_pubkey \n\
		FROM extended_pubkeys LEFT JOIN correspondent_devices USING(device_address) WHERE wallet=?", 
		[wallet], 
		function(rows){
			rows.forEach(function(row){
				if (row.device_address === device.getMyDeviceAddress()){
					if (row.name !== null)
						throw Error("found self in correspondents");
					row.me = true;
				}
				else if (row.name === null)
					throw Error("cosigner not found among correspondents, cosigner="+row.device_address+", my="+device.getMyDeviceAddress());
			});
			handleCosigners(rows);
		}
	);
}
```

**File:** device.js (L822-826)
```javascript
			// add new correspondent and delete pending pairing
			var safe_device_name = body.device_name.replace(/<[^>]*>?/g, '');
			db.query(
				"INSERT "+db.getIgnore()+" INTO correspondent_devices (device_address, pubkey, hub, name, is_confirmed) VALUES (?,?,?,?,1)", 
				[from_address, device_pubkey, json.device_hub, safe_device_name],
```

**File:** wallet_defined_by_addresses.js (L591-632)
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

// returns list of payment addresses of peers
function readSharedAddressPeerAddresses(shared_address, handlePeerAddresses){
	readSharedAddressPeers(shared_address, function(assocNamesByAddress){
		handlePeerAddresses(Object.keys(assocNamesByAddress));
	});
}

// returns assoc array: peer name by address
function readSharedAddressPeers(shared_address, handlePeers){
	db.query(
		"SELECT DISTINCT address, name FROM shared_address_signing_paths LEFT JOIN correspondent_devices USING(device_address) \n\
		WHERE shared_address=? AND shared_address_signing_paths.device_address!=?",
		[shared_address, device.getMyDeviceAddress()],
		function(rows){
			// no problem if no peers found: the peer can be part of our multisig address and his device address will be rewritten to ours
		//	if (rows.length === 0)
		//		throw Error("no peers found for shared address "+shared_address);
			var assocNamesByAddress = {};
			rows.forEach(function(row){
				assocNamesByAddress[row.address] = row.name || 'unknown peer';
			});
			handlePeers(assocNamesByAddress);
		}
	);
}
```

**File:** aa_validation.js (L98-111)
```javascript
							if (feed_name.length > constants.MAX_DATA_FEED_NAME_LENGTH)
								return cb2("feed name " + feed_name + " too long");
							if (feed_name.indexOf('\n') >= 0)
								return cb2("feed name " + feed_name + " contains \\n");
						}
						var value = payload[feed_name];
						if (typeof value === 'string') {
							var value_formula = getFormula(value);
							if (value_formula === null) {
								if (value.length > constants.MAX_DATA_FEED_VALUE_LENGTH)
									return cb2("value " + value + " too long");
								if (value.indexOf('\n') >= 0)
									return cb2("value " + value + " of feed name " + feed_name + " contains \\n");
							}
```
