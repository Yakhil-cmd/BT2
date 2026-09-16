### Title
Silent acceptance of a stale/attacker-raced `new_shared_address` device message due to `INSERT IGNORE` semantics - (File: wallet_defined_by_addresses.js)

### Summary
The reported CVE (ALPINE-CVE-2022-2625) is a class of bug where an object-creation statement that uses "create-if-not-exists" semantics (`CREATE OR REPLACE` / `CREATE IF NOT EXISTS`) silently keeps or reuses a pre-existing, attacker-influenced object instead of the one the legitimate actor intended to create, because the presence check does not verify that the *content* being inserted actually matches what the legitimate party expects. `ocore` contains the same pattern in `wallet_defined_by_addresses.js`, where `addNewSharedAddress()` persists a multi-signature ("shared") address definition and its cosigner-to-device mapping using `INSERT ... IGNORE`, so whichever `new_shared_address` device message arrives first wins, and any later (legitimate) message for the same address is silently dropped without any content-equality check on the security-relevant device mapping.

### Finding Description
`handleNewSharedAddress()` [1](#0-0)  only validates that:
- `body.address` equals `chash160(body.definition)`, and
- each `signerInfo.address` in `body.signers` matches the address found at the same path inside the definition (`extractAddressPathsFromDefinition`) [2](#0-1) 

It does **not** validate or bind `signerInfo.device_address` to anything cryptographically tied to the definition — the device address that will receive private-chain forwards and signing requests for a given signing path is an arbitrary field supplied by whichever device sends the message.

`addNewSharedAddress()` then writes the address and per-path device mapping with `INSERT IGNORE`: [3](#0-2) 

`shared_addresses` and `shared_address_signing_paths` both use the shared address (and signing path) as (part of) their primary key [4](#0-3) . Because the shared address itself is deterministic (`chash160` of the definition), an attacker who already knows or can predict the future definition (e.g. it uses public addresses, or the attacker is one of the legitimate cosigners setting up the deal) can pre-emptively craft and send a `new_shared_address` message for the *same* address/definition, but substitute a `device_address` under their control for another cosigner's signing path. If this attacker-controlled message is processed first, `INSERT IGNORE` persists it. When the real cosigner later sends the correct `new_shared_address` message with the correct device mapping, the `INSERT IGNORE` on `shared_address_signing_paths` (keyed by `(shared_address, signing_path)`) silently no-ops — the wallet keeps the attacker's device mapping instead of updating it to the legitimate one. This mirrors the CVE's root cause exactly: a party with limited ability to pre-create an object in a namespace can win a race against a legitimate later create/update, and the "IF NOT EXISTS"/"IGNORE" logic hides the fact that the wrong object was retained.

The device mapping controls where private payment chains for that member address get forwarded (`forwardPrivateChainsToOtherMembersOfAddresses` reads `device_address` from `shared_address_signing_paths` [5](#0-4) ) and where signature requests are routed. A poisoned mapping therefore causes the local wallet to forward private-chain data intended for a legitimate cosigner to the attacker's device, and/or route signing requests to the attacker instead of the real signer — breaking multisig cosigning and leaking private-payment information to an unauthorized device.

### Impact Explanation
- Confidentiality: private payment chain data destined for a legitimate cosigner of a shared/multisig address can be forwarded to an attacker-controlled device instead (`forwardPrivateChainsToOtherMembersOfAddresses`).
- Availability/fund freezing: signing requests routed via `shared_address_signing_paths.device_address` would go to the wrong (attacker or unreachable) device, preventing the real cosigner from ever being asked to sign, effectively freezing funds controlled by the shared address until the mapping is manually corrected.
- This does not directly allow forging a valid signature on-chain (unit validation still requires the real definition's keys per `definition.js`/`validation.js`), so it is not a direct unauthorized-spend of confirmed funds, but it is a concrete funds-freezing / private-data-misdirection outcome reachable purely by a paired/correspondent device sending a crafted `new_shared_address` message — no privileged network position needed.

### Likelihood Explanation
Exploitation requires the attacker to be a correspondent device already participating (or claiming to participate) in the shared-address setup protocol and to win a race by sending its forged mapping before the legitimate cosigner's message arrives — a timing-dependent, moderately involved but realistic scenario in any multi-party shared-address setup flow, especially since `createNewSharedAddressByTemplate`/`approvePendingSharedAddress` already show that legitimate address definitions are exchanged before all approvals are collected, giving an attacker time to inject a colliding `new_shared_address` for the same, predictable address.

### Recommendation
- On `INSERT IGNORE` conflict in `shared_address_signing_paths` (and `shared_addresses`), compare the incoming `device_address`/definition to the stored row and raise an error (or require cryptographic proof of the claimed device address, e.g. via signed pairing) instead of silently keeping the first-seen value.
- Bind `device_address` to `signerInfo.address` cryptographically (e.g., only accept it from the device that is paired/correspondent for that member address) rather than trusting the field in the `new_shared_address` payload.

### Proof of Concept
Conceptual (not verified end-to-end due to index limitations on device-pairing/network code):
1. Legitimate parties A and B agree out-of-band on a 2-of-2 shared address definition `D` referencing addresses `addrA`, `addrB`; the resulting `shared_address = chash160(D)` is deterministic and known to anyone who knows `D` (or can be inferred/guessed if addresses are reused/public).
2. Attacker M, already a correspondent device of A, sends A a `new_shared_address` message with `address = shared_address`, `definition = D`, and `signers` containing the correct `addrB` for B's path but `device_address = M's device` for that path (this passes the `assocDefinitionAddresses[signing_path] !== signerInfo.address` check in `handleNewSharedAddress` since only the address, not the device_address, is validated).
3. A's wallet processes this first, and `addNewSharedAddress` `INSERT IGNORE`s the row `(shared_address, addrB path) -> device=M` into `shared_address_signing_paths`.
4. B later sends the genuine `new_shared_address` message with the correct `device_address = B`. Because of `INSERT IGNORE` and the existing primary-key row, the update is silently dropped; A's wallet keeps forwarding private chains/signing requests for B's path to M instead of B.

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

**File:** initial-db/byteball-sqlite-light.sql (L583-623)
```sql
-- addresses composed of several other addresses (such as ["and", [["address", "ADDRESS1"], ["address", "ADDRESS2"]]]), 
-- member addresses live on different devices, member addresses themselves may be composed of several keys
CREATE TABLE shared_addresses (
	shared_address CHAR(32) NOT NULL PRIMARY KEY,
	definition TEXT NOT NULL,
	creation_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE pending_shared_addresses (
	definition_template_chash CHAR(32) NOT NULL PRIMARY KEY,
	definition_template TEXT NOT NULL,
	creation_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE pending_shared_address_signing_paths (
	definition_template_chash CHAR(32) NOT NULL,
	device_address CHAR(33) NOT NULL,
	signing_path TEXT NOT NULL, -- path from root to member address
	address CHAR(32) NULL, -- member address
	device_addresses_by_relative_signing_paths TEXT NULL, -- json
	creation_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	approval_date TIMESTAMP NULL,
	PRIMARY KEY (definition_template_chash, signing_path),
	-- own address is not present in correspondents
--    FOREIGN KEY byDeviceAddress(device_address) REFERENCES correspondent_devices(device_address),
	FOREIGN KEY (definition_template_chash) REFERENCES pending_shared_addresses(definition_template_chash)
);

CREATE TABLE shared_address_signing_paths (
	shared_address CHAR(32) NOT NULL,
	signing_path VARCHAR(255) NULL, -- full path to signing key which is a member of the member address
	address CHAR(32) NOT NULL, -- member address
	member_signing_path VARCHAR(255) NULL, -- path to signing key from root of the member address
	device_address CHAR(33) NOT NULL, -- where this signing key lives or is reachable through
	creation_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY (shared_address, signing_path),
	FOREIGN KEY (shared_address) REFERENCES shared_addresses(shared_address)
	-- own address is not present in correspondents
--    FOREIGN KEY byDeviceAddress(device_address) REFERENCES correspondent_devices(device_address)
);
CREATE INDEX sharedAddressSigningPathsByDeviceAddress ON shared_address_signing_paths(device_address);
```
