## Title
Improper Access Control in `new_shared_address` handling allows an unprivileged paired device to inject itself as an unauthorized co-signer of a victim's address - ([File: wallet_defined_by_addresses.js])

### Summary
`handleNewSharedAddress()` only checks that the *recipient's own* address/device is referenced somewhere in an incoming shared-address definition, but never checks (a) that the message actually originates from a device that is a legitimate cosigner of that definition, or (b) that the definition genuinely requires cooperation between the parties before it is accepted and installed as a trusted "shared address." This is the same class of bug as the vantage6 CVE: a coarse-grained check ("am I referenced at all?") is used as a stand-in for the fine-grained check that is actually required ("does this specific counterparty have the right level of control?").

### Finding Description
Any paired correspondent (an unprivileged device that merely exchanged a pairing code with the victim) can send a `new_shared_address` hub message that is handled in `wallet.js`: [1](#0-0) 

which forwards straight into `handleNewSharedAddress`: [2](#0-1) 

The only authorization gate is `determineIfIncludesMeAndRewriteDeviceAddress`, which merely confirms that one of the addresses in the definition belongs to `my_addresses`/`shared_addresses`: [3](#0-2) 

Unlike the sibling handler `approve_new_shared_address`, which restricts the update `WHERE device_address=?` bound to the actual `from_address` of the message: [4](#0-3) 

`handleNewSharedAddress` never checks `from_address` against the signers in `body.signers`/`body.definition` at all — it accepts and stores whatever definition+signer map the sender supplies, as long as the recipient happens to be named in it.

Furthermore, `validateAddressDefinition` only validates that the oscript definition is *syntactically/semantically* legal — it does not restrict the definition to structures that actually require cooperation: [5](#0-4) 

Consequently, an attacker can craft `body.definition = ["or", [["address", VICTIM_ADDR], ["address", ATTACKER_ADDR]]]`, set `body.address` to its chash160, and supply `body.signers` mapping the victim's path to the victim's real address and the other path to an attacker-controlled `device_address`. This passes every check in `handleNewSharedAddress` and is written into the DB via `addNewSharedAddress`: [6](#0-5) 

The victim's wallet now treats this address as a legitimate "shared address" it partially controls (it is watched, appears in shared-address listings/queries, e.g. `readAllControlAddresses`, `sendToPeerAllSharedAddressesHavingUnspentOutputs`), with the attacker's device permanently registered in `shared_address_signing_paths`.

### Impact Explanation
Because the injected definition is `"or"` (or any other weight/threshold that allows unilateral control), the attacker's address alone is sufficient to spend any funds the victim later sends to, or receives at, that "shared" address — the victim's cooperation is never actually required. This is concrete unauthorized spending of funds that the victim wallet displays as jointly controlled. Additionally, because the attacker's device is now a legitimate row in `shared_address_signing_paths`, any subsequent private (indivisible/divisible) asset payment chain touching that address is automatically forwarded to the attacker in cleartext by `forwardPrivateChainsToOtherMembersOfAddresses`: [7](#0-6) 

leaking private payment amounts, blinding factors and addresses to an unauthorized party.

### Likelihood Explanation
The attack requires only a normal pairing relationship (any correspondent device) and a single crafted `new_shared_address` message — no special privileges, no proof-of-work, no need to compromise keys. The victim does not need to interact for the record to be inserted; the only remaining condition is that the victim's UI/flow subsequently treats/uses this address as a receiving or shared address (a realistic UX path since shared addresses pushed by correspondents are a supported wallet feature).

### Recommendation
In `handleNewSharedAddress`, verify that `from_address` corresponds to one of the `device_address` values in `body.signers` at a signing path that is *not* the recipient's own path, and reject definitions whose access-control structure does not require genuine multi-party cooperation (e.g., disallow single-branch `"or"` combinations mixing one of my own addresses with an externally supplied address, or require explicit user confirmation before persisting any shared address received unsolicited from a peer, mirroring the `from_address`-scoped check already used in `approvePendingSharedAddress`).

### Proof of Concept
1. Attacker pairs with victim's wallet as an ordinary correspondent device.
2. Attacker learns/derives one of the victim's addresses `VICTIM_ADDR` (any address the victim has used, e.g. from a prior payment).
3. Attacker builds `arrDefinition = ["or", [["address", VICTIM_ADDR], ["address", ATTACKER_ADDR]]]`, computes `address = chash160(arrDefinition)`.
4. Attacker sends a `new_shared_address` device message: `{address, definition: arrDefinition, signers: {"r.0": {address: VICTIM_ADDR}, "r.1": {address: ATTACKER_ADDR, device_address: ATTACKER_DEVICE}}}`.
5. Victim's `handleNewSharedAddress` accepts it (checks in lines 378-415 all pass) and stores `shared_addresses`/`shared_address_signing_paths` rows via `addNewSharedAddress`.
6. If funds are later sent to `address` (e.g. victim uses it as a receive/change address believing it needs both parties, or an application pays "shared" funds there), attacker unilaterally composes and broadcasts a spend using only `ATTACKER_ADDR`'s `"or"` branch — no victim cooperation needed. Any private-asset payment chains sent to `address` are also auto-forwarded to `ATTACKER_DEVICE` per `forwardPrivateChainsToOtherMembersOfAddresses`.

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

**File:** wallet_defined_by_addresses.js (L150-154)
```javascript
function approvePendingSharedAddress(address_definition_template_chash, from_address, address, assocDeviceAddressesByRelativeSigningPaths){
	db.query( // may update several rows if the device is referenced multiple times from the definition template
		"UPDATE pending_shared_address_signing_paths SET address=?, device_addresses_by_relative_signing_paths=?, approval_date="+db.getNow()+" \n\
		WHERE definition_template_chash=? AND device_address=?", 
		[address, JSON.stringify(assocDeviceAddressesByRelativeSigningPaths), address_definition_template_chash, from_address], 
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

**File:** wallet_defined_by_addresses.js (L518-528)
```javascript
// fix:
// 1. check that my address is referenced in the definition
function validateAddressDefinition(arrDefinition, handleResult){
	var objFakeUnit = {authors: []};
	var objFakeValidationState = {last_ball_mci: MAX_INT32, bAllowUnresolvedInnerDefinitions: true};
	Definition.validateDefinition(db, arrDefinition, objFakeUnit, objFakeValidationState, null, false, function(err){
		if (err)
			return handleResult(err);
		handleResult();
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
