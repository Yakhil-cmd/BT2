### Title
Threshold subset of a shared (multisig) address's signers can unilaterally redefine the address and permanently remove other valid cosigners - ([File: validation.js])

### Summary
Obyte multisig ("shared") addresses are defined by an `r of set` (or similar) definition that specifies which of N cosigner keys/addresses must sign to authorize spending. A shared address is normally created only after **all** member devices have explicitly approved the definition template (see `wallet_defined_by_addresses.js`). However, once created, the address's *definition* can later be replaced entirely via a single `address_definition_change` message, and that message only needs to be authorized by whichever subset of signers currently satisfies the address's existing threshold — not by all original cosigners. This lets any threshold-satisfying subset of an r-of-n multisig silently and permanently exclude the remaining cosigners from ever controlling the address again, mirroring the Hats Safe report where a threshold of signers bypasses the intended cooperative-removal process by calling a lower-level primitive directly.

### Finding Description
When a shared address is first created, all cosigners must cooperate and approve the address_definition_template before the address is usable — see `createNewSharedAddressByTemplate` and `handleNewSharedAddress`, which validate that member addresses/signers match the definition: [1](#0-0) [2](#0-1) 

This gives the impression that control of the shared address is a cooperative, unanimous-setup arrangement among the named cosigners.

However, ocore also supports changing an address's definition post-hoc via the `address_definition_change` message, composed with `composeDefinitionChangeJoint`: [3](#0-2) 

The validation of this message only checks structural correctness of the payload (that `definition_chash` is a valid address-shaped hash, and that a multi-author payload references one of the unit's authors): [4](#0-3) 

Critically, the unit that carries this `address_definition_change` message is authorized using the **current** (soon-to-be-replaced) definition of the address, evaluated in `validateAuthor`/`checkSerialAddressUse`/`validateDefinition`: [5](#0-4) [6](#0-5) 

For an `r of set` shared address (e.g. 2-of-3), this means only `r` of the `n` cosigners need to sign the unit that changes `definition_chash`. They can point `definition_chash` to any definition of their choosing (e.g. excluding the remaining `n-r` cosigners entirely, or replacing them with new keys under the majority's control). The actual new definition array does not even need to be revealed at the time of the change — only its hash — so the excluded cosigner(s) may not immediately learn that they have been cut out. Once the change is stable, `storage.readDefinitionChashByAddress`/`readDefinitionByAddress` resolve all future signature checks against the new definition, permanently locking the excluded members out: [7](#0-6) 

There is no mechanism analogous to "all original signers must approve a definition change" — the check is purely "does this unit satisfy the definition **currently** in force," which for a threshold multisig is by design satisfiable by a strict subset of the members.

### Impact Explanation
A minority-controlling but threshold-satisfying subset of cosigners of any shared/multisig address (used for treasuries, escrows, arbiter contracts, DAOs, etc. built with `wallet_defined_by_addresses.js`) can unilaterally and permanently remove other legitimate cosigners' control over the address, and/or redirect control of remaining/future funds to themselves, without the consent, involvement, or prior knowledge of the removed cosigners. This is a fund-freezing/fund-theft-enabling governance bypass: excluded signers permanently lose their ability to co-authorize spends, and the majority can redefine control to concentrate all authority (or add new colluding parties) in themselves.

### Likelihood Explanation
Any application relying on ocore's shared/multisig addresses for governance guarantees (e.g., "spending/administration requires r of n cosigners, and no smaller subset can alter membership") is affected. All that is required is for `r` signers among an `n`-member shared address to cooperate to post one `address_definition_change` unit — a standard, always-available operation with no additional safeguard, making this readily reachable by any subset of colluding signers who together satisfy the address's existing threshold.

### Recommendation
Require an `address_definition_change` to be revealed and re-validated so that dependent logic (or optionally the protocol) can enforce policies such as: a definition change must preserve a minimum required overlap with the previous member set unless explicitly authorized by all members (e.g., require signatures satisfying the *union* / all leaf addresses of the old definition, not merely its threshold), or provide an explicit "unanimous consent" opcode/flag for shared multisig addresses created through the shared-address workflow so that wallet software can warn/require full-member sign-off before applying membership-changing definition updates.

### Proof of Concept
1. Three cosigners A, B, C create a shared address with definition `["r of set", {required: 2, set: [sig(A), sig(B), sig(C)]}]` via `wallet_defined_by_addresses.js`'s cooperative creation flow.
2. Funds accumulate at the shared address, controlled (per user expectation) by any 2-of-3 agreement.
3. A and B, without C's knowledge, compose a unit containing an `address_definition_change` message via `composeDefinitionChangeJoint` (`composer.js:85-87`), setting `definition_chash` to the hash of a new definition `["sig", {pubkey: A}]` (or `["r of set", {required:1, set:[sig(A), sig(B)]}]`).
4. This unit is signed only by A and B, satisfying the current 2-of-3 definition; `validation.js` (`validateInlinePayload`, `validateAuthor`/`validateDefinition`) accepts it since it only checks structural validity of the payload and that the *current* definition's authentication requirement is met.
5. Once stable, `storage.readDefinitionByAddress`/`readDefinitionChashByAddress` resolve the address strictly to the new definition; C is permanently excluded from any future authorization over the shared address, despite never having consented and despite being a legitimate original cosigner.

### Citations

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

**File:** wallet_defined_by_addresses.js (L481-516)
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
	
	var params = {};
	// to fill the template for validation, assign my device address (without leading 0) to all member devices 
	// (we need just any valid address with a definition)
	var fake_address = device.getMyDeviceAddress().substr(1);
	arrDeviceAddresses.forEach(function(device_address){
		params['address@'+device_address] = fake_address;
	});
	try{
		var arrFakeDefinition = Definition.replaceInTemplate(arrDefinitionTemplate, params);
	}
	catch(e){
		return handleResult(e.toString());
	}
	var objFakeUnit = {authors: [{address: fake_address, definition: ["sig", {pubkey: device.getMyDevicePubKey()}]}]};
	var objFakeValidationState = {last_ball_mci: MAX_INT32};
	Definition.validateDefinition(db, arrFakeDefinition, objFakeUnit, objFakeValidationState, null, false, function(err){
		if (err)
			return handleResult(err);
		handleResult(null, assocMemberDeviceAddressesBySigningPaths);
	});
}
```

**File:** composer.js (L85-87)
```javascript
function composeDefinitionChangeJoint(from_address, definition_chash, signer, callbacks){
	composeContentJoint(from_address, "address_definition_change", {definition_chash: definition_chash}, signer, callbacks);
}
```

**File:** validation.js (L1304-1343)
```javascript
	function checkSerialAddressUse(){
		var next = (objValidationState.last_ball_mci >= constants.pemCurvesFixMci || !objValidationState.hasBall && storage.getMinRetrievableMci() >= constants.pemCurvesFixMci) ? validateDefinition : checkNoPendingChangeOfDefinitionChash;
		findConflictingUnits(function(arrConflictingUnitProps){
			if (arrConflictingUnitProps.length === 0){ // no conflicting units
				// we can have 2 authors. If the 1st author gave bad sequence but the 2nd is good then don't overwrite
				objValidationState.sequence = objValidationState.sequence || 'good';
				return next();
			}
			var arrConflictingUnits = arrConflictingUnitProps.map(function(objConflictingUnitProps){ return objConflictingUnitProps.unit; });
			breadcrumbs.add("========== found conflicting units "+arrConflictingUnits+" =========");
			breadcrumbs.add("========== will accept a conflicting unit "+objUnit.unit+" =========");
			objValidationState.arrAddressesWithForkedPath.push(objAuthor.address);
			objValidationState.arrConflictingUnits = (objValidationState.arrConflictingUnits || []).concat(arrConflictingUnits);
			bNonserial = true;
			var arrUnstableConflictingUnitProps = arrConflictingUnitProps.filter(function(objConflictingUnitProps){
				return (objConflictingUnitProps.is_stable === 0);
			});
			// findConflictingUnits() already excludes final-bad rows, so any stable row left here is a real, good competitor
			var bConflictsWithStableUnits = arrConflictingUnitProps.some(function(objConflictingUnitProps){
				return (objConflictingUnitProps.is_stable === 1);
			});
			if (objValidationState.sequence !== 'final-bad') // if it were already final-bad because of 1st author, it can't become temp-bad due to 2nd author
				objValidationState.sequence = bConflictsWithStableUnits ? 'final-bad' : 'temp-bad';
			var arrUnstableConflictingUnits = arrUnstableConflictingUnitProps.map(function(objConflictingUnitProps){ return objConflictingUnitProps.unit; });
			// if we are (or already became, due to another author) final-bad, we are not a living competitor for this address either,
			// so there is no need to punish other pending units - they'll correctly resolve to 'good' on their own once stable
			if (objValidationState.sequence === 'final-bad')
				return next();
			if (arrUnstableConflictingUnits.length === 0)
				return next();
			conn.query("SELECT unit FROM units WHERE unit IN(?) AND +sequence='good'",[arrUnstableConflictingUnits],function(rows){
				if (rows.length > 0)
					objValidationState.arrUnitsGettingBadSequence = (objValidationState.arrUnitsGettingBadSequence || []).concat(rows.map(function(row){return row.unit}));
				// we don't modify the db during validation, schedule the update for the write
				objValidationState.arrAdditionalQueries.push(
				{sql: "UPDATE units SET sequence='temp-bad' WHERE unit IN(?) AND +sequence='good'", params: [arrUnstableConflictingUnits]});
				next();
				});
		});
	}
```

**File:** validation.js (L1464-1484)
```javascript
	function validateDefinition(){
		if (!("definition" in objAuthor))
			return callback();
		// the rest assumes that the definition is explicitly defined
		var arrAddressDefinition = objAuthor.definition;
		storage.readDefinitionByAddress(conn, objAuthor.address, objValidationState.last_ball_mci, {
			ifDefinitionNotFound: function(definition_chash){ // first use of the definition_chash (in particular, of the address, when definition_chash=address)
				try {
					if (objectHash.getChash160(arrAddressDefinition) !== definition_chash)
						return callback("wrong definition: " + objectHash.getChash160(arrAddressDefinition) + "!==" + definition_chash);
				}
				catch (e) {
					return callback("definition hash failed: " + e.toString());
				}
				callback();
			},
			ifFound: function(arrAddressDefinition2){ // arrAddressDefinition2 can be different
				handleDuplicateAddressDefinition(arrAddressDefinition2);
			}
		});
	}
```

**File:** validation.js (L1719-1746)
```javascript
		case "address_definition_change":
			if (!isNonemptyObject(payload))
				return callback("payload must be a non empty object");
			if (hasFieldsExcept(payload, ["definition_chash", "address"]))
				return callback("unknown fields in address_definition_change");
			var arrAuthorAddresses = objUnit.authors.map(function(author) { return author.address; } );
			var address;
			if (objUnit.authors.length > 1){
				if (!isValidAddress(payload.address))
					return callback("when multi-authored, must indicate address");
				if (arrAuthorAddresses.indexOf(payload.address) === -1)
					return callback("foreign address");
				address = payload.address;
			}
			else{
				if ('address' in payload)
					return callback("when single-authored, must not indicate address");
				address = arrAuthorAddresses[0];
			}
			if (!objValidationState.arrDefinitionChangeFlags)
				objValidationState.arrDefinitionChangeFlags = {};
			if (objValidationState.arrDefinitionChangeFlags[address])
				return callback("can be only one definition change per address");
			objValidationState.arrDefinitionChangeFlags[address] = true;
			if (!isValidAddress(payload.definition_chash))
				return callback("bad new definition_chash");
			return callback();

```

**File:** storage.js (L754-768)
```javascript
function readDefinitionChashByAddress(conn, address, max_mci, handle){
	if (!handle)
		return new Promise(resolve => readDefinitionChashByAddress(conn, address, max_mci, resolve));
	if (max_mci == null || max_mci == undefined)
		max_mci = MAX_INT32;
	// try to find last definition change, otherwise definition_chash=address
	conn.query(
		"SELECT definition_chash FROM address_definition_changes CROSS JOIN units USING(unit) \n\
		WHERE address=? AND is_stable=1 AND sequence='good' AND main_chain_index<=? ORDER BY main_chain_index DESC, level DESC LIMIT 1", 
		[address, max_mci], 
		function(rows){
			var definition_chash = (rows.length > 0) ? rows[0].definition_chash : address;
			handle(definition_chash);
	});
}
```
