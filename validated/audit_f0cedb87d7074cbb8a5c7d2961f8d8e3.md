### Title
Shared-address approval path stores a computed shared-address definition without validating it, unlike the sibling code path - (File: wallet_defined_by_addresses.js)

### Summary
`approvePendingSharedAddress()` in `wallet_defined_by_addresses.js` derives a final address definition from a stored template plus attacker-influenced per-device approval data, computes its c-hash, and inserts it directly into `shared_addresses` (making it a live, watched, spendable wallet address) — all without ever calling `Definition.validateDefinition()` on the resulting definition. This is the same bug class as the reported `fundIntent()` issue: a hash/derived object is accepted and persisted as authoritative without validating the underlying components it is supposed to represent, while a parallel, better-guarded code path (`handleNewSharedAddress()`) explicitly performs that validation before doing the same insert.

### Finding Description
Two independent paths in `wallet_defined_by_addresses.js` create a `shared_addresses` row (the local wallet's notion of a spendable multi-sig/shared address with signing paths):

1. `handleNewSharedAddress()` (device message `new_shared_address`): before inserting into `shared_addresses`, it checks the definition's c-hash matches the claimed address, checks each signer path against `extractAddressPathsFromDefinition`, and crucially calls `validateAddressDefinition(body.definition, cb)` before calling `addNewSharedAddress()`. [1](#0-0) 

2. `approvePendingSharedAddress()` (device message `approve_new_shared_address`, invoked from `wallet.js` for the "approve_new_shared_address" case): after collecting per-device approvals, it fills the stored `definition_template` with the approved `params` via `Definition.replaceInTemplate`, computes `shared_address = objectHash.getChash160(arrDefinition)`, and directly inserts the resulting definition into `shared_addresses` and `shared_address_signing_paths` — with no call to `Definition.validateDefinition()` (or any other structural/complexity/authentifier validation) on the final, real definition. [2](#0-1) [3](#0-2) 

The only prior validation of the template happened earlier in `validateAddressDefinitionTemplate()`, but that validation is performed on a *fake* filled-in definition where **every** member device address is substituted with the same placeholder ("fake_address") and a trivial `["sig", ...]` definition, purely to sanity-check the template shape: [4](#0-3) 

That fake-validation does not — and cannot — validate the actual final definition that gets built with the real, distinct per-signer addresses supplied during approval (`params['address@'+row.device_address] = row.address`), because definition validation in `Definition.validateDefinition` performs structural checks (complexity limits, duplicate/ambiguous branches, correct operator arities, oracle/attestor formatting, etc.) that depend on the real substituted values, not on a fake uniform placeholder. `approvePendingSharedAddress` never re-runs that check on the real definition before persisting it as an actively watched, funds-holding address.

This mirrors the reported bug precisely: `fundIntent()` trusted a caller-supplied `routeHash` without validating the route it was derived from, while a sibling function (`publishAndFund`) did perform the check via `_validateSourceChain`. Here, `approvePendingSharedAddress()` trusts a locally re-derived definition without validating it, while the sibling function `handleNewSharedAddress()` does perform that validation.

### Impact Explanation
`shared_addresses` entries are treated by the wallet as legitimate, controllable multi-signature addresses: they get watched for incoming funds, and the stored `definition` is later used by the composer/signing logic to build transactions spending from that address. If the final definition assembled from real per-device addresses is malformed or structurally invalid (e.g., a signing path that produces an ambiguous, unauthenticatable, or over-complex definition, or one where the intended "and"/"or" access-control invariants established at template-creation time no longer hold once concrete addresses are substituted), the wallet will persist and use it as if it were a properly validated multisig address. This can result in:
- Funds sent to a shared address whose real definition never passes `validateDefinition` (e.g., exceeds complexity limits or has malformed operator use), leaving that address's on-DAG spending units unable to validate — funds become effectively frozen/locked, unable to be spent, mirroring the "locked funds" impact called out in the report.
- Silent divergence between what the offering device intended (validated on a fake definition) and what actually gets stored/used, so cosigners could be misled about the security guarantees of the address they are approving into, similar to solvers being misled by unfunded/invalid routes in the original report.

### Likelihood Explanation
Medium: this path is reachable from a paired device counterparty by sending a "approve_new_shared_address" message (handled unconditionally by `wallet.js`, which only checks the shape/type of the fields, not the resulting definition) that references a previously proposed `pending_shared_addresses` template. A malicious or buggy counterparty controls the `address` and `device_addresses_by_relative_signing_paths` values it approves with, directly influencing the real substituted definition that later bypasses validation.

### Recommendation
In `approvePendingSharedAddress()`, before inserting into `shared_addresses`/`shared_address_signing_paths`, call `Definition.validateDefinition()` (or reuse `validateAddressDefinition()`, as `handleNewSharedAddress()` does) on the real, fully-substituted `arrDefinition`, and abort/reject the shared address creation on failure, notifying the rejecting device instead of silently persisting an unvalidated definition.

### Proof of Concept
1. Device A proposes a shared-address template via `create_new_shared_address`; the template is validated only against a fake, uniform placeholder address (`validateAddressDefinitionTemplate`), not against real member addresses. [4](#0-3) 
2. Cosigning devices respond via `approve_new_shared_address`, each supplying `address` and `device_addresses_by_relative_signing_paths` under their control. [3](#0-2) 
3. Once all approvals are collected, `approvePendingSharedAddress()` builds the real definition with `Definition.replaceInTemplate` using the real approved addresses and immediately inserts it into `shared_addresses` without any structural validation of the final definition. [5](#0-4) 
4. Because the real definition was never checked with `Definition.validateDefinition`, an invalid or unexpectedly-structured definition (arising from how concrete addresses interact within the template — e.g. duplicate leaves, exceeded complexity, or malformed sub-definitions) is persisted and used as a live wallet address, whereas the sibling `handleNewSharedAddress()` path would have rejected the same malformed definition via its explicit `validateAddressDefinition` call. [6](#0-5)

### Citations

**File:** wallet_defined_by_addresses.js (L150-227)
```javascript
function approvePendingSharedAddress(address_definition_template_chash, from_address, address, assocDeviceAddressesByRelativeSigningPaths){
	db.query( // may update several rows if the device is referenced multiple times from the definition template
		"UPDATE pending_shared_address_signing_paths SET address=?, device_addresses_by_relative_signing_paths=?, approval_date="+db.getNow()+" \n\
		WHERE definition_template_chash=? AND device_address=?", 
		[address, JSON.stringify(assocDeviceAddressesByRelativeSigningPaths), address_definition_template_chash, from_address], 
		function(){
			// check if this is the last required approval
			db.query(
				"SELECT device_address, signing_path, address, device_addresses_by_relative_signing_paths \n\
				FROM pending_shared_address_signing_paths \n\
				WHERE definition_template_chash=?",
				[address_definition_template_chash],
				function(rows){
					if (rows.length === 0) // another device rejected the address at the same time
						return;
					if (rows.some(function(row){ return !row.address; })) // some devices haven't approved yet
						return;
					// all approvals received
					var params = {};
					rows.forEach(function(row){ // the same device_address can be mentioned in several rows
						params['address@'+row.device_address] = row.address;
					});
					db.query(
						"SELECT definition_template FROM pending_shared_addresses WHERE definition_template_chash=?", 
						[address_definition_template_chash],
						function(templ_rows){
							if (templ_rows.length !== 1)
								throw Error("template not found");
							var arrAddressDefinitionTemplate = JSON.parse(templ_rows[0].definition_template);
							var arrDefinition = Definition.replaceInTemplate(arrAddressDefinitionTemplate, params);
							var shared_address = objectHash.getChash160(arrDefinition);
							db.query(
								"INSERT INTO shared_addresses (shared_address, definition) VALUES (?,?)", 
								[shared_address, JSON.stringify(arrDefinition)], 
								function(){
									var arrQueries = [];
									var assocSignersByPath = {};
									rows.forEach(function(row){
										var assocDeviceAddressesByRelativeSigningPaths = JSON.parse(row.device_addresses_by_relative_signing_paths);
										for (var member_signing_path in assocDeviceAddressesByRelativeSigningPaths){
											var signing_device_address = assocDeviceAddressesByRelativeSigningPaths[member_signing_path];
											// this is full signing path, from root of shared address (not from root of member address)
											var full_signing_path = row.signing_path + member_signing_path.substring(1);
											// note that we are inserting row.device_address (the device we requested approval from), not signing_device_address 
											// (the actual signer), because signing_device_address might not be our correspondent. When we need to sign, we'll
											// send unsigned unit to row.device_address and it'll forward the request to signing_device_address (subject to 
											// row.device_address being online)
											db.addQuery(arrQueries, 
												"INSERT INTO shared_address_signing_paths \n\
												(shared_address, address, signing_path, member_signing_path, device_address) VALUES(?,?,?,?,?)", 
												[shared_address, row.address, full_signing_path, member_signing_path, row.device_address]);
											assocSignersByPath[full_signing_path] = {
												device_address: row.device_address, 
												address: row.address, 
												member_signing_path: member_signing_path
											};
										}
									});
									async.series(arrQueries, function(){
										deletePendingSharedAddress(address_definition_template_chash);
										// notify all other member-devices about the new shared address they are a part of
										rows.forEach(function(row){
											if (row.device_address !== device.getMyDeviceAddress())
												sendNewSharedAddress(row.device_address, shared_address, arrDefinition, assocSignersByPath);
										});
										forwardNewSharedAddressToCosignersOfMyMemberAddresses(shared_address, arrDefinition, assocSignersByPath);
										if (conf.bLight)
											network.addLightWatchedAddress(shared_address);
									});
								}
							);
						}
					);
				}
			);
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

**File:** wallet.js (L214-226)
```javascript
			case "approve_new_shared_address":
				// {address_definition_template_chash: "BASE32", address: "BASE32", device_addresses_by_relative_signing_paths: {...}}
				if (!ValidationUtils.isValidAddress(body.address_definition_template_chash))
					return callbacks.ifError("invalid addr def c-hash");
				if (!ValidationUtils.isValidAddress(body.address))
					return callbacks.ifError("invalid address");
				if (typeof body.device_addresses_by_relative_signing_paths !== "object" 
						|| Object.keys(body.device_addresses_by_relative_signing_paths).length === 0)
					return callbacks.ifError("invalid device_addresses_by_relative_signing_paths");
				walletDefinedByAddresses.approvePendingSharedAddress(body.address_definition_template_chash, from_address, 
					body.address, body.device_addresses_by_relative_signing_paths);
				callbacks.ifOk();
				break;
```
