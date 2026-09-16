### Title
`approvePendingSharedAddress()` finalizes and activates a multisig shared address without validating the combined definition against `Definition.validateDefinition()` - ([File: wallet_defined_by_addresses.js])

### Summary
The reported bug pattern is: a hook/callback result (`onTokenTransfer()`'s return value) is not checked before the caller proceeds as if the operation succeeded, allowing state to advance on unverified input. The analogous defect in `ocore` is in the peer-to-peer shared-address (multisig) approval flow: `approvePendingSharedAddress()` in `wallet_defined_by_addresses.js` builds the final address definition from cosigner-supplied data and immediately inserts it into `shared_addresses`, registers signing paths, and notifies all cosigners that the address is ready to use — all **without ever calling `Definition.validateDefinition()`** on the final, fully-substituted definition. [1](#0-0) 

### Finding Description
Compare the two code paths that create a shared (multisig) address in `wallet_defined_by_addresses.js`:

- `handleNewSharedAddress()` (invoked when a peer sends the `new_shared_address` device message) explicitly validates the definition via `Definition.validateAddressDefinition()` (which wraps `Definition.validateDefinition()`) **before** calling `addNewSharedAddress()`: [2](#0-1) 

- `approvePendingSharedAddress()` (invoked when a cosigner responds to `approve_new_shared_address`, handled in `wallet.js` case `"approve_new_shared_address"`) builds `arrDefinition` by substituting the cosigner-reported `address` values into the previously agreed template via `Definition.replaceInTemplate()`, computes `shared_address = objectHash.getChash160(arrDefinition)`, and directly writes it to `shared_addresses`/`shared_address_signing_paths`, then notifies all cosigners — **without any call to `Definition.validateDefinition()`** on the resulting `arrDefinition`: [3](#0-2) 

The device-message handler that drives this path performs no additional validation either — it just forwards the body fields and immediately reports success: [4](#0-3) 

The only earlier validation, `validateAddressDefinitionTemplate()`, is performed once, at template-creation time, using a single **fake placeholder address** substituted for every member's slot (`fake_address`) — it never re-validates the actual definition once real per-cosigner addresses replace the placeholders: [5](#0-4) 

`Definition.validateDefinition()` performs important protocol-level checks that the network itself will enforce later (complexity limits `MAX_COMPLEXITY`, op-count limits `MAX_OPS`, filter/field validity, structural correctness of `or`/`and`/`r of set`/`weighted and`, etc.): [6](#0-5) 

Because this check is skipped on the finalization path, the locally registered "shared address" can end up with a definition that:
1. is structurally invalid or exceeds complexity/ops limits imposed by the real network validator, or
2. contains a definition whose real per-cosigner substitutions differ meaningfully from the fake-address-only structural check that was performed on the template (e.g., malicious/duplicate address values a cosigner reports during approval), producing a combined definition that was never actually checked as a legitimate address-spending condition.

This mirrors the External Report’s root cause precisely: the caller advances to a "success" state (registers/broadcasts a fully-approved shared address, ready for use) without checking the outcome of the exact validation step (`Definition.validateDefinition`) that is used elsewhere in the same file for the equivalent operation.

### Impact Explanation
If the finalized shared-address definition is never checked against `Definition.validateDefinition()`, the wallet can register and start using (and directing peers to send funds to) a multisig address whose real, network-enforced spending definition is invalid, oversized, or otherwise semantically different from what any device actually validated. When later a payment is attempted from that address, or when a unit referencing that address definition is broadcast, the network/other nodes' independent validation (which does run `Definition.validateDefinition()` before accepting a unit into the DAG) can reject it. Funds already sent to an address whose spending definition cannot pass network validation are effectively frozen/lost. A malicious cosigner participating in the approval handshake can also supply crafted address values during the approval step, exploiting the fact that only the fake-address template shape — not the real substituted definition — was ever checked.

### Likelihood Explanation
This code path is reachable by any correspondent device (an unprivileged paired device) sending the `approve_new_shared_address` device message once a multisig address creation was initiated locally (a supported wallet UI flow). No hub/network privilege or ability to forge signatures is required — the attacker only needs to be one of the intended cosigners in an in-progress shared-address negotiation, which is a normal position for any counterparty in a multi-signature wallet setup. Because `approvePendingSharedAddress` only updates rows keyed by `(definition_template_chash, device_address)` where `device_address = from_address`, an attacking cosigner can control the `address` and `device_addresses_by_relative_signing_paths` values attributed to their own slot, letting them influence the final combined definition that skips validation.

### Recommendation
In `approvePendingSharedAddress()`, before inserting into `shared_addresses` and notifying cosigners, call `Definition.validateDefinition()` (as already done in `handleNewSharedAddress()`/`validateAddressDefinition()`) on the fully-substituted `arrDefinition`. If validation fails, abort the finalization, do not register the shared address, and surface an error to the initiating device instead of proceeding as if approval succeeded.

### Proof of Concept
1. Device A creates a shared/multisig address template involving Device A (self) and Device B (attacker), via `createNewSharedAddressByTemplate` → `sendOfferToCreateNewWallet`-style flow, storing a `pending_shared_addresses` row with `definition_template_chash`.
2. Device B (attacker, already a known cosigner in the negotiation) responds with `approve_new_shared_address`, supplying an `address` value and `device_addresses_by_relative_signing_paths` for its own slot that, once substituted into the template, produce a definition that would fail `Definition.validateDefinition()` (e.g., exceeding `MAX_COMPLEXITY`/`MAX_OPS`, or structurally malformed for the op used at that path).
3. `wallet.js`'s `"approve_new_shared_address"` handler calls `walletDefinedByAddresses.approvePendingSharedAddress(...)` and immediately calls `callbacks.ifOk()` without waiting for or checking any validation result — because none is performed. [7](#0-6) 
4. Once all cosigners have "approved" (i.e., all rows have a non-null `address`), `approvePendingSharedAddress()` computes and inserts the shared address into `shared_addresses`, registers signing paths, and notifies Device A and other cosigners that the address is ready to receive funds — with no verification the assembled definition is a valid, network-acceptable spending condition. [3](#0-2) 
5. Device A, believing the address is fully validated and operational, may direct funds to it; a subsequent attempt to spend from it can be rejected by network-level validation (which does enforce `Definition.validateDefinition()`), freezing the funds.

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

**File:** wallet_defined_by_addresses.js (L406-415)
```javascript
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

**File:** definition.js (L103-118)
```javascript
	function evaluate(arr, path, bInNegation, cb){
		complexity++;
		count_ops++;
		if (complexity > constants.MAX_COMPLEXITY)
			return cb("complexity exceeded at "+path);
		if (count_ops > constants.MAX_OPS)
			return cb("number of ops exceeded at "+path);
		if (objValidationState.max_complexity && objValidationState.complexity + complexity > objValidationState.max_complexity)
			return cb(`custom complexity limit ${objValidationState.max_complexity} exceeded at ${path}`);
		if (!isArrayOfLength(arr, 2))
			return cb("expression must be 2-element array");
		var op = arr[0];
		var args = arr[1];
		if (typeof op !== 'string')
			return cb("op is not a string");
		switch(op){
```
