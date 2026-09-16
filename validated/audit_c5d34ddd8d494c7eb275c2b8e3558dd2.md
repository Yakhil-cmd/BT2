### Title
Missing Sender-Authorization Check in `handleNewSharedAddress` Allows Unauthorized Injection of Malicious Shared/Multisig Address Definitions - (File: `wallet_defined_by_addresses.js`)

### Summary
The Capgo advisory describes a case where a security control (mandatory 2FA) is enforced only at the "front door" (UI) while the backend API that actually performs the privileged action never re-checks it, allowing any authenticated-but-not-fully-verified actor to bypass the control. The analogous pattern in `ocore` is in the device-message handler for shared (multisig) address creation: `handleNewSharedAddress` in [1](#0-0)  validates the internal *consistency* of a proposed shared-address definition (hash matches, signer addresses match paths) but never verifies that the device sending the `"new_shared_address"` message is actually authorized/expected to propose that definition for the local user. Authorization is only implicit in the UI flow (`create_new_shared_address` → user confirmation dialog → `approve_new_shared_address`), but the `new_shared_address` case in [2](#0-1)  accepts and silently commits shared-address definitions from **any paired correspondent**, without confirming the local peer actually agreed to join this multisig group.

### Finding Description
The wallet-to-wallet device protocol has two independent paths that lead to writing an entry into the `shared_addresses` table:
1. The "happy path" (UI-gated): `create_new_shared_address` → user reviews and calls `approve_new_shared_address` → after all cosigners approve, `approvePendingSharedAddress` in [3](#0-2)  inserts the shared address.
2. The direct path: any correspondent device can send a `"new_shared_address"` message directly, which is routed straight to `handleNewSharedAddress` in [2](#0-1)  and [1](#0-0) , bypassing the confirmation-dialog / approval workflow entirely.

`handleNewSharedAddress` only checks:
- the definition's c-hash matches the claimed address (line 384-390),
- each `signers` path's address is well-formed (line 391-395),
- signer addresses match the `["address", ...]` leaves extracted from the definition via `extractAddressPathsFromDefinition` (line 396-405),
- that the local device is a member of the definition, via `determineIfIncludesMeAndRewriteDeviceAddress` in [4](#0-3) , which only requires that *some* address in the definition be one of the caller's own `my_addresses`/`shared_addresses` — it does not check that the sending device is a legitimate participant of that address,
- the definition passes generic oscript definition validation via `validateAddressDefinition`.

Crucially, there is **no check anywhere in this call chain that ties `from_address` (the device that sent the message) to the shared address being proposed** the way the `approve_new_shared_address` / cosigner-approval flow does. Since the victim's own on-chain address is public information (visible from any transaction with them), any paired correspondent can craft a definition like `["or", [["address", VICTIM_ADDRESS], ["address", ATTACKER_ADDRESS]]]` (or a more deceptive nested structure that a naive UI might render as "protected"/"joint") and send it via `"new_shared_address"`. Because `determineIfIncludesMeAndRewriteDeviceAddress` only asks "is one of the addresses in this definition mine?" (it is — the victim's own address is present), the record is silently accepted and stored into `shared_addresses` with no user confirmation, and future funds sent to this new derived "shared address" are then handled by the wallet as if it were a legitimately negotiated joint address (see `readFundedAddresses`, `sendMultiPayment`, and address-fund tracking logic in [5](#0-4) ).

The `sign`-request path also reflects the same gap: the code at [6](#0-5)  explicitly comments out (disables) the very authorization check ("sender is cosigner of this address") that would have prevented a non-cosigner device from requesting/soliciting a signature for the shared address, relying instead on the user's visual confirmation dialog — exactly the "enforced at UI, not at backend" pattern from the CVE.

### Impact Explanation
An attacker who is merely a paired correspondent (any user can pair with any other via a pairing code/QR — a low-privilege, easily obtained relationship) can inject an attacker-controlled "shared address" definition into a victim's wallet database that:
- appears to the victim (via wallet UI reading `shared_addresses`) as a legitimate multisig/joint address involving the victim's own funds,
- may actually be spendable unilaterally by the attacker (e.g., via `"or"` logic instead of `"and"`), enabling **unauthorized diversion of funds** the victim believes are protected by co-signing,
- can also be leveraged to solicit unnecessary signing confirmations or corrupt local address bookkeeping used by `sendMultiPayment`/`readFundedAddresses`, increasing risk of the victim authorizing loss of funds to a shared address they never agreed to create.

This satisfies "concrete unauthorized spending" and "AA/definition fund loss" criteria, reachable purely from a paired-device message (an entry point available to any unprivileged correspondent, analogous to the "authenticated-but-lower-privilege" attacker in the CVE).

### Likelihood Explanation
Medium: exploitation requires the attacker to be a paired correspondent of the victim (achieved via a normal pairing exchange, which is a low-friction and common wallet interaction, not requiring elevated trust) and to know the victim's on-chain address (frequently public through any prior transaction). No cryptographic secret or private key of the victim is needed — only a `"new_shared_address"` device message crafted with a self-consistent definition referencing the victim's real address. The main mitigating factor is that most wallet UIs are expected to prominently display/ask about new shared addresses to the user before use, but the vulnerability is that the **backend accepts and stores the record regardless of any user action**, matching the "check enforced at UI only" bug class from the reference advisory.

### Recommendation
- In `handleNewSharedAddress` (`wallet_defined_by_addresses.js`), require and verify that `from_address` corresponds to a device that is actually referenced as a signer/device for one of the addresses in the proposed definition (i.e., cross-check `from_address` against `assocDefinitionAddresses`/`body.signers` device mappings) before persisting the shared address, rather than accepting any correspondent's proposal outright.
- Reinstate (or replace with an equivalent mandatory check) the currently commented-out cosigner verification in the `"sign"` message handler in `wallet.js` (lines 335-338) so that only devices that are actually known cosigners of the target address can trigger a signing request/confirmation flow.
- Require an explicit, server/backend-verifiable acknowledgment/approval record (analogous to `approvePendingSharedAddress`'s multi-party approval bookkeeping) before any `shared_addresses` row is written via the direct `new_shared_address` message path, so that the same authorization guarantees apply regardless of which code path (UI-approved vs. direct) is used.

### Proof of Concept
1. Attacker device pairs with Victim device (normal pairing flow via `device.handlePairingMessage`).
2. Attacker learns Victim's public on-chain address `V` (e.g., from a public unit/transaction).
3. Attacker crafts `arrDefinition = ["or", [["address", V], ["address", A]]]` where `A` is an address attacker fully controls, computes `address = objectHash.getChash160(arrDefinition)`.
4. Attacker sends a `"new_shared_address"` device message: `{address, definition: arrDefinition, signers: {"r.0": {address: V}, "r.1": {address: A}}}`.
5. Victim's `handleNewSharedAddress` (`wallet_defined_by_addresses.js:377-415`) validates c-hash and structural consistency (all pass), calls `determineIfIncludesMeAndRewriteDeviceAddress` (passes, since `V` is one of Victim's `my_addresses`), and calls `addNewSharedAddress`, silently inserting the new shared address into Victim's `shared_addresses` table — with no confirmation dialog, since this path bypasses `create_new_shared_address`/`approve_new_shared_address` entirely.
6. If Victim's UI subsequently treats this address as a legitimate joint/protected address (e.g., displays it or funds get routed to it), the attacker can spend independently via the `"or"` branch, resulting in unauthorized loss of Victim's funds.

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

**File:** wallet.js (L332-339)
```javascript
				findAddress(body.address, body.signing_path, {
					ifError: callbacks.ifError,
					ifLocal: function(objAddress){
						// the commented check would make multilateral signing impossible
						//db.query("SELECT 1 FROM extended_pubkeys WHERE wallet=? AND device_address=?", [row.wallet, from_address], function(sender_rows){
						//    if (sender_rows.length !== 1)
						//        return callbacks.ifError("sender is not cosigner of this address");
							callbacks.ifOk();
```

**File:** wallet.js (L1795-1858)
```javascript
function readAssetProps(asset, handleResult){
	if (!asset)
		return handleResult(null, {fixed_denominations: false, cap: constants.TOTAL_WHITEBYTES, issued_by_definer_only: true});
	storage.readAsset(db, asset, null, handleResult);
}

function readFundedAddresses(asset, wallet, estimated_amount, spend_unconfirmed, handleFundedAddresses){
	var walletIsAddresses = ValidationUtils.isNonemptyArray(wallet);
	if (walletIsAddresses)
		return composer.readSortedFundedAddresses(asset, wallet, estimated_amount, spend_unconfirmed, handleFundedAddresses);
	if (estimated_amount && typeof estimated_amount !== 'number')
		throw Error('invalid estimated amount: '+estimated_amount);
	// addresses closest to estimated amount come first
	var order_by = estimated_amount ? "(SUM(CAST(amount AS DOUBLE))>"+estimated_amount+") DESC, ABS(SUM(CAST(amount AS DOUBLE))-"+estimated_amount+") ASC" : "total DESC";
	readAssetProps(asset, function (err, objAsset) {
		if (err) {
			console.log(err);
			return handleFundedAddresses([]);
		}
		var limit = objAsset.fixed_denominations ? "" : " LIMIT " + constants.MAX_AUTHORS_PER_UNIT;
		db.query(
			"SELECT * FROM ( \n\
				SELECT address, SUM(CAST(amount AS DOUBLE)) AS total \n\
				FROM my_addresses \n\
				CROSS JOIN outputs USING(address) \n\
				CROSS JOIN units USING(unit) \n\
				WHERE wallet=? "+inputs.getConfirmationConditionSql(spend_unconfirmed)+" AND sequence='good' \n\
					AND is_spent=0 AND "+(asset ? "asset=?" : "asset IS NULL")+" \n\
				GROUP BY address ORDER BY "+order_by + limit + " \n\
			) AS t \n\
			WHERE NOT EXISTS ( \n\
				SELECT * FROM units CROSS JOIN unit_authors USING(unit) \n\
				WHERE is_stable=0 AND unit_authors.address=t.address AND definition_chash IS NOT NULL AND definition_chash != unit_authors.address \n\
			)",
			asset ? [wallet, asset] : [wallet],
			function(rows){
				if (objAsset.fixed_denominations)
					estimated_amount = 0; // don't shorten the list of addresses, indivisible_asset.js will do it later according to denominations
				if (!objAsset.cap){ // uncapped asset: can be issued from definer_address or from any address
					var and_address = objAsset.issued_by_definer_only ? " AND address="+db.escape(objAsset.definer_address) : '';
					db.query("SELECT address FROM my_addresses WHERE wallet=? "+and_address+" LIMIT 1", [wallet], function(issuer_rows){
						issuer_rows.forEach(issuer_row => {
							issuer_row.total = Infinity;
						});
						var arrNonIssuerAddresses = rows.map(row => row.address);
						issuer_rows = issuer_rows.filter(issuer_row => arrNonIssuerAddresses.indexOf(issuer_row.address) === -1);
						rows = rows.concat(issuer_rows);
						handleFundedAddresses(composer.filterMostFundedAddresses(rows, estimated_amount));
					});
					return;
				}
				handleFundedAddresses(composer.filterMostFundedAddresses(rows, estimated_amount));
			}
		);
			/*if (arrFundedAddresses.length === 0)
				return handleFundedAddresses([]);
			if (!asset)
				return handleFundedAddresses(arrFundedAddresses);
			readFundedAddresses(null, wallet, function(arrBytesFundedAddresses){
				handleFundedAddresses(_.union(arrFundedAddresses, arrBytesFundedAddresses));
			});*/
	});
}

```
