## Analog Found

### Title
Single-Step, Irreversible Attestor-List Replacement for `spender_attested` Assets Can Permanently Freeze User Funds - (File: validation.js, storage.js, writer.js)

### Summary
The Y2K report flags that `TimeLock.changeOwner` (and similarly `CarouselFactory`'s fee-changing configuration) is a **one-step** privileged operation with no confirmation/undo path, so a mistaken or malicious update can permanently lock legitimate parties out. Ocore has a directly analogous pattern: the asset "attestor list" that gates spending of a `spender_attested` asset is updated by the asset definer in a **single unit**, with no staging/confirmation step, and each new `asset_attestors` message **completely replaces** the previous trusted list rather than being additive.

### Finding Description
When an asset is defined with `spender_attested: true`, only addresses on the asset's current attestor list may issue/hold/spend that asset [1](#0-0) . The definer (a single privileged address for that asset) can update this list at any time by posting an `asset_attestors` message; validation enforces only that the sender is the definer, with no two-step or delayed-activation mechanism: [2](#0-1) 

The persisted attestor list for the asset is derived by taking the single **latest** `asset_attestors` (or original `asset`) unit and using **only its attestors**, not a union of all historically-posted lists: [3](#0-2) 

The write path shows the same "one message, immediate full replacement" semantics — each `asset_attestors` message inserts a fresh attestor set for that `(unit, message_index)` and the latest one wins on read: [4](#0-3) 

Composing such an update is a single call with no staging step, analogous to `TimeLock.changeOwner` being one function call instead of an `initiate` + `confirm` pair: [5](#0-4) 

Because there is no "propose new attestor list" step that requires a second confirmation (e.g. from the new attestors, or a timelock delay before the new list takes effect), a single mistaken or compromised-key `asset_attestors` unit from the definer instantly and irreversibly (until another correct update is posted and stabilizes) removes the addresses previously trusted to hold/spend the asset.

### Impact Explanation
If the definer posts a bad attestor list (typo'd address, wrong address format issue, or key compromise), every legitimate holder of that `spender_attested` asset who was relying on the old attestor set is immediately unable to spend the asset once the malformed update stabilizes: `validatePayment` will reject any transfer/issue where none of the authors are attested [1](#0-0) . This is a fund-freezing outcome — users' asset balances become unspendable — that persists until the definer notices and corrects it with another single-step, unverified update. There is no built-in delay, confirmation, or rollback mechanism, mirroring exactly the "Loss of Access" impact called out in the original TimeLock report.

### Likelihood Explanation
The definer address is exactly the party trusted to manage the attestor list, same as the "owner" role in the TimeLock report. Likelihood is Medium: it requires either an operational mistake by the definer (fat-finger address, wrong pubkey copy-paste) or compromise of the definer's private key — the same two triggers the original report describes for the owner-change flow. No collusion with other network participants is required; a single unit from the already-privileged definer is sufficient to trigger the freeze.

### Recommendation
Introduce a two-step process for `asset_attestors` updates analogous to the recommended TimeLock fix:
1. `propose_asset_attestors` message that records a pending attestor list with an activation delay (e.g. N main-chain indices) before it becomes effective, instead of taking effect on stabilization of a single message.
2. Require either a second confirmation from the definer after the delay, or make the list additive-with-explicit-removal (separate `add_attestors`/`remove_attestors` ops) so a single malformed message cannot wipe the entire trusted set at once.
3. Alternatively, at minimum reject `asset_attestors` updates that would result in an attestor list disjoint from all currently-attested holders' addresses without an explicit "migration" flag, to prevent silent, total freezing.

### Proof of Concept
1. Definer `D` issues asset `A` with `spender_attested: true` and initial attestors `[X, Y]` [6](#0-5) .
2. Users `U1`, `U2` are attested by `X`/`Y` and hold balances of asset `A`.
3. `D` posts a single `asset_attestors` message intending attestors `[X, Z]` but mistypes `Z` (or `D`'s key is used by an attacker) resulting in `[Q]`, an address unrelated to any real attestor [5](#0-4) .
4. Once this unit stabilizes, `readAsset` resolves the attestor list to `[Q]` only, since only the latest unit's list is used [3](#0-2) .
5. Any subsequent payment message for asset `A` from `U1`/`U2` fails validation with "none of the authors is attested" / "issuer is not attested" [1](#0-0) , freezing all previously-valid holders' funds with no automatic recovery — exactly one mistaken, single-step transaction away, with no two-step safeguard.

### Citations

**File:** validation.js (L2115-2122)
```javascript
		if (objAsset.spender_attested){
			if (conf.bLight && objAsset.is_private) // in light clients, we don't have the attestation data but if the asset is public, we trust witnesses to have checked attestations
				return callback("being light, I can't check attestations for private assets"); // TODO: request history
			if (objAsset.arrAttestedAddresses.length === 0)
				return callback("none of the authors is attested");
			if (bIssue && objAsset.arrAttestedAddresses.indexOf(issuer_address) === -1)
				return callback("issuer is not attested");
		}
```

**File:** validation.js (L2829-2848)
```javascript
function validateAttestorListUpdate(conn, payload, objUnit, objValidationState, callback){
	if (objUnit.authors.length !== 1)
		return callback("attestor list must be single-authored");
	if (!isNonemptyObject(payload))
		return callback("attestor update must be a non-empty object");
	if (hasFieldsExcept(payload, ['asset', 'attestors']))
		return callback("foreign fields in attestor list update");
	storage.readAsset(conn, payload.asset, objValidationState.last_ball_mci, false, function(err, objAsset){
		if (err)
			return callback(err);
		if (!objAsset.spender_attested)
			return callback("this asset does not require attestors");
		if (objUnit.authors[0].address !== objAsset.definer_address)
			return callback("attestor list can be edited only by definer");
		err = checkAttestorList(payload.attestors);
		if (err)
			return callback(err);
		callback();
	});
}
```

**File:** storage.js (L1917-1946)
```javascript
		function addAttestorsIfNecessary(byAA = false){
			if (!objAsset.spender_attested)
				return handleAsset(null, objAsset);

			// find latest list of attestors
			const before_last_ball_cond = byAA ? "" : `AND main_chain_index<=${+last_ball_mci} AND is_stable=1`;
			conn.query(
				"SELECT unit FROM asset_attestors CROSS JOIN units USING(unit) \n\
				WHERE asset=? " + before_last_ball_cond + " AND sequence='good' ORDER BY "+ (conf.bLight ? "units.rowid" : "level") + " DESC LIMIT 1",
				[asset],
				function (latest_rows) {
					if (latest_rows.length === 0)
						throw Error("no latest attestor list");
					var latest_attestor_list_unit = latest_rows[0].unit;

					// read the list
					conn.query(
						"SELECT attestor_address FROM asset_attestors CROSS JOIN units USING(unit) \n\
						WHERE asset=? AND unit=? " + before_last_ball_cond + " AND sequence='good'",
						[asset, latest_attestor_list_unit],
						function (att_rows) {
							if (att_rows.length === 0)
								throw Error("no attestors?");
							objAsset.arrAttestorAddresses = att_rows.map(function (att_row) { return att_row.attestor_address; });
							handleAsset(null, objAsset);
						}
					);
				}
			);
		}
```

**File:** writer.js (L218-235)
```javascript
						case "asset":
							var asset = message.payload;
							conn.addQuery(arrQueries, "INSERT INTO assets (unit, message_index, \n\
								cap, is_private, is_transferrable, auto_destroy, fixed_denominations, \n\
								issued_by_definer_only, cosigned_by_definer, spender_attested, \n\
								issue_condition, transfer_condition) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", 
								[objUnit.unit, i, 
								asset.cap, asset.is_private?1:0, asset.is_transferrable?1:0, asset.auto_destroy?1:0, asset.fixed_denominations?1:0, 
								asset.issued_by_definer_only?1:0, asset.cosigned_by_definer?1:0, asset.spender_attested?1:0, 
								asset.issue_condition ? JSON.stringify(asset.issue_condition) : null,
								asset.transfer_condition ? JSON.stringify(asset.transfer_condition) : null]);
							if (asset.attestors){
								for (var j=0; j<asset.attestors.length; j++){
									conn.addQuery(arrQueries, 
										"INSERT INTO asset_attestors (unit, message_index, asset, attestor_address) VALUES(?,?,?,?)",
										[objUnit.unit, i, objUnit.unit, asset.attestors[j]]);
								}
							}
```

**File:** writer.js (L244-251)
```javascript
						case "asset_attestors":
							var asset_attestors = message.payload;
							for (var j=0; j<asset_attestors.attestors.length; j++){
								conn.addQuery(arrQueries, 
									"INSERT INTO asset_attestors (unit, message_index, asset, attestor_address) VALUES(?,?,?,?)",
									[objUnit.unit, i, asset_attestors.asset, asset_attestors.attestors[j]]);
							}
							break;
```

**File:** composer.js (L123-125)
```javascript
function composeAssetAttestorsJoint(from_address, asset, arrNewAttestors, signer, callbacks){
	composeContentJoint(from_address, "asset_attestors", {asset: asset, attestors: arrNewAttestors}, signer, callbacks);
}
```
