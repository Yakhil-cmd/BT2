### Title
Asset attestor list update lets definer freeze balances of previously-attested holders - (File: validation.js)

### Summary
For assets with `spender_attested=true`, the asset definer can publish an `asset_attestors` message at any time to fully replace the attestor list, and this replacement takes effect immediately for all future spends of the asset, without checking whether existing holders who were valid recipients/spenders under the old list remain attested under the new one. Holders whose only attestations came from the removed attestors become permanently unable to spend or receive that asset.

### Finding Description
When an asset requires attestation (`spender_attested`), every payment of that asset is validated against the *latest* attestor list for the asset, not the list that was in effect when the payer/output address was attested or when the funds were received. `storage.readAsset()` resolves `objAsset.arrAttestorAddresses` by pulling the most recent `asset_attestors` unit for the asset: [1](#0-0) 

Validation of payment inputs/outputs then checks addresses against exactly this latest list: [2](#0-1) [3](#0-2) 

The `asset_attestors` message itself is only validated for basic structure and that the sender is the asset's definer — there is no check that current holders remain covered: [4](#0-3) [5](#0-4) 

The write path simply overwrites the attestor set for the asset with whatever new list the definer submits: [6](#0-5) 

This is structurally the same bug class as `setAlchemist` in the report: a privileged single-author action (here, the asset definer, reachable via a single posted "asset_attestors" unit) swaps out a critical dependency (the attestor set that gates fund movement) without verifying that all current holders' exposure/eligibility carries over, and there is no on-chain mechanism to migrate or grandfather already-attested holders.

### Impact Explanation
Any address holding units of a `spender_attested` asset that was attested only by attestors removed in the new list immediately loses the ability to spend those units — `storage.filterAttestedAddresses` will no longer find them among `arrAttestorAddresses`, and `validatePaymentInputsAndOutputs` rejects the payment with "some output addresses are not attested" / "none of the authors is attested". If the definer changes attestors (e.g., due to attestor rotation, malice, or operational mistake) without every existing holder being re-attested by at least one attestor from the new list, those balances become frozen with no protocol-level remedy — the same "massive user fund freeze" impact called out in the original report, but here it is triggerable directly through a single ordinary message type (`asset_attestors`) available to any asset definer, and it affects *arbitrary third-party holders* of the asset, not just the definer.

### Likelihood Explanation
The action requires only a single-authored `asset_attestors` unit signed by the asset's definer address — no special network role, no multi-party coordination, and no additional validation beyond signature and definer-address checks. Because updating attestors is an expected/normal operation for `spender_attested` assets (e.g., adding/removing/rotating KYC attestors), an operational mistake (forgetting that outstanding balances are attested under the old set only) is plausible, exactly as the original report describes for `setAlchemist`.

### Recommendation
Before accepting an `asset_attestors` update, or as part of asset design, ensure holders are not silently orphaned by an attestor swap:
- Require that new attestor lists be supersets of (or contain a persisting subset from) the current list until impacted balances are demonstrably empty/migrated, or
- Introduce a grace/migration mechanism so that outputs already attested under the previous list remain spendable to the same address after the attestor list changes, and
- At minimum, document/require applications built on `spender_attested` assets to gate `asset_attestors` updates on confirming no outstanding balances belong to addresses that lose attestation, mirroring the recommended `getTotalCredit()==0` / buffer-empty checks from the original report.

### Proof of Concept
1. Definer creates asset `A` with `spender_attested=true` and initial `attestors=[X]`.
2. Attestor `X` attests address `H`; `H` receives a payment of asset `A` (valid, since `H` is attested by `X`, the current/only attestor list).
3. Definer publishes `asset_attestors` message changing the list to `attestors=[Y]` (validated only per `validateAttestorListUpdate`, `validation.js:2829-2848`, no check of `H`'s balance).
4. `storage.readAsset()` now resolves `arrAttestorAddresses=[Y]` for asset `A` (`storage.js:1917-1946`).
5. `H` attempts to spend its previously received `A` balance: `filterAttestedAddresses` finds `H` not attested by `Y`, and `validatePaymentInputsAndOutputs`/`validatePayment` reject the unit ("none of the authors is attested" / "some output addresses are not attested"), permanently freezing `H`'s funds unless `Y` also attests `H`.

### Citations

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

**File:** validation.js (L2630-2641)
```javascript
				async.series([
					function(cb){
						if (!objAsset.spender_attested)
							return cb();
						storage.filterAttestedAddresses(
							conn, objAsset, objValidationState.last_ball_mci, arrOutputAddresses, 
							function(arrAttestedOutputAddresses){
								if (arrAttestedOutputAddresses.length !== arrOutputAddresses.length)
									return cb("some output addresses are not attested");
								cb();
							}
						);
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

**File:** validation.js (L2850-2864)
```javascript
function checkAttestorList(arrAttestors){
	if (!isNonemptyArray(arrAttestors))
		return "attestors not defined";
	if (arrAttestors.length > constants.MAX_ATTESTORS_PER_ASSET)
		return "too many attestors";
	var prev="";
	for (var i=0; i<arrAttestors.length; i++){
		if (!isValidAddress(arrAttestors[i]))
			return "invalid attestor address: "+JSON.stringify(arrAttestors[i]);
		if (arrAttestors[i] <= prev)
			return "attestors not sorted";
		prev = arrAttestors[i];
	}
	return null;
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
