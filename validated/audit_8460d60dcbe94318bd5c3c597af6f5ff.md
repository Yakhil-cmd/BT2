## Title
Asset definer can update `attestors` list via `asset_attestors` message without accounting for existing attested holders, freezing their already-held asset outputs from being spent - (File: `validation.js`)

### Summary
The `SolverVaults::setDepositLimit` bug pattern — a privileged setter changes a limit/gating parameter without validating it against the state that already exists (deposits already made) — has a direct analog in ocore's `spender_attested` asset mechanism. The asset definer can freely replace the list of trusted attestors for an asset at any time via an `asset_attestors` message, and this new list retroactively becomes the *only* list used to determine whether any address (including ones that already legitimately hold/received the asset) is allowed to spend it. There is no check that addresses currently holding unspent outputs of the asset remain attested under the new list.

### Finding Description
When an asset is defined with `spender_attested: true`, spendability of every output of that asset is gated on the address being attested by one of the addresses in `objAsset.arrAttestorAddresses`/`arrAttestedAddresses`, checked at validation time in `validatePayment`/`validatePaymentInputsAndOutputs`: [1](#0-0) [2](#0-1) 

Crucially, the attestor list that is consulted is always the *latest* one, not the list that was active when the holder acquired/was attested for the asset. `storage.readAsset` looks up the most recent `asset_attestors` unit by ordering `ORDER BY level DESC LIMIT 1`: [3](#0-2) 

The definer can post a fresh `asset_attestors` message to fully replace the attestor set at will, gated only by `validateAttestorListUpdate`, which checks only that the sender is the definer and that the new list is well-formed — it performs **no check** against addresses that already hold unspent, previously-valid outputs of the asset: [4](#0-3) [5](#0-4) 

This mirrors the `SolverVaults::setDepositLimit` flaw exactly: a privileged party (definer/setter) changes a gating parameter (attestor list/deposit limit) without validating it against existing legitimate state (already-attested holders/already-deposited users), unilaterally locking out parties who did nothing wrong.

### Impact Explanation
Any address that received the asset while being attested by an attestor who is later dropped from the list (or replaced entirely) becomes permanently unable to spend/transfer its already-held, previously valid outputs of that asset — `validatePaymentInputsAndOutputs` will reject with `"owner address is not attested"` for inputs and `"some output addresses are not attested"` for outputs. Since only the latest list matters, this is not a hypothetical edge case but the designed behavior: the definer can freeze arbitrary honest holders' funds at any time by simply publishing a new attestor list that omits the attestor who validated them, with zero involvement of, or compensation to, the affected holders. This is a fund-freezing vulnerability reachable by an ordinary asset issuer against ordinary counterparties who received the asset in good faith.

### Likelihood Explanation
This requires no attacker sophistication: it is triggerable by any asset definer simply posting a normal, valid `asset_attestors` message (a standard, documented operation, already exercised in `test/ojson.test.js` and various `.oscript` samples). No consensus-breaking behavior or malicious peer/hub action is needed — it is a straightforward application-logic gap reachable from a single posted unit by the asset's own (potentially adversarial, or simply careless) definer/issuer.

### Recommendation
When updating an asset's attestor list, either:
- Snapshot the attestor list valid at output-receipt time and check spendability against that snapshot instead of always the latest list, or
- Require that spendability checks consider whether the address was ever validly attested by *any* attestor list that was active while the address's un-spent balance was accumulated, or
- At minimum, disallow silently orphaning attested holders by requiring the definer to preserve backward compatibility (e.g., union rather than replace attestor sets) unless there is an explicit migration/grace mechanism for existing holders.

### Proof of Concept
1. Definer issues asset `X` with `spender_attested: true` and publishes attestor list `[A1]`.
2. `A1` attests address `U`.
3. `U` receives a payment of asset `X` (valid, since `U` is attested by `A1`, per `validatePaymentInputsAndOutputs` output check at [6](#0-5) ).
4. Definer later posts an `asset_attestors` message for asset `X` replacing the attestor list with `[A2]` (validated only via `validateAttestorListUpdate`, no check against `U`'s holdings) — [4](#0-3) .
5. `U` attempts to spend its previously received, still-unspent output of asset `X`. `storage.readAsset` now returns `arrAttestorAddresses = [A2]` (the newest list) — [7](#0-6) .
6. `filterAttestedAddresses` finds no attestation of `U` by `A2`, so `objAsset.arrAttestedAddresses` excludes `U`.
7. Validation fails with `"owner address is not attested"` at [8](#0-7) , permanently freezing `U`'s legitimately acquired funds despite `U` having done nothing wrong.

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

**File:** validation.js (L2504-2507)
```javascript
							if (objAsset && objAsset.auto_destroy && owner_address === objAsset.definer_address)
								return cb("this output was destroyed by sending it to definer address");
							if (objAsset && objAsset.spender_attested && objAsset.arrAttestedAddresses.indexOf(owner_address) === -1)
								return cb("owner address is not attested");
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
