### Title
Asset definer can unilaterally update the attestor list of a `spender_attested` asset, permanently freezing existing holders' balances - (File: validation.js, storage.js)

### Summary
In ocore, an asset can be created with `spender_attested: true`, requiring that any address receiving or issuing the asset be attested by one of the asset's designated attestors. The asset definer alone controls this attestor list and can update it at any time after asset creation via an `asset_attestors` message. This mirrors the Unitas `TokenManager.removeTokensAndPairs()` pattern: a privileged, single-actor operation that instantly changes eligibility rules for an already-circulating token, with no mechanism to let existing holders redeem/transfer out first, permanently trapping their balances.

### Finding Description
When an asset is defined with `spender_attested: true`, every payment (issue or transfer) of that asset requires all output addresses to be attested by one of the asset's current attestors, checked in `validatePaymentInputsAndOutputs`: [1](#0-0) 

The attestor list is not fixed at asset creation — it can be freely replaced later using an `asset_attestors` message, gated only by "only definer can edit": [2](#0-1) 

When resolving which attestors currently apply to an asset, `storage.readAsset` always picks the *latest* attestor-list unit only (by level, `ORDER BY ... DESC LIMIT 1`), fully discarding all prior attestor lists — there is no concept of grandfathering existing holders who were attested under an older list: [3](#0-2) 

Consequently, if the definer publishes a new `asset_attestors` update that no longer attests the addresses currently holding the asset (e.g. switches to a different set of attestors, or the attestors simply stop attesting old holders), any address whose attestation is not in the new/current attestor set can no longer be a valid output address for that asset. Because `is_transferrable`/`spender_attested` checks apply uniformly to both issuance and transfer, a holder who becomes unattested cannot move their balance to any address at all (they cannot even self-transfer to a still-attested address, since the check is on output addresses, not just balances). Unlike Unitas's `removeTokensAndPairs`, there is no timelock delay, no supply/redeeem-first requirement, and no protocol-level protection preventing the definer from cutting off already-issued tokens instantaneously and unilaterally — this is entirely equivalent to "removing a token/pair" out from under existing holders.

This same `asset` / `asset_attestors` message construction is also reachable from an Autonomous Agent definition (an AA can define assets and issue `asset_attestors` updates as part of its bytecode), as validated in `aa_validation.js`: [4](#0-3) 

meaning an AA-issued stable/wrapped asset with `spender_attested: true` is exposed to the exact same freezing pattern if the AA (or its author, if the AA logic allows parameterized attestor updates) changes the attestor set.

### Impact Explanation
Any holder of a `spender_attested` asset can have their balance permanently frozen the moment the definer updates the attestor list to exclude them, with immediate effect on the very next stable MC index and no recourse — they cannot transfer, redeem, or move the asset to any address, because every payment output must be attested under the *current* list only. This is a concrete, protocol-level fund-freezing condition for legitimate token holders, directly analogous to the "user's minted token can't redeem" issue in the source report.

### Likelihood Explanation
This requires action by the asset definer (an "asset issuer" actor explicitly in scope), and is trivially reachable: any asset can opt into `spender_attested: true` at creation, and the definer is completely unconstrained afterward in how it changes the attestor list — no cooldown, no minimum-notice period, and no on-chain check that current holders remain attestable. This makes it easy to trigger, whether accidentally (through legitimate attestor rotation) or maliciously.

### Recommendation
Introduce a grace/redemption mechanism before an attestor-list update takes effect for spend validation of already-issued balances — e.g., require a delay (a stability/MCI-based timelock) between publishing an `asset_attestors` update and its enforcement, or allow addresses attested under any list within a lookback window to remain eligible to transfer out. Alternatively, decouple "attested to issue new asset units" from "attested to transfer already-held asset units," so removing an attestor only prevents new issuance to unattested addresses, not the movement of previously-issued balances.

### Proof of Concept
1. Definer publishes an `asset` message with `spender_attested: true` and `attestors: [A1]`.
2. Attestor `A1` attests address `H` (holder). `H` receives/holds a balance of the asset via a normal payment, validated per `validatePaymentInputsAndOutputs`: [1](#0-0) 
3. Definer later publishes an `asset_attestors` message for the same asset with `attestors: [A2]` (a different attestor), validated only against "definer" authorization: [2](#0-1) 
4. `storage.readAsset` resolves the asset's current attestor list to only the newest unit (A2's list), completely dropping A1: [5](#0-4) 
5. `H` was never attested by `A2`. Any attempt by `H` to spend/transfer the asset now fails validation ("some output addresses are not attested"), permanently locking `H`'s balance with no way to redeem.

### Citations

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

**File:** aa_validation.js (L338-353)
```javascript
				case 'asset_attestors':
					if (hasFieldsExcept(payload, ['asset', 'attestors', 'init']))
						return cb2("foreign fields in attestor list update");
					if (!isNonemptyString(payload.asset))
						return cb2("asset is not a string");
					var asset_formula = getFormula(payload.asset);
					if (asset_formula !== null) {
					}
					else if (!isValidBase64(payload.asset, constants.HASH_LENGTH))
						return cb2("bad asset in asset_attestors: " + payload.asset);
					validateFieldWrappedInCases(payload, 'attestors', validateAttestors, function (err) {
						if (err)
							return cb2(err);
						cb2();
					});
					break;
```
