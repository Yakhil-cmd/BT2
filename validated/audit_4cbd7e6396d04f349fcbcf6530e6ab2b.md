### Title
Asset definer can freeze already-held balances of a `spender_attested` asset by unilaterally updating the attestor list - ([File: validation.js])

### Summary
For assets created with `spender_attested: true`, the asset definer can post an `asset_attestors` message at any time to redefine who is considered "attested." Balance validation always uses the *latest* attestor list rather than the list that was in effect when the coins were received, so a holder whose address is dropped from the new attestor list becomes permanently unable to spend an output they already legitimately own — the same centralization/freezing pattern as the reported "unregister depository" issue, but reachable purely from on-chain asset messages.

### Finding Description
When an asset is defined with `spender_attested: true`, every payment involving it must contain only inputs/outputs owned by currently-attested addresses: [1](#0-0) 

This is enforced again per-input for both public and private payments: [2](#0-1) [3](#0-2) 

The attestor list itself is not pinned to a specific point in time relative to the output being spent. `storage.readAsset` resolves `spender_attested` assets by looking up the single most recent `asset_attestors` unit before `last_ball_mci` and using only that list: [4](#0-3) 

The attestor list can be replaced at any time, unilaterally, by the asset definer alone — no consent from existing holders is required, and there is no restriction preventing removal of addresses that currently hold a balance: [5](#0-4) 

Because `filterAttestedAddresses`/`arrAttestedAddresses` are computed against the *current* (latest stable) list rather than the list in force when the output was created, any address that received/held asset units while attested can be excluded from all future spends simply by the definer publishing a new `asset_attestors` message that omits their attestor(s) or otherwise causes them to fail `attested` checks going forward.

### Impact Explanation
This lets a single privileged party (the asset definer) retroactively and unilaterally freeze funds already owned by other users, with no on-chain recourse — a direct funds-freezing/centralization risk analogous to the reported depository-unregistration bug, but native to core asset validation logic rather than an external contract. Any holder of a `spender_attested` asset is exposed; the definer needs only to publish one `asset_attestors` message.

### Likelihood Explanation
Likelihood is high whenever a `spender_attested` asset is used, since updating the attestor list is a normal, single-authored, always-available operation for the definer (`validateAttestorListUpdate` imposes no restriction tied to current holders' balances). No colluding nodes, network attack, or special privileges beyond being the asset's own definer are required.

### Recommendation
Bind attestor eligibility checks to the attestor list that was current (or attestation timestamp) at the time the specific output was created/received rather than always re-evaluating against the latest list, or provide a grace/vesting mechanism so that holders who were attested at receipt time retain the ability to spend (or at least transfer back) their existing balance even if later removed from the attestor list.

### Proof of Concept
1. Definer issues asset `A` with `spender_attested: true` and attestor list `[X]`.
2. Attestor `X` attests address `U`.
3. User `U` receives a payment of asset `A` (valid at the time, since `U` is attested per `arrAttestedAddresses`).
4. Definer posts `asset_attestors` with a new list that no longer results in `U` being attested (e.g., removing `X` or replacing it).
5. `U` attempts to spend the previously received output; `validatePaymentInputsAndOutputs` now rejects it with `"owner address is not attested"` (`validation.js:2506-2507`/`2432-2433`) because `storage.readAsset`/`filterAttestedAddresses` only consult the newest attestor list (`storage.js:1917-1946`), permanently freezing `U`'s balance.

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

**File:** validation.js (L2430-2433)
```javascript
						if (objAsset.auto_destroy && owner_address === objAsset.definer_address)
							return cb("this output was destroyed by sending to definer address");
						if (objAsset.spender_attested && objAsset.arrAttestedAddresses.indexOf(owner_address) === -1)
							return cb("owner address is not attested");
```

**File:** validation.js (L2504-2507)
```javascript
							if (objAsset && objAsset.auto_destroy && owner_address === objAsset.definer_address)
								return cb("this output was destroyed by sending it to definer address");
							if (objAsset && objAsset.spender_attested && objAsset.arrAttestedAddresses.indexOf(owner_address) === -1)
								return cb("owner address is not attested");
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
