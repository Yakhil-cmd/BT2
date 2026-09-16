### Title
Asset definer can retroactively revoke attestor trust and freeze existing holders' funds of a `spender_attested` asset - (File: `validation.js`, `storage.js`)

### Summary
For any asset created with `spender_attested: true`, the asset definer maintains a mutable whitelist of trusted `attestors` via the `asset_attestors` message. Payment validation always evaluates a holder's "attested" status against the **current/latest** attestor list rather than the list that was active when the holder was actually attested. If the definer swaps out an attestor (e.g. removes the attestor that vouched for a given holder and adds a different one), holders who were legitimately attested under the old list instantly lose the ability to spend or transfer the asset units they already hold, exactly mirroring the "owner changes whitelist status → user funds frozen" pattern from the external report.

### Finding Description
When an asset has `spender_attested = true`, `storage.readAsset()` resolves the asset's `arrAttestorAddresses` by always picking the newest `asset_attestors` unit for that asset that is stable and before `last_ball_mci`, i.e. the *current* whitelist, with no regard for what the whitelist looked like historically: [1](#0-0) 

That current whitelist is then used to filter which addresses count as "attested" for a payment: [2](#0-1) 

`validatePayment()` requires that at least one author be attested (and, for issuance, that the issuer specifically be attested) before it will validate the payment/transfer of a `spender_attested` asset: [3](#0-2) 

The attestor list itself is fully controlled by the asset definer and can be changed at will via the `asset_attestors` message, gated only by `validateAttestorListUpdate`, which just checks that the sender is the asset's `definer_address`: [4](#0-3) 

There is no check that removing/replacing an attestor does not strip attested status from addresses that already hold balances of the asset, and no grandfathering of previously-valid attestations. The composer-side check for indivisible assets shows the same reliance on the live attestor list at spend time: [5](#0-4) 

### Impact Explanation
This is the direct analog of the Blueberry "whitelist change freezes/loses user funds" pattern: the asset definer (an unprivileged actor from the protocol's perspective, reachable by simply posting an `asset_attestors` unit) can unilaterally revoke a previously-valid attestation path, and any existing holder of the asset whose only attestation came from the removed attestor becomes permanently unable to spend, transfer, or (if applicable) issue their already-held balance of that asset — their funds are frozen inside the DAG with no recovery path except the definer restoring the exact attestor relationship, at their sole discretion. Because `spender_attested` assets are a general-purpose primitive usable by any asset issuer (including AAs, per `aa_validation.js`'s `asset` message support), this can freeze real user value with no protocol-level safeguard.

### Likelihood Explanation
Likelihood is moderate to high in any deployment using `spender_attested` assets (e.g., KYC/whitelist-gated tokens): the definer routinely rotates attestors for business reasons (e.g., replacing a compromised or discontinued attestation provider), and each such rotation silently invalidates the "attested" status of every holder whose attestation isn't re-validated by the new attestor set. No malicious intent is required — even a benign/legitimate attestor-list update produces the freeze for unrelated holders.

### Recommendation
When evaluating whether a spender/issuer is attested, evaluate against the attestor list that was in effect at the time the attestation unit was posted (or otherwise track a historical mapping of attestation→attestor-list validity), rather than only the currently-live attestor list. Alternatively, require that attestor-list changes cannot retroactively invalidate attestations that were valid when made, or provide an explicit grace/migration mechanism so existing holders are not silently frozen out when the definer rotates attestors.

### Proof of Concept
1. Definer issues asset `A` with `spender_attested: true` and initial `attestors: [X]`.
2. Attestor `X` posts an `attestation` for holder `H`'s address, making `H` "attested" per `filterAttestedAddresses` (storage.js:1959-1974).
3. `H` receives units of asset `A` (e.g., via a `payment` from the definer or another holder) — this succeeds because `H` is currently attested.
4. Definer posts an `asset_attestors` message for asset `A` changing the attestor set to `[Y]` (validation.js:2829-2848 only checks the sender is `definer_address`; no check on existing holders).
5. `H` attempts to spend/transfer their existing balance of `A`. `validatePayment()` recomputes `arrAttestedAddresses` using the new, current attestor list `[Y]` (storage.js:1917-1946, 1959-1974); since `X`'s attestation of `H` is no longer backed by a listed attestor, `H` is excluded from `arrAttestedAddresses`, and validation.js:2115-2122 rejects the payment with "none of the authors is attested," even though `H`'s balance and original attestation are untouched.
6. `H`'s previously acquired, legitimately-attested funds are now unspendable unless the definer restores `X` (or re-attests `H` under `Y`) — a freeze fully controlled by the definer's unilateral, single-unit action.

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

**File:** storage.js (L1959-1974)
```javascript
// filter only those addresses that are attested (doesn't work for light clients)
function filterAttestedAddresses(conn, objAsset, last_ball_mci, arrAddresses, handleAttestedAddresses){
	conn.query(
		"SELECT DISTINCT address FROM attestations CROSS JOIN units USING(unit) \n\
		WHERE attestor_address IN(?) AND address IN(?) AND main_chain_index<=? AND is_stable=1 AND sequence='good' \n\
			AND main_chain_index>IFNULL( \n\
				(SELECT main_chain_index FROM address_definition_changes JOIN units USING(unit) \n\
				WHERE address_definition_changes.address=attestations.address AND main_chain_index<=? AND is_stable=1 AND sequence='good' ORDER BY main_chain_index DESC LIMIT 1), \n\
			0)",
		[objAsset.arrAttestorAddresses, arrAddresses, last_ball_mci, last_ball_mci],
		function(addr_rows){
			var arrAttestedAddresses = addr_rows.map(function(addr_row){ return addr_row.address; });
			handleAttestedAddresses(arrAttestedAddresses);
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

**File:** indivisible_asset.js (L756-757)
```javascript
				if (objAsset.spender_attested && objAsset.arrAttestedAddresses.length === 0)
					return onDone("none of the authors is attested");
```
