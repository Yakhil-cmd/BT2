### Title
Asset attestor list can be changed by the definer in a single, unconfirmed step, permanently freezing holders' ability to spend - (File: validation.js)

### Summary
For `spender_attested` assets, the definer can replace the entire list of authorized attestors with one signed `asset_attestors` message. The change takes effect immediately once the unit is stable, with no two-step confirmation, delay, or acknowledgement from the affected attestors or holders, mirroring the "admin/treasury address change should be confirmed" bug class from the referenced report: a single mistaken or malicious address update by a privileged party can lock out funds/functionality for everyone else.

### Finding Description
`validateAttestorListUpdate` only checks that the message is well-formed and signed by the current `definer_address` of the asset before accepting the new attestor list outright: [1](#0-0) 

There is no `pendingAttestors`/confirmation mechanism, no requirement that new attestors acknowledge or that old attestors sign off, and no delay/rollback window. As soon as the `asset_attestors` unit becomes stable, `readAsset`/`loadAssetWithListOfAttestedAuthors` recompute the attestor set from the latest such unit: [2](#0-1) 

Every subsequent payment of that asset is validated against this new, unilaterally-set list: [3](#0-2) 

If the definer posts an `asset_attestors` unit that removes all currently-relevant attestors (typos in addresses, revoking the wrong attestors, or a compromised/careless definer key), every holder whose attestation depended on the old list is immediately unable to spend (`none of the authors is attested`), and there is no built-in path to reverse or confirm the change before it locks in.

### Impact Explanation
This directly matches the "concrete... AA fund loss or freezing" acceptance criterion: a single one-step, unconfirmed change to a critical, protocol-recognized address list (attestors gating spendability of a `spender_attested` asset) can freeze the funds of every holder of that asset. Because the change is irreversible without a further definer-signed correction (which may itself be error-prone, or which the definer may be unable/unwilling to issue), holder funds can be locked indefinitely — a Medium-severity issue analogous to the original "admin/treasury change should be confirmed" finding.

### Likelihood Explanation
The action is reachable by any asset issuer (definer) who has `spender_attested` enabled for their asset — a normal, unprivileged (from the protocol's perspective) unit poster action requiring only a single signed unit. No hub, node, or peer collusion is needed; a simple operational mistake (wrong `attestors` array) or key compromise triggers the freeze for all current holders.

### Recommendation
Introduce a two-step confirmation for `asset_attestors` updates, e.g., require the new attestor set to co-sign (or explicitly opt-in via a subsequent unit) before it becomes authoritative, or add a timelocked/pending state (`pending_attestors`) that only becomes active after a grace period during which the definer (or holders) can cancel the change if it is erroneous.

### Proof of Concept
1. Asset X is created with `spender_attested: true` and attestor list `[A, B]`.
2. Holders receive attestation from A or B and can freely spend X per `validatePayment` (validation.js:2115-2122).
3. Definer posts a single `asset_attestors` message replacing the list with `[C]` (a typo'd or otherwise unreachable address) — accepted per `validateAttestorListUpdate` (validation.js:2829-2848) with only the definer's own signature required.
4. Once stable, `readAsset`/`loadAssetWithListOfAttestedAuthors` (storage.js:1917-1946) return the new list; no existing holder is attested by C.
5. All holders' payment attempts now fail with "none of the authors is attested" (validation.js:2118-2119), permanently freezing their funds unless the definer issues a further correcting unit — which is exactly the "wrong address locks out funds" scenario from the referenced report, but without any confirmation safeguard.

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
