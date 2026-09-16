## Analysis

The Cantina finding describes a bug class where a **migration/reconfiguration function does not allow transitioning a gating dependency (a staking contract) to an empty/disabled state**, so once the feature is turned on it can never be turned off, permanently restricting fund movement.

The closest reachable analog in `ocore` is the **asset `spender_attested` / attestor-list mechanism**, which gates every payment of a given asset behind a mandatory, non-emptiable list of attestor addresses, with no way for the asset issuer to ever disable the requirement.

### Title
Asset issuer can never disable `spender_attested` attestation gating, permanently freezing the asset once attestors become unusable - (File: `validation.js`)

### Summary
When an asset is defined with `spender_attested: true`, every future payment of that asset requires at least one author to be attested by an address in the asset's current attestor list [1](#0-0) . The attestor list can be updated later via an `asset_attestors` message, but `checkAttestorList` unconditionally rejects an empty list [2](#0-1) , and the `spender_attested` flag itself is set once at asset definition and can never be changed afterward (there is no message type that lets the definer flip `spender_attested` back to `false`) [3](#0-2) . This is structurally identical to the reported bug class: a configuration that enables a gating dependency has no corresponding "disable"/empty-target path.

### Finding Description
`validateAssetDefinition` requires `spender_attested` to be a boolean at asset creation and, if true, requires a valid non-empty `attestors` array via `checkAttestorList` [4](#0-3) . This asset definition is immutable once issued — assets are identified by the defining unit and there is no "redefine asset" message app, so `spender_attested` can never be toggled off.

The only way to change the trusted set is `asset_attestors`, validated by `validateAttestorListUpdate`, which is restricted to the asset definer and again enforces `checkAttestorList`, which requires `isNonemptyArray(arrAttestors)` [5](#0-4) . There is no code path anywhere that allows the definer to submit an empty attestor list to effectively disable the attestation requirement, analogous to the reported inability to migrate a staking pool to an empty address.

At payment-validation time, `storage.readAsset`/`loadAssetWithListOfAttestedAuthors` computes `arrAttestedAddresses` from the latest stable attestor-list unit [6](#0-5) , and `validatePayment` then hard-rejects any payment where none of the authors is attested [1](#0-0) .

### Impact Explanation
If the set of attestor addresses becomes unusable — attestors lose their keys, stop cooperating, become malicious, or the definer simply wants to discontinue the attestation requirement — the asset issuer has no way to disable the gate. Because `spender_attested` cannot be reverted and the attestor list can never be emptied, every future payment of that asset (for every holder, not just the issuer) will be permanently rejected with "none of the authors is attested", freezing all outstanding balances of the asset. This matches the "AA fund loss or freezing" impact category: legitimate asset holders lose access to their funds with no on-chain recovery path, mirroring the original report's "liquidity can be locked" scenario.

### Likelihood Explanation
This requires no attacker action — it is a deterministic design gap reachable by any asset issuer who legitimately wants to retire or relax the attestation requirement, or who is forced into it because the attestors they originally chose stop being trustworthy/available. Since attestor addresses are ordinary addresses chosen at issuance (private, off-chain entities), attestor unavailability over the asset's lifetime is a realistic, foreseeable event, making the likelihood of hitting this permanent-freeze condition moderate to high for any long-lived attested asset.

### Recommendation
Allow the asset definer to submit an `asset_attestors` update with an empty `attestors` array (or add an explicit flag) that is interpreted as disabling the `spender_attested` requirement going forward, analogous to allowing migration to an "empty" state in the referenced report. Update `checkAttestorList` in `validation.js` to permit an empty list specifically for this disable path, and update `storage.readAsset`/`validatePayment` to skip the attestation check once the list has been intentionally emptied.

### Proof of Concept
1. Issuer defines asset `A` with `spender_attested: true` and `attestors: [X]` (validated by `checkAttestorList`, requiring non-empty list) [4](#0-3) .
2. Address `X` loses its keys / stops attesting, or the issuer decides attestation is no longer desired.
3. Issuer attempts to submit `asset_attestors` with `attestors: []` to disable the gate — rejected by `checkAttestorList("attestors not defined")` [7](#0-6) .
4. No message exists to flip `spender_attested` to `false` on the already-issued asset.
5. All subsequent payments of asset `A` from any holder fail permanently at `validatePayment`'s "none of the authors is attested" check [1](#0-0) , freezing every holder's balance in that asset indefinitely.

### Citations

**File:** validation.js (L2115-2121)
```javascript
		if (objAsset.spender_attested){
			if (conf.bLight && objAsset.is_private) // in light clients, we don't have the attestation data but if the asset is public, we trust witnesses to have checked attestations
				return callback("being light, I can't check attestations for private assets"); // TODO: request history
			if (objAsset.arrAttestedAddresses.length === 0)
				return callback("none of the authors is attested");
			if (bIssue && objAsset.arrAttestedAddresses.indexOf(issuer_address) === -1)
				return callback("issuer is not attested");
```

**File:** validation.js (L2725-2733)
```javascript
function validateAssetDefinition(conn, payload, objUnit, objValidationState, callback){
	if (objUnit.authors.length !== 1)
		return callback("asset definition must be single-authored");
	if (!isNonemptyObject(payload))
		return callback("asset definition must be a non-empty object");
	if (hasFieldsExcept(payload, ["cap", "is_private", "is_transferrable", "auto_destroy", "fixed_denominations", "issued_by_definer_only", "cosigned_by_definer", "spender_attested", "issue_condition", "transfer_condition", "attestors", "denominations"]))
		return callback("unknown fields in asset definition");
	if (typeof payload.is_private !== "boolean" || typeof payload.is_transferrable !== "boolean" || typeof payload.auto_destroy !== "boolean" || typeof payload.fixed_denominations !== "boolean" || typeof payload.issued_by_definer_only !== "boolean" || typeof payload.cosigned_by_definer !== "boolean" || typeof payload.spender_attested !== "boolean")
		return callback("some required fields in asset definition are missing");
```

**File:** validation.js (L2745-2748)
```javascript
	// attestors
	var err;
	if ( payload.spender_attested && (err=checkAttestorList(payload.attestors)) )
		return callback(err);
```

**File:** validation.js (L2829-2864)
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
