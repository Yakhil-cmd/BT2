### Title
Asset definer can revoke/replace the `spender_attested` attestor list, permanently freezing already-issued asset holdings - (File: `validation.js`, `storage.js`)

### Summary
For `spender_attested` assets, the ability of a holder to send or receive the asset depends entirely on whether their address is currently attested by an attestor found in the asset's *latest* `asset_attestors` list. The asset definer can post a new `asset_attestors` message at any time, unconditionally replacing the previous attestor list, with no check on whether tokens are already in circulation among addresses attested only under the old list. This mirrors the `removeWrapping` bug class: a privileged party can destroy a mapping that outstanding token holders depend on to move/redeem their funds, with no safeguard tied to circulating supply.

### Finding Description
`spender_attested` assets require every input/output address in a payment to be attested by one of the asset's currently active attestors: [1](#0-0) 

The set of "current" attestors is determined by `readAsset`'s `addAttestorsIfNecessary`, which looks up **only the single most recent** `asset_attestors` unit for that asset (`ORDER BY level DESC LIMIT 1`) — older lists are completely discarded, not merged: [2](#0-1) 

`filterAttestedAddresses` only counts attestations issued by an attestor present in `objAsset.arrAttestorAddresses` (the latest list): [3](#0-2) 

The update path, `validateAttestorListUpdate`, only checks that the sender is the asset's definer and that the new attestor list is well-formed (non-empty, sorted, valid addresses) — it performs **no check on outstanding asset balances or on whether removing an attestor would strand existing holders**: [4](#0-3) 

The `asset_attestors` message can be posted by the definer at any time after the asset is created, unconditionally, as shown by both validation and write paths: [5](#0-4) [6](#0-5) 

This is the exact analog of the `removeWrapping` finding: a privileged actor (there, the `XC20Wrapper` owner; here, the asset `definer_address`) can delete/replace a mapping (`unwrapped[wrappedToken]` vs. the asset's active attestor list) that outstanding token holders rely on, with no circulating-supply check, causing legitimate holders to be permanently unable to move their funds.

### Impact Explanation
Once the definer posts a new `asset_attestors` list that omits an attestor who previously attested some holders, those holders' addresses immediately fail the `arrAttestedAddresses` check in `validatePayment`. Since `readAsset` uses only the single latest list, there is no fallback or grace period — the holder's coins under that `spender_attested` asset become permanently unspendable/untransferable (frozen), even though the tokens were legitimately issued and held before the list was changed. This is a direct freezing of user funds, matching the "AA/user fund loss or freezing" impact class validated for this exercise. It can occur unintentionally (definer rotates/loses an attestor key and updates the list without knowing about affected holders) or maliciously (definer deliberately excludes specific holders to lock their balances).

### Likelihood Explanation
Likelihood is Medium-High: any asset defined with `spender_attested: true` (a supported and documented asset feature, also usable by AAs — see `aa_validation.js` case `'asset_attestors'`) exposes this risk. The definer is a normal, expected actor who routinely needs to publish/update attestor lists (e.g., to attest new users), so triggering a list replacement is a normal, permissionless (from the protocol's perspective) operation, not a rare edge case. No additional privilege beyond being the original asset definer is required, and the validation code provides no warning or restriction.

### Recommendation
Before accepting an `asset_attestors` update that removes an existing attestor, or as a general mitigation, consider one of:
- Track/accumulate historical attestor lists so that holders attested under any past list remain valid for spending (rather than only the single latest list), or
- Require that an attestor removal only take effect for future issuances/attestations while preserving validity of prior attestations already used to justify existing balances, or
- Add a governance/warning mechanism (e.g., minimum notice period, or explicit confirmation that no holder solely relies on the removed attestor) before an attestor-list replacement is accepted by `validateAttestorListUpdate`.

### Proof of Concept
1. Definer `D` creates asset `A` with `spender_attested: true` and initial `attestors: [X]` (`asset` message with `attestors`, per `writer.js` lines 218-235).
2. Attestor `X` attests holder `H`'s address via an `attestation` message; `H` is issued/receives units of asset `A` and successfully transfers them (validated per `validation.js` lines 2115-2122, using attestor list `[X]`).
3. Definer `D` posts an `asset_attestors` message for asset `A` with a new list `[Y]` (excluding `X`). This passes `validateAttestorListUpdate` unconditionally since only definer authorship and list well-formedness are checked (`validation.js` lines 2829-2864).
4. `storage.readAsset` now returns only `[Y]` as `arrAttestorAddresses` for asset `A` (`storage.js` lines 1917-1946).
5. `H` attempts to transfer/spend their existing balance of asset `A`. `filterAttestedAddresses` finds no attestation for `H` from any attestor in `[Y]` (`storage.js` lines 1960-1974), so `arrAttestedAddresses` excludes `H`, and `validatePayment` rejects the payment with "none of the authors is attested" (`validation.js` line 2118-2119).
6. `H`'s pre-existing, legitimately-held balance of asset `A` is now permanently frozen — unspendable and untransferable — with no path to recovery unless `D` chooses to re-attest via `X` again (at `D`'s sole discretion).

### Citations

**File:** validation.js (L2033-2042)
```javascript
		case "asset_attestors":
			if (!isStringOfLength(payload.asset, constants.HASH_LENGTH))
				return callback("invalid asset in attestor list update");
			if (!objValidationState.assocHasAssetAttestors)
				objValidationState.assocHasAssetAttestors = {};
			if (objValidationState.assocHasAssetAttestors[payload.asset])
				return callback("can be only one asset attestor list update per asset");
			objValidationState.assocHasAssetAttestors[payload.asset] = true;
			validateAttestorListUpdate(conn, payload, objUnit, objValidationState, callback);
			break;
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

**File:** storage.js (L1960-1974)
```javascript
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
