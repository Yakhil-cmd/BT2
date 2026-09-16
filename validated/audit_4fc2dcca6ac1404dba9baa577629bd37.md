## Title
Asset definer's `asset_attestors` update can permanently freeze already-held `spender_attested` assets - (File: `validation.js`, `storage.js`)

### Summary
An asset issuer (definer) of a `spender_attested` asset can post an `asset_attestors` message at any time to change the list of trusted attestors for that asset. Because ocore always resolves an asset's attestor list to the **latest** update rather than the list in effect when a holder received their coins, a holder who legitimately received/held the asset while attested under the old attestor list can become permanently unable to transfer or spend it once the definer swaps out the attestors, exactly mirroring the reported `setRedeemable()` pattern where a privileged party changes a critical dependency address after users already hold the asset.

### Finding Description
When an asset is defined with `spender_attested: true`, every payment of that asset requires both the spender and every output address to be attested by one of the asset's current attestors: [1](#0-0) [2](#0-1) 

The attestor list itself is not fixed at issuance time. It can be changed later by the definer via an `asset_attestors` message, whose only checks are that the sender is the asset's definer and the new list is well-formed — there is no restriction protecting existing holders' ability to keep transacting: [3](#0-2) 

When resolving an asset's attestor list for validation, `storage.readAsset()` always fetches the **most recent** `asset_attestors` unit for that asset (ordered by level DESC LIMIT 1), not the list that was in force when a particular holder acquired the coins: [4](#0-3) 

Consequently, a user who received the asset while properly attested under attestor set A has no guarantee that they, or the intended recipient of a future transfer, will still be attested once the definer replaces the attestor set with B. If none of set B ever attests that holder's address, the holder's balance becomes permanently non-transferrable — they cannot even issue an output back to themselves in a divisible/transferrable sense the same way `redeemable.allowance` reverted the redeem call in the original UXD bug.

### Impact Explanation
This causes concrete freezing of already-issued asset funds for legitimate, previously-compliant holders, with no way to recover unless the definer chooses to re-attest them (a trust decision entirely outside the holder's control). This matches the accepted impact class of "AA fund loss or freezing" for a reachable, single-poster (asset holder/spender) trigger path.

### Likelihood Explanation
Any asset definer can trigger this simply by issuing a normal `asset_attestors` unit, a standard, unprivileged-from-the-holder's-perspective operation that is fully supported by the protocol as "update the attestor list." No malicious node/peer/hub behavior is required — only the ordinary, permitted action of the asset's definer, and it directly affects funds held by unrelated third-party wallets that already legitimately acquired the asset.

### Recommendation
- Bind attestor validation for a holder's balance to the attestor list version that was in effect at the time the coins were received/attested (similar to how `filterAttestedAddresses` already compares against `address_definition_changes` timestamps), rather than always resolving to the latest attestor list.
- Alternatively, require that transfer/spend validation succeed if the address was attested under *any* attestor list that has ever governed the asset up to the point of receipt, so a later attestor-list change cannot retroactively strip existing holders of spendability.

### Proof of Concept
1. Definer `D` issues asset `X` with `spender_attested: true` and initial attestors `[A1]`.
2. `A1` attests holder `H`'s address (`attestation` message referencing `H`).
3. `D` issues asset `X` to `H` (validated successfully since `H` is attested by `A1`, per `validation.js:2115-2122`).
4. `D` posts an `asset_attestors` message for asset `X` replacing the attestor list with `[A2]` (validated per `validation.js:2829-2848`; only checks sender == definer and list well-formedness).
5. `storage.readAsset()` now resolves `X`'s attestor list to `[A2]` for all future validations, per `storage.js:1911-1946`.
6. `H` attempts to transfer/spend their previously-issued balance of `X`. Validation calls `filterAttestedAddresses` against `[A2]`; since `H` was never attested by `A2`, the payment fails with "some output addresses are not attested" / "none of the authors is attested" (`validation.js:2115-2122`, `2630-2641`).
7. `H`'s existing balance of `X` is now permanently frozen unless `A2` chooses to attest `H`, a decision `H` has no control over.

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

**File:** storage.js (L1911-1946)
```javascript
	readAssetInfo(conn, asset, function (objAsset) {
		if (!objAsset)
			return handleAsset("asset " + asset + " not found");
		if (objAsset.sequence !== "good")
			return handleAsset("asset definition is not serial");
		
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
