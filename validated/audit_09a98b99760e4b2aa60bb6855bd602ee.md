### Title
Removing/Changing Asset Attestor List Freezes Already-Attested Holders' Funds - ([File: validation.js])

### Summary
For assets with `spender_attested: true`, the attestor list is mutable by the asset definer via an `asset_attestors` message at any time. Payment validation always re-checks the *current* attestor list against on-chain `attestations` rather than the attestation status that was valid when the holder received/owned the output. If the definer updates the attestor list (e.g., removes an attestor, or replaces it), addresses that were legitimately attested and hold existing outputs of that asset instantly lose the ability to spend or transfer those outputs — exactly the "asset no longer listed → can't redeem" bug class from the reference report, but here the trigger is a mutable whitelist of attestors rather than a listing flag.

### Finding Description
When validating a payment of a `spender_attested` asset, the code loads the **latest** attestor list for the asset and checks whether the owner address is in the set of addresses attested by a **currently listed** attestor: [1](#0-0) 

`filterAttestedAddresses` joins the `attestations` table against `objAsset.arrAttestorAddresses`, which is always the *current* attestor list, not the list that was in effect when the address was attested: [2](#0-1) 

The definer can change this list unilaterally at any time via an `asset_attestors` message — only the asset definer's signature is required, and there is no restriction preventing them from doing this after users already hold funds: [3](#0-2) 

Both the "spend" path (checking `owner_address`) and the "receive" path (checking `arrOutputAddresses`) enforce attestation against this mutable, current-only list: [4](#0-3) [5](#0-4) 

Because the check is always evaluated against the live attestor list rather than a snapshot of the attestation valid at receipt time, any address whose original attestor is later removed (or whose attestation predicates on an attestor that gets swapped out) becomes permanently unable to move its existing balance of that asset, even though it did nothing wrong and legitimately acquired the funds while properly attested.

### Impact Explanation
Users holding a `spender_attested` asset can have their existing, legitimately-owned funds permanently frozen purely by an action of the asset definer (updating the attestor list), with no way for the affected user to recover access short of convincing the definer to re-add the attestor or obtaining a fresh attestation from a currently-listed attestor. This is a fund-freezing issue reachable by an ordinary asset holder/counterparty in a normal payment flow, matching the "Medium — locked out of withdrawing/redeeming" severity class of the referenced report.

### Likelihood Explanation
This requires only that (a) an asset is defined with `spender_attested: true` (a supported, common asset feature, also usable by AA-defined assets per `validateAssetDefinition`), and (b) the definer later issues an `asset_attestors` update removing or changing an attestor — an action explicitly permitted and unrestricted in `validateAttestorListUpdate`. No malicious peer/hub/network conditions are needed; it's a straightforward asset-issuer-driven interaction with a normal holder.

### Recommendation
Do not re-validate attestation of the *current* owner/output holder against the live attestor list at spend time using only the latest list. Instead, either:
- Snapshot/cache which attestor list version was valid when the output was created and permit spending if it was attested under any list, or
- Only enforce the current spender-attestation check on the sender for the purposes of the *current* transaction's business logic (already covered) but allow spending of previously-received/legitimately-owned balances regardless of later attestor list changes — i.e., treat attestation only as a gate on transfer to new attested addresses, not as a retroactive freeze of already-owned outputs.

### Proof of Concept
1. Definer creates asset A with `spender_attested: true` and attestor set `{X}`.
2. Attestor `X` attests address `U`.
3. `U` receives a valid payment of asset A (passes `validatePaymentInputsAndOutputs`, since `U` is in `arrAttestedAddresses`).
4. Definer posts an `asset_attestors` message for asset A removing `X`, setting attestor set to `{Y}` (permitted per `validateAttestorListUpdate`, only requires definer's signature).
5. `U` now tries to spend the previously received output. `storage.readAsset` → `filterAttestedAddresses` uses the new attestor set `{Y}`; since `U` was never attested by `Y`, `arrAttestedAddresses` no longer includes `U`.
6. Validation at `validation.js:2506` (`objAsset.arrAttestedAddresses.indexOf(owner_address) === -1`) fails with `"owner address is not attested"`, permanently blocking `U` from spending funds it legitimately owns.

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

**File:** validation.js (L2504-2507)
```javascript
							if (objAsset && objAsset.auto_destroy && owner_address === objAsset.definer_address)
								return cb("this output was destroyed by sending it to definer address");
							if (objAsset && objAsset.spender_attested && objAsset.arrAttestedAddresses.indexOf(owner_address) === -1)
								return cb("owner address is not attested");
```

**File:** validation.js (L2630-2642)
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
					},
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
