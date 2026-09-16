### Title
Asset attestor list update fully replaces (rather than extends) the trusted attestor set, retroactively freezing already-issued asset holdings - ([File: storage.js])

### Summary
For a `spender_attested` asset, the current list of trusted attestors is computed at validation time by looking only at the single most-recent `asset_attestors` update unit and using **only its** attestor list, discarding every attestor that was present in earlier updates. This is directly analogous to `clearExtraRewards` in the external report: a single call/message from a privileged-but-reachable actor (the asset definer) wipes out the previously established set of references (attestors) that other users' funds depend on, instead of adding to it, causing loss of ability to spend/transfer already-held coins.

### Finding Description
When an asset is created with `spender_attested: true`, holders can only spend/transfer it if they are attested by one of the addresses in the asset's current attestor list. The attestor list can be updated at any time by the asset definer via an `asset_attestors` message [1](#0-0) , which is validated only for author-is-definer and a well-formed non-empty list [2](#0-1) . Nothing requires the new list to be a superset of, or otherwise consistent with, previous lists.

Crucially, when the asset is later read for validation, `readAsset` does **not** union all historical attestor lists — it looks up only the single latest `asset_attestors` unit and uses exclusively that unit's list as the current trusted attestor set: [3](#0-2) 

This list is then used to filter which authors/spenders count as "attested" for payment validation of the asset: [4](#0-3) [5](#0-4) 

Because the lookup keys strictly on the latest update unit and does not merge with prior lists, if the definer posts a new `asset_attestors` message that (intentionally or by mistake) omits an attestor address that was present in an earlier list, all attestations previously issued by that now-removed attestor immediately stop counting. Token holders who received/hold the asset in reliance on that earlier attestation can no longer pass the `spender_attested` check and become unable to spend or transfer coins they already legitimately hold — exactly the "premature/inadvertent clearing of external references leading to loss of access to already-accrued value" pattern described in the external report, except here it also results in unauthorized/inconsistent spend-ability (a node-disagreement/fund-freezing outcome) rather than merely losing a claim on rewards.

### Impact Explanation
Any legitimate holder of a `spender_attested` asset can have their existing balance frozen the moment the asset definer posts a new `asset_attestors` update that does not re-include the attestor who validated them. This is a full loss-of-funds-usability event for affected addresses, triggered by a single message from the asset issuer — an actor explicitly listed as in-scope/reachable ("asset issuer"). Given attestor updates are a normal expected asset-management operation (e.g., adding a new attestor, rotating compromised attestor keys), an issuer performing a routine update without carefully re-specifying the full historical attestor set will unintentionally freeze funds of unrelated third parties who never consented to or were even aware of the update. This matches the required "AA fund loss or freezing" / node-disagreement-on-validity bar for High severity.

### Likelihood Explanation
This requires only one crafted/careless `asset_attestors` message from the asset's definer — no coordination, no malicious node/hub, and no privileged network position. Any asset with `spender_attested: true` is affected, and issuers routinely need to update attestor lists (e.g., to add attestors), making accidental omission of a previously valid attestor a realistic and easy-to-trigger event.

### Recommendation
Change the attestor-list semantics to be additive/cumulative (union of all posted `asset_attestors` lists, with a possible explicit "remove attestor" message) instead of "latest list wins," or require any update to be a superset of the currently active list unless a separate, clearly-labeled attestor-removal message is used. At minimum, `readAsset`'s `addAttestorsIfNecessary` should merge attestor sets across historical `asset_attestors` units rather than selecting only the most recent one [6](#0-5) .

### Proof of Concept
1. Definer creates asset `X` with `spender_attested: true` and initial `attestors: [A]`.
2. Attestor `A` attests address `H` (holder). `H` receives asset `X` and can freely transfer it because `A ∈ current attestor list`.
3. Later, definer posts `asset_attestors` update with `attestors: [B]` (e.g., intending to add attestor `B` alongside `A`, but forgetting to include `A`).
4. `readAsset`'s `addAttestorsIfNecessary` now returns `arrAttestorAddresses = [B]` only (latest unit wins) [7](#0-6) .
5. `H` attempts to spend/transfer previously-held asset `X`. `filterAttestedAddresses` checks `attestor_address IN (B)` for `H`'s attestation, which was made by `A`, so `H` is no longer in `arrAttestedAddresses` [5](#0-4) .
6. `validatePayment` rejects the transfer with "none of the authors is attested" / "issuer is not attested" [4](#0-3) , even though `H`'s holdings were legitimately acquired and nothing about `H` changed — `H`'s funds are now frozen solely due to the definer's attestor-list update.

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
