### Title
Asset definer can freeze all holders' funds by replacing the attestor list at will with no restriction - (File: validation.js)

### Summary
For a `spender_attested` asset, the asset definer can post an `asset_attestors` message at any time to completely replace the list of attestors, with no timelock, no minimum notice period, and no requirement that existing holders remain able to spend. Because payment validation always checks the *current* (latest) attestor list rather than the list in effect at the time the asset was issued or transferred, a malicious or compromised definer can swap in attestors who refuse to attest anyone, permanently freezing every holder's balance of that asset.

### Finding Description
`validateAttestorListUpdate` only requires that the sender is the asset's `definer_address` and that the new attestor list is syntactically valid (sorted, valid addresses, under `MAX_ATTESTORS_PER_ASSET`). There is no limit on how often the list can change, no minimum-attestor-overlap rule, and no delay between posting the change and it taking effect: [1](#0-0) 

The list-format check itself performs no economic validation at all: [2](#0-1) 

When a payment of the asset is validated, the spender must be on the *latest* attestor list, queried by taking the most recent `asset_attestors` unit (`ORDER BY level DESC LIMIT 1`), not the list that existed when the holder acquired the asset: [3](#0-2) [4](#0-3) 

This latest list is then enforced on every payment attempt, both for issuing and for transferring/spending: [5](#0-4) [6](#0-5) 

There is no grandfathering: a spender who was validly attested under an older list becomes unable to spend as soon as the definer posts a new list that excludes them (or that includes only attestors who refuse to attest anyone), even though the definer performs no privileged/admin action beyond being the original asset issuer — an actor explicitly reachable via a single posted unit.

### Impact Explanation
An asset definer, acting as an ordinary unprivileged unit poster (issuer of the asset), can single-handedly and irreversibly freeze the funds of every current holder of a `spender_attested` asset by posting one `asset_attestors` unit that swaps in attestors who will never attest the affected holders. This is a direct freezing of already-issued funds with no timelock or economic constraint — structurally identical to the reported bug class (a privileged party can change a critical, funds-affecting parameter at will, harming users who already hold balances under the old rules).

### Likelihood Explanation
Likelihood is high for any asset that uses `spender_attested: true`. The action requires only a single-authored unit from the definer address containing a valid `asset_attestors` message; no cosigning, no waiting period, and no on-chain guard prevents it. Users who acquired the asset in good faith under a previous attestor list have no way to detect or react before the freeze takes effect, since it becomes enforceable in the very next unit that references the change.

### Recommendation
- Enforce a delay/timelock (e.g., require the change to be stable for N main-chain indices) before a new attestor list applies to spends of already-existing outputs.
- Alternatively, bind spend eligibility to the attestor list that was current when the output was created, or require attestor-list changes to preserve attestation for addresses that were already attested at the time of the change.
- Require asset definitions to declare (or vote in) attestor-list change policies (e.g., minimum overlap, cool-down periods) so holders can evaluate this risk before acquiring the asset.

### Proof of Concept
1. Definer address `D` creates an asset `A` with `spender_attested: true` and `attestors: [X]`, where `X` currently attests many addresses including a victim `V`.
2. `V` acquires balance of asset `A` and is validly attested by `X`, so `V` can spend `A` normally (validated via `validatePayment` → `objAsset.arrAttestedAddresses`).
3. `D` posts a new `asset_attestors` message: `{ asset: A, attestors: [Y] }`, where `Y` is an attestor controlled by `D` that will never attest `V` (or anyone). This passes `validateAttestorListUpdate` unconditionally (only checks sender==definer and list format).
4. From this point on, `readAsset`'s attestor lookup picks up the newest `asset_attestors` unit as the "latest list of attestors" [7](#0-6) , so any subsequent payment by `V` fails the `arrAttestedAddresses` check in `validatePayment` [8](#0-7)  and in `validatePaymentInputsAndOutputs` [9](#0-8) , permanently freezing `V`'s existing balance with no recourse.

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
