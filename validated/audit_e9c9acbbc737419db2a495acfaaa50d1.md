### Title
Asset definer can replace the attestor list via `asset_attestors`, permanently freezing already-issued asset holdings of previously-attested addresses - (File: `validation.js`, `storage.js`)

### Summary
For a `spender_attested` asset, the definer can post an `asset_attestors` message at any time to change which addresses are considered "attestors." `readAsset()` looks up only the single most recent attestor-list unit and uses it as the sole source of truth, discarding all prior attestor lists. Any address that was attested under the old attestor set but is not attested under the new one instantly loses the ability to spend its already-held balance of that asset — with no check that such balances exist and no mechanism to let holders exit before the change takes effect. This mirrors the reported bug class: an admin/definer action removes/replaces a dependency (reward token / attestor) without accounting for value already accrued/held by users, resulting in a silent loss (freeze) of user funds.

### Finding Description
`validateAttestorListUpdate` only checks that the payload is well-formed, that the asset requires attestors, and that the sender is the asset definer — it performs no check on outstanding token holders: [1](#0-0) 

`checkAttestorList` only validates address format/sorting/length, it does not prevent the new list from being disjoint from the old one: [2](#0-1) 

When resolving the effective attestor list for spending, `readAsset()` selects **only the latest** `asset_attestors` unit for the asset (`ORDER BY level DESC LIMIT 1`) and uses that unit's attestor set exclusively — earlier attestor lists are completely superseded, not merged: [3](#0-2) 

`filterAttestedAddresses` then filters real attestations against this current attestor list only: [4](#0-3) 

Finally, `validatePayment`/`validatePaymentInputsAndOutputs` require every spending input's owner address (and, for issuance, the issuer) to be in `arrAttestedAddresses` computed against the *current* attestor list, or the payment is rejected: [5](#0-4) [6](#0-5) 

So, if the definer replaces the attestor set (e.g., attestor A → attestor B) after users have already received/held units of the asset while being attested only by A, those users' existing balances become permanently unspendable the moment the new `asset_attestors` unit stabilizes, exactly analogous to the reported bug: removing a "reward" dependency wipes out access to already-accrued value with no safeguard, refund, or grace-period check.

### Impact Explanation
This causes concrete freezing of user funds at the protocol layer: any output of a `spender_attested` asset owned by an address that isn't attested under the newly published attestor list can never be spent again (no payment message can pass validation for that input). This is not a hypothetical or informational issue — it is an on-chain, irrecoverable loss of access to real asset balances, triggered unilaterally by the asset definer with a single valid `asset_attestors` message, and no other part of the protocol compensates, migrates, or unlocks these balances.

### Likelihood Explanation
Any asset definer of a `spender_attested` asset can trigger this simply by posting a normal `asset_attestors` update (a supported, documented operation) with a different attestor set than the one currently in effect. No special privilege beyond being the original asset definer is required, and no additional validation blocks the definer from doing this even while many addresses hold balances attested only under the old list.

### Recommendation
When processing an `asset_attestors` update, either (a) treat the attestor list as additive rather than a full replacement so previously-attested addresses retain spending rights, or (b) require/allow a migration window during which holders attested under the old list can still spend/exit before the new list takes exclusive effect, or (c) validate that removing an attestor does not strand addresses that currently hold nonzero balances of the asset (requiring an explicit unlock/burn/exchange path for those balances) before accepting the new attestor-list unit.

### Proof of Concept
1. Definer issues asset X with `spender_attested: true` and initial `attestors: [A]`.
2. Attestor A attests address U (via an `attestation` message referencing U).
3. Definer sends U some units of asset X; U's balance is validly spendable because U is attested by A, the current (and only) attestor list.
4. Definer posts a new `asset_attestors` message for asset X with `attestors: [B]` (B ≠ A). This passes `validateAttestorListUpdate` since it only checks well-formedness and definer authorship (`validation.js:2829-2848`).
5. `storage.readAsset()` now resolves the attestor list to `[B]` only, discarding `[A]` (`storage.js:1917-1946`).
6. U attempts to spend its previously received asset X balance. `validatePayment` computes `arrAttestedAddresses` against `[B]`; since U was never attested by B, `objAsset.arrAttestedAddresses.indexOf(owner_address) === -1` and the payment is rejected with `"owner address is not attested"` (`validation.js:2506-2507`).
7. U's asset X balance is now permanently frozen with no path to recovery, mirroring the "user rewards lost when token is removed" bug class in the reference report.

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

**File:** validation.js (L2506-2507)
```javascript
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
