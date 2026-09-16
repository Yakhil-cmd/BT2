I found a valid analog in the `spender_attested` asset attestor-list mechanism.

### Title
Asset definer can update the trusted attestor list and permanently freeze existing coin holders' funds - ([File: validation.js], [File: storage.js])

### Summary
For `spender_attested` assets, the asset definer maintains a "trusted attestor list" (`asset_attestors` message). Anyone holding coins of such an asset can only spend them if they are currently attested by an attestor **from the latest published list**. `validateAttestorListUpdate` lets the definer replace this list at any time with no check that current coin holders remain attested under the new list, mirroring the "plugin removal freezes funds" pattern: a privileged party can swap out the component (here, the attestor set) that gates access to already-issued funds, stranding holders with no recourse.

### Finding Description
`validateAttestorListUpdate` only verifies that the caller is the asset definer and that the new list is well-formed (`checkAttestorList`); it does not check whether currently attested/holding addresses remain attestable under the new list: [1](#0-0) [2](#0-1) 

`storage.readAsset` resolves `arrAttestorAddresses` from only the **single latest** `asset_attestors` unit for the asset — older attestor lists are discarded entirely once a newer one is published: [3](#0-2) 

Spending (payment validation) and issuing both gate on `arrAttestedAddresses`, which is computed by cross-referencing the **current** `objAsset.arrAttestorAddresses` against the `attestations` table: [4](#0-3) [5](#0-4) [6](#0-5) 

Output addresses on transfer/issue are likewise required to already be attested by the current attestor list, checked again deep in `validatePaymentInputsAndOutputs`: [7](#0-6) [8](#0-7) 

If the definer publishes a new `asset_attestors` message replacing all attestors with a completely different set (accidentally or maliciously), every address that was attested only by the removed/old attestors instantly loses the ability to spend or transfer coins they already hold of that asset — because `arrAttestedAddresses` (and the `owner address is not attested` check) is always evaluated against the newest attestor list only, with no historical fallback and no re-attestation grace period.

### Impact Explanation
This is directly analogous to the plugin-removal bug: a component (here, the attestor set) that gates access to already-existing user funds can be swapped out unilaterally, without any check that current holders remain able to access their balances. Users' asset coins become permanently unspendable/untransferable unless the definer (or a cooperating attestor) chooses to re-attest them — a potentially permanent freeze of user funds within the protocol's own accounting rules, matching the Medium-severity "AA/asset fund loss or freezing" impact class.

### Likelihood Explanation
This requires only a single `asset_attestors` unit from the asset definer — an action explicitly reachable by an "asset issuer," one of the actor classes in scope. No special network conditions, multi-party collusion, or unusual timing are needed; it can happen from routine attestor-list maintenance/rotation if the definer doesn't realize existing holders will be locked out, or deliberately to trap specific holders' balances.

### Recommendation
Before accepting an `asset_attestors` update, or before treating an attestor-list change as authoritative for existing holders, consider adding a mechanism to avoid immediately orphaning holders, e.g.:
- Retain validity of coins already recognized as attested under a previous attestor list for a grace period, or
- Require the definer to prove (or the protocol to check) that current known holders/attested addresses remain attestable, or provide an explicit unlock/migration path, or
- Warn/require an explicit acknowledgment in the definer tooling when swapping attestors away from currently-attested holders.

### Proof of Concept
1. Definer issues asset X with `spender_attested: true` and initial `attestors: [A]`.
2. Attestor A attests user U's address (`attestation` message), and U receives/holds coins of asset X.
3. U can freely spend/transfer X because `filterAttestedAddresses` finds U attested by A, the current (and only) attestor: [4](#0-3) .
4. Definer posts an `asset_attestors` message for asset X with a brand-new list `[B]` (B has never attested U). This passes `validateAttestorListUpdate` since it only checks the caller is the definer and the list is well-formed: [1](#0-0) .
5. `storage.readAsset` now resolves `arrAttestorAddresses = [B]` for asset X (only the latest list is used): [3](#0-2) .
6. Any subsequent payment by U is rejected with "owner address is not attested" / "none of the authors is attested", because U is not attested by B: [8](#0-7) [6](#0-5) .
7. U's existing coins of asset X are now permanently frozen unless B (or a future attestor) chooses to attest U — entirely at the definer/attestor's discretion, with no protocol-level safeguard.

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

**File:** validation.js (L2504-2507)
```javascript
							if (objAsset && objAsset.auto_destroy && owner_address === objAsset.definer_address)
								return cb("this output was destroyed by sending it to definer address");
							if (objAsset && objAsset.spender_attested && objAsset.arrAttestedAddresses.indexOf(owner_address) === -1)
								return cb("owner address is not attested");
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

**File:** storage.js (L1976-1992)
```javascript
// note that light clients cannot check attestations
function loadAssetWithListOfAttestedAuthors(conn, asset, last_ball_mci, arrAuthorAddresses, bAcceptUnconfirmedAA, handleAsset){
	if (arguments.length === 5) {
		handleAsset = bAcceptUnconfirmedAA;
		bAcceptUnconfirmedAA = false;
	}
	readAsset(conn, asset, last_ball_mci, bAcceptUnconfirmedAA, function(err, objAsset){
		if (err)
			return handleAsset(err);
		if (!objAsset.spender_attested)
			return handleAsset(null, objAsset);
		filterAttestedAddresses(conn, objAsset, last_ball_mci, arrAuthorAddresses, function(arrAttestedAddresses){
			objAsset.arrAttestedAddresses = arrAttestedAddresses;
			handleAsset(null, objAsset);
		});
	});
}
```
