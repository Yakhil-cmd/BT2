### Title
Unilateral, timelock-free control of an asset's attestor whitelist by a single definer address enables freezing of previously spendable tokens - ([File: validation.js])

### Summary
For any asset created with `spender_attested: true`, ocore grants the asset's `definer_address` sole and unrestricted authority to replace the list of trusted attestors at any time via an `asset_attestors` message, with no timelock, no multisig requirement, and no on-chain constraint preventing a complete swap of the whitelist. Because spendability of the asset is gated on the spender being currently attested by the *current* attestor list, the definer can instantly invalidate the attestation status of any/all existing legitimate holders, freezing their already-issued balances — the same class of "owner can unilaterally change trust/control parameters and hurt users without restriction" risk flagged in the external report about upgradeable `Vault.sol`.

### Finding Description
When an asset is defined with `spender_attested: true`, every payment of that asset requires that at least one author of the spending unit currently be attested by one of the asset's registered attestors: [1](#0-0) 

The list of "trusted" attestors for the asset is not fixed — it can be updated at will by a message of app `asset_attestors`, and validation restricts only *who* may submit that update: solely `objAsset.definer_address`, with no other constraint (no cooldown, no requirement to preserve any prior attestors, no consensus from token holders): [2](#0-1) 

At spend time, the *latest* attestor list unit is looked up and used to determine which addresses currently count as attested; historically-issued attestations from attestors that have since been dropped from the list no longer count: [3](#0-2) [4](#0-3) 

Because attestation status is evaluated against the *current* attestor list rather than the list at the time the attestation/tokens were originally issued, a definer can post a new `asset_attestors` message that entirely swaps out the attestor set. Every previously-attested holder of the asset instantly loses spendability of their balance the next time they try to transact, since `loadAssetWithListOfAttestedAuthors` will find no matching attested author: [5](#0-4) 

This is analogous to the reported risk class: a single privileged party (here, the asset definer, comparable to the Vault owner) can unilaterally alter a trust/authorization parameter that other, unrelated users depend on for continued access to their own funds, with no on-chain safeguard, multisig, or delay to protect against malicious or compromised behavior.

### Impact Explanation
Any holder of a `spender_attested` asset (including balances held by autonomous agents that transact in such an asset) can have their funds permanently frozen without their consent the moment the definer decides to change the attestor list. Because AAs and ordinary wallets alike must satisfy the current attestor list to spend, this can also be leveraged to selectively block a specific address's ability to move funds. This matches the "AA fund loss or freezing" impact category.

### Likelihood Explanation
Any asset issuer choosing `spender_attested: true` is, from asset genesis, a single ordinary address with no code-enforced governance protections. Malicious or key-compromised definers can exploit this trivially by posting a single `asset_attestors` unit; no cooperation from other parties or race conditions are required. The likelihood scales with adoption of `spender_attested` assets by users/AAs that are not the definer.

### Recommendation
- Evaluate attestation against the attestor list in effect at the time the attestor's attestation was made (or at issuance time), rather than always against the newest list, so retroactive/instant freezing is not possible.
- Alternatively, require a minimum on-chain delay (analogous to a timelock) between an `asset_attestors` update and its effect, and/or require the update to be co-signed by a broader set (e.g., a majority of the current attestors) rather than solely the definer.
- Document this centralization risk prominently for asset creators/users of `spender_attested` assets, similar to the report's recommendation to disclose the trust assumptions of privileged upgrade paths.

### Proof of Concept
1. Definer `D` creates asset `A` with `spender_attested: true`, initial `attestors: [X]`.
2. Attestor `X` posts an `attestation` message for user `U`'s address, allowing `U` to be a valid spender of asset `A` per `filterAttestedAddresses`.
3. `U` acquires/holds balance of asset `A`.
4. `D` posts `asset_attestors` message for asset `A` with a new attestor list `[Y]` (validated only by `objUnit.authors[0].address === objAsset.definer_address` in `validateAttestorListUpdate`, `validation.js:2829-2848`).
5. `U` attempts to spend asset `A`; `loadAssetWithListOfAttestedAuthors` → `filterAttestedAddresses` finds no attestation from `Y` for `U`, so `arrAttestedAddresses` no longer contains `U`.
6. `validatePayment` rejects `U`'s spend with "none of the authors is attested" (`validation.js:2118-2119`), permanently freezing `U`'s balance unless `D` chooses to attest `U` again via a cooperating new attestor.

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
