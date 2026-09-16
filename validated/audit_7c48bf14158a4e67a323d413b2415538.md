## Title
Definer-controlled asset attestor list changes can permanently freeze previously-compliant token holders' ability to transfer their balance - (File: `storage.js`, `validation.js`)

## Summary
Assets in ocore can be created with `spender_attested: true`, meaning every address that sends/receives this asset must be attested by one of the addresses currently listed in the asset's attestor list [1](#0-0) . The definer of the asset can update this attestor list at any time via an `asset_attestors` message, and the check that determines whether a holder is allowed to spend/transfer always uses the *latest* attestor list rather than the list that was valid when the holder acquired the tokens. This is structurally the same bug class as the reported `AutoCompound` issue: a privileged party (the vault owner / here, the asset definer) can toggle a mutable authorization registry, and a legitimate, uninvolved balance holder who relied on the old state becomes unable to move funds they already hold.

## Finding Description
When an asset has `spender_attested = true`, spend/transfer validation requires the address to be currently attested by one of the addresses in `objAsset.arrAttestorAddresses`: [2](#0-1) 

The attestor list itself is not fixed at asset-creation time; the definer can publish new `asset_attestors` updates, and only the *latest* one (highest level/mci) is used when resolving `objAsset.arrAttestorAddresses`: [3](#0-2) 

The only guard on updating this list is that the update must be single-authored by the asset definer and syntactically well-formed; there is no check of whether existing balance holders were attested by the attestors being removed, nor any requirement that they remain reachable under the new list: [4](#0-3) 

`filterAttestedAddresses` cross-references the `attestations` table only against the attestor addresses currently in `arrAttestorAddresses` (i.e., the current list), not the list that was active when the attestation/transfer took place: [5](#0-4) 

Consequence: a holder `U` who received asset `X` while attestor `A` had attested them (valid at time of receipt) can be permanently blocked from moving those tokens once the definer swaps `A` out of the attestor list for `B` — unless `B` (an independent third party with no obligation to `U`) attests `U` again. This mirrors `AutoCompound.setVault`/`vaults[owner]` in the referenced report: an administrative toggle of a mutable registry (`vaults` mapping there, `asset_attestors`/attestor list here) silently breaks the authorization check used by an unrelated function that legitimate users rely on to access already-held funds (`withdrawLeftoverBalances` there, payment input validation here), with no built-in check for currently-held balances before allowing the change.

## Impact Explanation
Any holder of a `spender_attested` asset can have their already-received balance permanently frozen by a normal, permitted administrative action of the asset definer (updating the attestor list), with no way for the holder to remediate other than depending on the goodwill/action of a completely different party (the new attestor). This is a fund-freezing issue reachable purely through the asset issuance/transfer path available to any asset issuer, matching the "AA fund loss or freezing" / inability to confirm previously valid spends criterion. Given ocore's C4-analog precedent was rated Medium ("temporary, mitigable DoS caused by normal administrative operations"), the same severity applies here.

## Likelihood Explanation
Any asset definer who creates a `spender_attested` asset can trigger this by legitimately updating the attestor list (a supported, validated operation) at any point after tokens have already been distributed to holders attested under the old list. No malicious behavior or protocol violation is required — it's an ordinary state transition explicitly supported by `validateAttestorListUpdate`, making the likelihood of accidental or intentional occurrence non-trivial for any asset that uses attestor-gated transfers and periodically rotates attestors (e.g., compliance/KYC providers).

## Recommendation
When validating an `asset_attestors` update, check whether removing/replacing attestors would leave addresses with existing non-zero balances of that asset without any valid attestation path, and either reject the update or provide a mechanism (e.g., grandfathering, a required grace period, or requiring that removed attestors re-attest currently-attested holders under the new list before removal) so that a definer's normal attestor rotation cannot silently strand previously compliant balances. At minimum, this risk should be explicitly documented so wallets/users are aware that holding a `spender_attested` asset carries an ongoing dependency on the definer keeping attestation valid for their address.

## Proof of Concept
1. Definer `D` creates asset `X` with `spender_attested: true`, `attestors: [A]` (`validateAssetDefinition`, `validation.js:2725-2827`).
2. Attestor `A` posts an `attestation` for address `U` (`validation.js:2011-2024`).
3. `D` issues/sends asset `X` to `U`; validation passes because `filterAttestedAddresses` finds `U` attested by `A`, who is in the current attestor list (`validation.js:2115-2122`, `storage.js:1959-1974`).
4. `D` later posts `asset_attestors` update changing the list to `[B]` (`validateAttestorListUpdate`, `validation.js:2829-2848`) — this succeeds because there is no check on existing holders.
5. `U` now attempts to transfer/spend their existing `X` balance. `readAsset` resolves `arrAttestorAddresses = [B]` (latest list) (`storage.js:1917-1946`), and `filterAttestedAddresses` finds no attestation of `U` by `B`. The payment fails validation with "owner address is not attested" (`validation.js:2506-2507`), even though `U`'s balance was validly acquired and `U` did nothing wrong. `U`'s tokens are stuck until `B` independently chooses to attest `U`.

### Citations

**File:** initial-db/byteball-sqlite.sql (L256-260)
```sql
	issued_by_definer_only TINYINT NOT NULL,
	cosigned_by_definer TINYINT NOT NULL,
	spender_attested TINYINT NOT NULL, -- must subsequently publish and update the list of trusted attestors
	issue_condition TEXT NULL,
	transfer_condition TEXT NULL,
```

**File:** validation.js (L2504-2507)
```javascript
							if (objAsset && objAsset.auto_destroy && owner_address === objAsset.definer_address)
								return cb("this output was destroyed by sending it to definer address");
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
