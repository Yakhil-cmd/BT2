### Title
No mechanism to revoke an individual spender attestation for `spender_attested` assets — only wholesale attestor removal is possible - ([File: storage.js])

### Summary
Assets defined with `spender_attested: true` restrict issuance/transfer to addresses that have been attested by one of the asset's trusted attestors. Once an attestor publishes an `attestation` message for a given address, that specific attestation record is permanent and there is no way for the attestor (or the asset definer) to revoke that single grant. The only revocation lever available is removing the attestor entirely from the asset's trusted-attestor list via `asset_attestors`, which invalidates *every* attestation that attestor ever made, not just the mistaken one.

### Finding Description
When `spender_attested` is true, `validatePayment` requires the issuer/owner address to be attested before it can issue or spend the asset, via `storage.loadAssetWithListOfAttestedAuthors` → `filterAttestedAddresses`: [1](#0-0) 

This query determines "is attested" purely from the historical `attestations` table: `WHERE attestor_address IN(?) AND address IN(?) AND main_chain_index<=? AND is_stable=1 AND sequence='good'`, filtered only by whether the address later changed its own key definition. There is no attestor-controlled "revoke" or "un-attest" message type — the `attestation` app only inserts rows (`writer.js` lines 205-216) and no corresponding deletion/negation message exists.

The only way to invalidate a wrongly-issued attestation is for the asset definer to publish a new `asset_attestors` update that drops that attestor from the trusted list entirely: [2](#0-1) 

But `readAsset`'s `addAttestorsIfNecessary` always uses the single *latest* full attestor list (not incremental), so removing one bad attestor also revokes every other legitimate attestation that attestor has ever made for that asset: [3](#0-2) 

This mirrors the external report's bug class exactly: a grantor (attestor) is given power to authorize a party to perform a restricted action (issuing/spending a `spender_attested` asset), but there is no `onlyOwner`-style function to revoke that specific grant — the only "revocation" tool available is a blunt, all-or-nothing instrument (dropping the attestor from the list), which is disproportionate and can break other users' legitimate rights as collateral damage.

### Impact Explanation
An attestor that mistakenly, or under compromise, attests a malicious address for a `spender_attested` asset has no way to walk back that single decision. The malicious address permanently retains the ability to issue/spend the asset (subject to `cap`/`issued_by_definer_only` rules) unless the definer nukes the entire attestor's trust, collaterally revoking attestations for all other legitimately attested spenders. This can lead to unauthorized issuance/spending of a restricted asset that the definer explicitly gated behind attestor approval — a concrete asset-issuance/transfer-condition bypass reachable by any asset issuer/attestor workflow.

### Likelihood Explanation
Likelihood is moderate: it requires an attestor to make an erroneous attestation (misconfiguration, compromised attestor key, or bug in the attesting service) for a `spender_attested` asset. Given attestors are often automated services/oracles integrated by third parties, erroneous or compromised attestations are a realistic operational risk, and the current design offers no fine-grained recovery path.

### Recommendation
Introduce an explicit, single-target revocation mechanism, e.g., a new message type (or an extension of `attestation`/`asset_attestors`) that lets an attestor (or the asset definer) revoke a specific address's attestation without affecting other addresses attested by the same attestor. `filterAttestedAddresses`/`readAsset` should then treat the latest revocation as authoritative for that specific address, similar to how `address_definition_changes` overrides earlier definitions per-address instead of requiring a global reset.

### Proof of Concept
1. Definer creates asset `A` with `spender_attested: true` and `attestors: [X]`.
2. Attestor `X` is compromised or misconfigured and posts an `attestation` message vouching for attacker-controlled address `M`.
3. `filterAttestedAddresses` (storage.js:1959-1974) will forever consider `M` attested for asset `A` as long as `X` remains in the trusted attestor list and `M` doesn't change its address definition.
4. `M` issues/spends asset `A` freely (validation.js `validatePayment`, checks `objAsset.arrAttestedAddresses.indexOf(owner_address)`).
5. The definer's only recourse is publishing `asset_attestors` dropping `X` entirely (validation.js:2829-2848), which also de-attests every other honest address `X` had attested — there is no way to surgically revoke just `M`'s attestation.

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
