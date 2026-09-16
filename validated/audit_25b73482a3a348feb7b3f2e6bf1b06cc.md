### Title
Asset attestor-list updates can permanently freeze already-held asset balances (including AA funds) - ([File: validation.js])

### Summary
The `asset_attestors` message lets an asset's definer unilaterally replace the trusted attestor list for a `spender_attested` asset at any time, with no check on whether addresses (including AAs) currently hold balances of that asset that depend on attestations from the attestors being removed. This mirrors the CurveLP `set_pool()` bug class: a privileged setter mutates a "current configuration" reference (pool address / attestor list) that other logic uses to authorize movement of already-existing "liquidity" (asset balance), without verifying that the previous configuration's holders can still exit.

### Finding Description
`validateAttestorListUpdate` in `validation.js` only checks that the message is single-authored, well formed, and signed by the asset's definer — it performs no check on current holders or balances before allowing the attestor set to change: [1](#0-0) 

When a payment of a `spender_attested` asset is validated, `storage.readAsset` resolves the asset's *current* attestor list by taking the single most-recent `asset_attestors` unit — there is no fallback to the attestor list that was active when the spender was originally attested: [2](#0-1) 

`filterAttestedAddresses` then only counts attestations issued by attestors that are members of this *latest* list: [3](#0-2) 

Finally, `validatePayment` enforces that a spending author (which can be an AA address) must be in `arrAttestedAddresses`, i.e. attested by a *currently* trusted attestor, or the payment is rejected outright: [4](#0-3) 

Consequently, an address (including an autonomous agent) that legitimately received and is holding units of a `spender_attested` asset — having been attested by attestor A1 at the time it acquired the balance — becomes permanently unable to spend that balance if the definer later swaps the attestor list to {A2, ...} via `asset_attestors`, and the holder cannot obtain a fresh attestation from a member of the new list (attestor unavailable, unwilling, or — critically for an AA — unable to interactively request/receive attestation at all, since AAs cannot initiate off-chain attestation flows). Exactly as in the CurveLP report, the setter (`set_pool`-equivalent = `asset_attestors`) mutates the single "current" reference used by all downstream validation without checking that value already relied upon by existing holders/liquidity has been settled or grandfathered.

### Impact Explanation
Any balance of a `spender_attested` asset held by an AA (a common pattern for AAs that gate access to regulated/KYC'd assets) can be permanently frozen by a single unilateral action of the asset definer, with no way for the AA or its users to recover the funds if the previously-trusted attestor cannot or will not re-attest under the new list. This is a direct AA fund-freezing condition triggered entirely through normal, unprivileged unit posting (the definer only needs to post one `asset_attestors` message; the freezing/loss is suffered by an unrelated third-party AA holding the asset).

### Likelihood Explanation
Any asset definer can trigger this at will by posting a single-authored `asset_attestors` unit; no cooperation from witnesses or the affected AA/holder is required, and no on-chain check prevents it while balances of the asset are outstanding. Given that `spender_attested` assets are a supported, documented asset type intended to interoperate with AAs (e.g., regulated-asset AAs), this is a readily reachable path for any application built on top of ocore that uses attested assets together with AAs holding balances.

### Recommendation
Before allowing an `asset_attestors` update to take effect for spending purposes, require the definer to prove no currently-held balances depend on the outgoing attestor set (analogous to the CurveLP fix of checking previous liquidity is withdrawn), or alternatively let historical attestations remain valid for balances that existed prior to the attestor-list change (grandfathering), so that spending is gated on "was attested under some attestor list valid at time of receipt" rather than solely "is attested under the single most recent list."

### Proof of Concept
1. Definer creates asset X with `spender_attested: true`, initial attestors `[A1]`.
2. Attestor A1 attests address `AA1` (an autonomous agent).
3. `AA1` receives/accumulates a balance of asset X, relying on being attested by A1 (validated via `storage.readAsset`/`filterAttestedAddresses`).
4. Definer posts an `asset_attestors` message replacing the attestor list with `[A2]` (validated solely by `validateAttestorListUpdate`, `validation.js:2829-2848`, no balance check).
5. `AA1` attempts to spend/forward its held balance of asset X; `validatePayment` (`validation.js:2115-2122`) now requires attestation by `A2`, which `AA1` never received and, being an AA, cannot dynamically request off-chain.
6. `AA1`'s balance of asset X is now permanently unspendable — frozen — with no code path in `ocore` allowing recovery.

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
