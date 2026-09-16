## Title
Asset definer can retroactively revoke attestation of existing holders, permanently freezing already-received `spender_attested` asset funds - (File: `validation.js`)

## Summary
`ocore` lets an asset be created with `spender_attested: true`, meaning every address that holds or receives units of that asset must be attested by one of the asset's designated attestors. The attestor list, however, is not fixed at asset creation: the definer can update it at any time via an `asset_attestors` message, and every subsequent spend validation re-checks attestation status against the *current* (latest) attestor list rather than the list that was in effect when the funds were legitimately received. This lets the definer role — supposedly limited to managing who can *newly* receive/spend the asset — retroactively strip already-held, legitimately-acquired user balances of their spendability, freezing user funds exactly the way a compromised "rescuer" role can seize/immobilize assets that were never meant to be under its control.

## Finding Description
The asset-attestors update path is validated in `validateAttestorListUpdate`: [1](#0-0) 

This only checks that the sender is the asset's `definer_address` and that the new list is well-formed — it does not preserve or grandfather attestation status for holders who already hold funds under the previous attestor set.

When any later payment (public or private) spends this asset, `validatePaymentInputsAndOutputs` re-validates attestation of both the *inputs* (existing owners) and the *outputs* (recipients) using the current attestor list: [2](#0-1) [3](#0-2) 

The attestor list used for this check is always the *latest* one as of `last_ball_mci`, not the one in effect when the address originally received the funds: [4](#0-3) [5](#0-4) 

Because `filterAttestedAddresses` only accepts attestations made by attestors that are *currently* in the asset's attestor list, removing an attestor from the list instantly and retroactively invalidates every attestation that attestor previously issued — even for addresses that already legitimately hold the asset's tokens (received while properly attested). Those holders can no longer produce a valid `payment` message for that asset (`"owner address is not attested"` / `"some output addresses are not attested"`), so their balance becomes permanently unspendable/frozen. There is no requirement that the removal only affect future transfers; the check is state-based, not chronological.

This mirrors the reported class of bug: a role that is only supposed to manage prospective, "accidental" or administrative conditions (here, the future eligibility list) is in fact able to unilaterally strip already-vested user assets of usability — the equivalent of "rescuing" tokens that were never meant to be touched by that privileged role.

## Impact Explanation
Any `spender_attested` asset (a common pattern for compliance/KYC-style tokens, or any AA/asset built by third parties on top of ocore) is exposed: if the asset definer key is compromised, taken over, or simply turns rogue, the attacker can post a single `asset_attestors` unit that drops one or more attestors from the list. This immediately and irreversibly freezes the funds of every address whose attestation depended on the removed attestor(s), with no recourse for the victims (their coins are unspendable, matching the "AA fund loss or freezing" acceptable-impact category). Since asset definers are ordinary user-controlled addresses (not network operators/witnesses), this is reachable purely through normal asset-issuer privileges, not through any excluded (node/hub/p2p) actor.

## Likelihood Explanation
Triggering the freeze requires only a single, cheaply composed unit (`asset_attestors` message) authored by the asset definer address — no special network position, no race condition, and no cooperation from victims is needed. Any asset issuer who becomes compromised or malicious can execute this immediately against all existing holders of their `spender_attested` asset.

## Recommendation
- Short term: When validating a payment's inputs/outputs for a `spender_attested` asset, check attestation against the attestor list that was current as of the last time the specific input/output address's balance was validated (or otherwise grandfather previously-attested holdings), rather than always requiring attestation under the *latest* list. Alternatively, require `asset_attestors` updates to only add attestors (never remove), or introduce a mandatory notice/lock-in period before a removed attestor's prior attestations stop being honored for existing balances.
- Long term: For any asset/AA feature where a single privileged address (definer/issuer) can change eligibility, permission, or spending conditions after tokens have already been distributed, ensure the design cannot be used to trap or seize already-vested user funds if that privileged key is lost or compromised.

## Proof of Concept
1. Definer `D` creates asset `A` with `spender_attested: true` and attestor `T1` (`validateAssetDefinition` in `validation.js:2725`).
2. `T1` attests user `U`'s address; `D` (or anyone) sends `A` tokens to `U`, validated successfully because `U` is attested by `T1` (`validatePayment`/`validatePaymentInputsAndOutputs`, `validation.js:2115-2121`, `2504-2507`).
3. `D`'s key is compromised (or `D` turns rogue). Attacker posts an `asset_attestors` unit removing `T1` from `A`'s attestor list (`validateAttestorListUpdate`, `validation.js:2829-2848`).
4. `U` now attempts to spend/transfer their previously received `A` tokens. `storage.readAsset`/`filterAttestedAddresses` use the new attestor list (which no longer includes `T1`), so `U`'s prior attestation no longer counts, and the payment is rejected with `"owner address is not attested"` (`validation.js:2504-2507`, `storage.js:1960-1974`).
5. `U`'s funds are now permanently frozen with no attestor able to re-attest them retroactively for the same balance state, even though `U` did nothing wrong and the tokens were legitimately received.

### Citations

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
