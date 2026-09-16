Based on the investigation, the closest reachable analog to the TellerV2 "owner can arbitrarily change a fee/parameter between commitment and execution to steal/freeze counterparty value" bug class is the unilaterally-revocable **asset attestor list** mechanism for `spender_attested` assets.

### Title
Asset definer can unilaterally revoke attestor status at any time to freeze/steal value already held by attested counterparties in a payment chain - (File: validation.js, storage.js)

### Summary
For assets defined with `spender_attested: true`, the asset definer can publish an `asset_attestors` message at any moment to change who counts as "attested," and this new list is picked up by validation as the single "latest" list with no notice period or commitment binding it to previously-received coins. A holder who legitimately received such an asset while attested can have their attestation silently revoked by the definer before their own outgoing payment (public or private) stabilizes, causing their transfer to fail validation and their funds to be effectively frozen/unspendable, with no recourse — mirroring the reported pattern of a privileged party changing a parameter after the counterparty already committed value, to the counterparty's detriment.

### Finding Description
Asset definitions with `spender_attested: true` require the payment's author addresses (and the issuer, if issuing) to be present in the "latest" attestor list at validation time: [1](#0-0) 

The "latest" attestor list is not the one that applied at the time the holder received/was attested; it is dynamically recomputed for whatever `asset` payment is currently being validated, simply picking the most recent `asset_attestors` unit visible at `last_ball_mci`: [2](#0-1) 

Only the asset definer is authorized to publish attestor-list updates, and there is no restriction on how often, how soon, or under what conditions the list can be updated — no cooldown, no grandfathering of existing holders, no binding to units/payments already in flight: [3](#0-2) 

The same unbounded, single-author, non-locked control also applies via the `asset` message's inline `attestors` field, and the `asset_attestors` message can be posted once per unit but arbitrarily many times across units (no "can be only one asset attestor list update per asset" check per asset-lifetime, only per-unit): [4](#0-3) 

This applies equally to public and private assets: a private, `spender_attested` asset is explicitly checked the same way (only light wallets are excused from checking, and only for privacy reasons, not because the check is skipped): [5](#0-4) 

### Impact Explanation
A user who received `spender_attested` coins in good faith (while attested) can compose and broadcast a further payment (transfer, or in a private-payment chain), but if the definer revokes their attestation before that payment's referenced `last_ball_mci` stabilizes, the payment becomes permanently invalid ("none of the authors is attested" / "issuer is not attested"). Because ocore units are immutable once broadcast (they cannot be re-signed with a different `last_ball` after being shared/handed off, especially in private-payment chains where the recipient depends on receiving a valid spend chain), this can result in the holder's coins becoming permanently unspendable — a fund-freezing/fund-loss impact for a counterparty who had no ability to consent to or anticipate the definer's action, directly analogous to the TellerV2 issue where an owner's unilateral fee change harmed a counterparty who had already committed to a transaction.

### Likelihood Explanation
The required actor is the asset's own definer — a role explicitly reachable by any user who deploys an asset (an "asset issuer," one of the permitted roles for this analysis) — and the action (publishing `asset_attestors`) is a normal, always-available operation requiring no special privileges. No cooldown or rate limit constrains how quickly a definer can move from attesting to revoking, so a malicious or compromised definer can weaponize this against any counterparty who has just received coins and is relying on continued attestation to move them further (e.g., in a multi-hop private payment or timed settlement).

### Recommendation
Bind the attestor-list version used for validating a payment to the state that existed when the payer's coins were attributed/attested (e.g., snapshot attestor membership at the time coins were received, or require a minimum notice/lock-in period before an attestor-list change can affect already-issued/held coins), and/or require multi-party consent (e.g., cosigning) for any change that could invalidate previously attested holders' ability to spend coins they already legitimately hold.

### Proof of Concept
1. Definer `D` issues asset `A` with `spender_attested: true`, `attestors: [D]` initially, and attests address `H`.
2. `D` sends `H` some units of asset `A`; `H`'s address is in the current attestor list, so the transfer to `H` validates.
3. `H` composes a further payment spending the received asset `A` coins (e.g., forwarding them privately to `H2`), referencing a current `last_ball_unit`.
4. Before `H`'s payment stabilizes, `D` posts an `asset_attestors` update removing `H` from the list; this update stabilizes with `main_chain_index` at or before `H`'s payment's `last_ball_mci`.
5. When `H`'s payment unit is validated (`validatePayment` in [6](#0-5) ), `storage.readAsset`'s `addAttestorsIfNecessary` ( [2](#0-1) ) returns the new list without `H`, and the payment is rejected with "none of the authors is attested," freezing `H`'s coins.

### Citations

**File:** validation.js (L2033-2041)
```javascript
		case "asset_attestors":
			if (!isStringOfLength(payload.asset, constants.HASH_LENGTH))
				return callback("invalid asset in attestor list update");
			if (!objValidationState.assocHasAssetAttestors)
				objValidationState.assocHasAssetAttestors = {};
			if (objValidationState.assocHasAssetAttestors[payload.asset])
				return callback("can be only one asset attestor list update per asset");
			objValidationState.assocHasAssetAttestors[payload.asset] = true;
			validateAttestorListUpdate(conn, payload, objUnit, objValidationState, callback);
```

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
