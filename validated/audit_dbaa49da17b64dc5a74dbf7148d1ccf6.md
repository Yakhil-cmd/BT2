### Title
Asset definer can retroactively freeze existing holders' balances of a `spender_attested` asset by updating the attestor list - (File: `validation.js`, `storage.js`)

### Summary
For assets with `spender_attested=true`, the set of addresses allowed to hold/spend the asset is not fixed at issuance/receipt time — it is re-evaluated at every validation against the *current* (latest) attestor list. The asset definer (an unprivileged, non-owner-governed actor who only needs `issued_by_definer_only`-style control over the asset definition) can publish a new `asset_attestors` message at any time to replace the trusted attestor list. Any address that already holds a balance of the asset, but is not attested under the *new* list, becomes permanently unable to spend those existing outputs, even though the outputs were validly acquired under a previous, correctly-attested state. This mirrors the reported bug class where lowering/changing a validity parameter (`skewFractionMax`) after the fact locks funds that were valid under the old parameter.

### Finding Description
When an asset has `spender_attested: true`, the current attestor list is fetched dynamically: [1](#0-0) 

Note that `addAttestorsIfNecessary` always looks up the single *most recent* `asset_attestors` unit (`ORDER BY level DESC LIMIT 1`) confirmed before `last_ball_mci`, and only uses the addresses in that latest unit. There is no notion of "attested at time output was received" — the check is always against the current global list.

The asset definer can change this list at any time via an `asset_attestors` message, and the only validation is that it is single-authored by the definer and contains a valid, well-formed attestor address list: [2](#0-1) 

The spend-side checks then reject any output whose owner is not in this latest list, regardless of whether the owner was attested when the output was created: [3](#0-2) [4](#0-3) [5](#0-4) 

So the sequence is:
1. Attestor A attests address X. Asset definer's attestor list includes A.
2. X legitimately receives units of the `spender_attested` asset (payment validates fine, since X is in `arrAttestedAddresses`).
3. The definer later publishes a new `asset_attestors` message that drops attestor A (or otherwise removes X's attestation chain) from the list.
4. From this point on, any attempt by X to spend the previously-received (and already-owned) asset outputs fails validation with `"owner address is not attested"`, because `objAsset.arrAttestedAddresses` is recomputed from the new list, not the list that was in force when X received the funds.

This is structurally identical to the `skewFractionMax` issue: a global eligibility/validity threshold can be tightened after the fact by a single actor, and previously-valid positions (LP withdrawals in the original report, asset balances here) become permanently unspendable/frozen with no remediation path for the affected holder — the affected holder has no way to "re-attest" retroactively, and the definer has no obligation (and, adversarially, incentive not) to restore the old list.

### Impact Explanation
This results in concrete freezing of funds: an unprivileged asset holder's already-received balance of a `spender_attested` asset becomes permanently unspendable once the definer rotates the attestor list. This is not merely a UX inconvenience — it is a hard validation failure enforced by consensus-critical code (`validatePaymentInputsAndOutputs`), so the funds cannot be moved by any means through the protocol. Because `spender_attested` assets are a first-class, commonly-used asset feature (KYC/whitelisted tokens), and the attacker/triggering party here is simply the asset's own definer performing a routine, permitted operation (updating attestors), the impact meets the "AA fund loss or freezing" / "concrete... freezing" bar for Medium severity.

### Likelihood Explanation
Likelihood is realistic: rotating attestor lists is an intended, permitted, and expected feature of `spender_attested` assets (e.g., an attestor's key is compromised, an attestor service is discontinued, or the definer wants to switch to a new KYC provider). No special privilege beyond being the asset definer is required, and no additional safeguard exists (e.g., grandfathering previously-attested holders, or checking attestation status as of receipt rather than as of spend time). Any legitimate list update that drops a previously-included attestor will immediately and silently freeze the balances of every holder who was only attested through that entry.

### Recommendation
Change the spend-time attestation check so it does not exclusively depend on the *current* attestor list snapshot:
- Either check attestation as of the time the output was created (i.e., against the attestor list unit that was current when the spent output/joint was produced), similar to how other asset properties are pinned at definition time, or
- Allow spending (but not necessarily further attested-only transfers) of outputs that were valid under any historical attestor list version, e.g. by tracking historical attestations per-output rather than recomputing eligibility solely from the latest list, or
- At minimum, disallow attestor list updates from removing addresses that already hold balances of the asset without an explicit migration/grace mechanism, so that existing holders are never retroactively excluded.

### Proof of Concept
1. Definer D issues asset `spender_attested: true` with initial attestor list `[A]`.
2. Attestor A attests address X (`attestation` message referencing A → X).
3. X receives a payment of the asset from D (valid, since `arrAttestedAddresses` includes X at that time), producing output O owned by X.
4. D publishes `asset_attestors` message setting the list to `[B]` (dropping A), which is accepted per `validateAttestorListUpdate` (only requires D to be the sole author/definer and a valid attestor list).
5. `storage.readAsset` → `addAttestorsIfNecessary` now returns `arrAttestorAddresses = [B]`; since X is only attested via A (which is no longer in the list, and B has never attested X), `objAsset.arrAttestedAddresses` no longer contains X.
6. X attempts to spend output O in a new payment. `validatePaymentInputsAndOutputs` hits `if (objAsset.spender_attested && objAsset.arrAttestedAddresses.indexOf(owner_address) === -1) return cb("owner address is not attested");` and the unit is rejected.
7. X's previously legitimately-acquired funds in output O are now permanently frozen — there is no way to spend them unless D restores an attestation path for X, which D is not obligated to do.

### Citations

**File:** storage.js (L1911-1946)
```javascript
	readAssetInfo(conn, asset, function (objAsset) {
		if (!objAsset)
			return handleAsset("asset " + asset + " not found");
		if (objAsset.sequence !== "good")
			return handleAsset("asset definition is not serial");
		
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

**File:** validation.js (L2430-2433)
```javascript
						if (objAsset.auto_destroy && owner_address === objAsset.definer_address)
							return cb("this output was destroyed by sending to definer address");
						if (objAsset.spender_attested && objAsset.arrAttestedAddresses.indexOf(owner_address) === -1)
							return cb("owner address is not attested");
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
