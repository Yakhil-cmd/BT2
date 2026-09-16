Confirmed: `validateAttestorListUpdate` (validation.js) allows only the definer to update an asset's attestor list, with no check against outputs already held by addresses that will be dropped from the new list.

### Title
Asset definer can revise the attestor list at any time, permanently freezing already-issued/transferred `spender_attested` outputs held by dropped addresses - (File: validation.js)

### Summary
For an asset defined with `spender_attested: true`, spending any output of that asset requires the owning address to be on the asset's *current* attestor list at validation time [1](#0-0) . The attestor list itself can be freely replaced by the asset definer at any later point via an `asset_attestors` message, with no check on whether existing, already-received outputs belong to addresses being removed from the list [2](#0-1) . This mirrors the reported bug class: an owner/definer-controlled parameter (a "slot"/whitelist) is mutated without verifying that already-committed user state (bids in the report; asset outputs here) still fits inside the new constraint, silently stranding that state.

### Finding Description
When an asset is created with `spender_attested: true`, its initial attestor list is stored via the `asset` message, and `readAsset`/`loadAssetWithListOfAttestedAuthors` always resolve the *most recent* attestor list for the asset at validation time (there is no per-output snapshot of "attestor list at time of receipt") [3](#0-2) . The definer can issue an `asset_attestors` message at any later moment to replace the entire attestor list [4](#0-3) , and the only checks performed are that the sender is the definer, the asset actually requires attestors, and the new list is well-formed/sorted [5](#0-4) . Nothing checks whether users are currently holding unspent outputs of that asset at addresses that are about to be dropped from the list.

Once the new list is stable, `validatePayment`/`validatePaymentInputsAndOutputs` re-evaluate `objAsset.arrAttestedAddresses` fresh from the current list on every spend attempt, so a previously-received output at an address no longer in the list becomes permanently unspendable: `objAsset.spender_attested && objAsset.arrAttestedAddresses.indexOf(owner_address) === -1` rejects the payment both for the general payment path [1](#0-0)  and for individual transfer inputs [6](#0-5) . Unlike the reported bid-queue bug, there is no `retract_bid`-style recovery: the coins are simply stuck at that address until (if ever) the definer re-adds it to the attestor list.

### Impact Explanation
Any holder of a `spender_attested` asset can have their existing, previously valid balance frozen indefinitely by a single unilateral, unchecked action of the asset definer, with no on-chain safeguard requiring the definer to consider currently held balances. This is a fund-freezing condition reachable purely by the asset issuer acting within the protocol's own message types (`asset`, `asset_attestors`), matching the "AA fund loss or freezing" / freezing-of-value class called out in the validation criteria.

### Likelihood Explanation
Likelihood is moderate: it requires the asset definer to actively replace the attestor list, which is an intended, single-message operation with no additional friction or timelock, and is nearly certain to occur naturally in normal asset lifecycle management (e.g., swapping a KYC provider or revoking a previously-attested party) without any code path warning about, or accounting for, currently held outputs.

### Recommendation
Before accepting an `asset_attestors` update, or at minimum before enforcing the new list against outputs received prior to the update, either (a) reject updates that would strand addresses currently holding significant unspent balances, or (b) grandfather previously accepted spender addresses for the outputs they already hold (e.g., snapshot the attestor list applicable to the received-time balance instead of always resolving to the latest list), so that revocation only affects future issuance/transfers rather than retroactively freezing existing holdings.

### Proof of Concept
1. Definer `D` issues asset `A` with `spender_attested: true` and `attestors: [X]`.
2. User `U` (address `X`) receives a `payment` of asset `A`, validated successfully because `X` is in the current attestor list [1](#0-0) .
3. `D` posts an `asset_attestors` message for asset `A` with a new list that excludes `X`, e.g. `[Y]`; this passes validation because only definer authorship and list well-formedness are checked [2](#0-1) .
4. `U` now attempts to spend the previously received output of asset `A`. `loadAssetWithListOfAttestedAuthors` recomputes `arrAttestedAddresses` from the new list (which no longer contains `X`), and `validatePayment` rejects the spend with "none of the authors is attested" [1](#0-0) .
5. `U`'s balance is now permanently frozen unless `D` chooses to re-add `X` to the attestor list.

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

**File:** validation.js (L2829-2864)
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

**File:** composer.js (L123-125)
```javascript
function composeAssetAttestorsJoint(from_address, asset, arrNewAttestors, signer, callbacks){
	composeContentJoint(from_address, "asset_attestors", {asset: asset, attestors: arrNewAttestors}, signer, callbacks);
}
```
