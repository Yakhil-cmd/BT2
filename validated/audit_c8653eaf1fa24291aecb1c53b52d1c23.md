### Title
Asset issuer can silently freeze previously-attested holders' funds by updating `asset_attestors` list - (File: `validation.js`, `storage.js`)

### Summary
For a `spender_attested` asset, only the **current/latest** attestor list is consulted when validating whether a spender may transfer the asset. There is no on-chain check that a new `asset_attestors` update doesn't strand addresses that already hold unspent, previously-attested asset outputs. Exactly like the referenced Backd finding — where `InflationManager.removeKeeperGauge` could disable a `KeeperGauge` that a `TopUpActionFeeHandler` still depended on, with no check that it was "in use" — an ocore asset issuer can post an `asset_attestors` message that drops an attestor whose attestations are still backing live, unspent outputs, permanently freezing those funds until the issuer manually restores the old attestor (with no guaranteed timeline).

### Finding Description
When an asset requires `spender_attested`, `storage.readAsset` → `addAttestorsIfNecessary` looks up only the single **latest** stable `asset_attestors` unit for the asset and uses only that list going forward: [1](#0-0) 

`filterAttestedAddresses` then checks that a spending address has an `attestation` record from one of these current attestors: [2](#0-1) 

`validatePayment` enforces `objAsset.arrAttestedAddresses.indexOf(issuer_address/owner_address) === -1` errors ("none of the authors is attested" / "owner address is not attested") strictly against this current list: [3](#0-2) [4](#0-3) 

The `asset_attestors` update itself is validated only for basic well-formedness and definer authorship — there is **no check whatsoever** that removing/replacing an attestor won't orphan holders whose existing balances were validated under the old list: [5](#0-4) [6](#0-5) 

This mirrors the reported bug class precisely: a privileged-but-reachable actor (the asset issuer, one of the explicitly allowed unprivileged-reachable roles) performs a "replace/remove" action on a dependency (the attestor list, analogous to the keeper gauge) without any on-chain guarantee that the dependency isn't currently relied upon by other parties' funds/flows (analogous to `TopUpActionFeeHandler` still pointing at the killed gauge).

### Impact Explanation
Any address that already received a `spender_attested` asset in reliance on attestation by attestor X becomes unable to spend that asset the moment the issuer posts a new `asset_attestors` list that no longer contains X — even though nothing malicious happened to the address itself. `validatePaymentInputsAndOutputs`/`validatePayment` will reject any payment message from that address with "owner address is not attested" / "none of the authors is attested", freezing the funds indefinitely until the issuer restores X (or a current attestor re-attests the address), a step this design gives no guarantee will happen. This is a direct "AA/asset fund freezing" impact matching the accepted-impact bar (funds unable to move), not merely a resource-only or low-severity issue.

### Likelihood Explanation
No special conditions are required beyond the asset issuer posting a completely ordinary `asset_attestors` message — a normal, expected administrative action (e.g., rotating compliance providers, revoking a compromised attestor key). Since `readAsset` always uses only the single latest list with no grace period or backward-compatibility check for already-attested holders, this can happen unintentionally during routine attestor rotation, making the likelihood high whenever an issuer legitimately updates its attestor set while holders still have unspent balances attested by the old set.

### Recommendation
When validating an `asset_attestors` update, or when validating spends, consider one of:
- Allow spend validation to accept attestations from *any* attestor list that was current at the time the attestation was issued (i.e., attestation validity should be evaluated against the attestor list in effect when the attestation unit was posted, not only the very latest list), similar to how definition changes are matched to specific MCIs elsewhere in the codebase.
- Alternatively, require the issuer to keep removed attestors valid for previously-issued attestations for some grace period, or require new attestor-list updates to not invalidate already-spendable outputs without an explicit migration mechanism.

### Proof of Concept
1. Issuer defines asset `A` with `spender_attested: true` and initial attestor list `[Attestor1]`. [5](#0-4) 
2. Attestor1 attests Alice's address; Alice receives a payment of asset `A` and holds it unspent.
3. `storage.readAsset` currently resolves the latest `asset_attestors` unit to the one naming `Attestor1`, so Alice's holdings are fully spendable: [1](#0-0) 
4. Issuer legitimately rotates compliance provider and posts a new `asset_attestors` message naming only `[Attestor2]`, which passes validation because there is no check against currently-attested holders: [5](#0-4) 
5. Alice now tries to spend her asset `A` balance. `loadAssetWithListOfAttestedAuthors` → `filterAttestedAddresses` looks up attestations only from `Attestor2`; Alice's attestation from `Attestor1` doesn't count: [7](#0-6) 
6. `validatePayment` rejects the transaction with "none of the authors is attested" / "owner address is not attested", freezing Alice's funds with no defined recovery path: [3](#0-2)

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

**File:** storage.js (L1977-1991)
```javascript
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
