## Analog Found

### Title
Asset definer can instantly invalidate all existing spender attestations by replacing the attestor list, freezing holders' funds with no validation of prior state - ([File: validation.js])

### Summary
The Sherlock report describes `Controller.updateCollateral()` swapping a critical system reference (the collateral contract address) without validating that no funds/positions are tied to the old reference, letting the privileged party silently orphan user state and letting attackers race the update. The analogous unprivileged-reachable pattern in ocore is the `asset_attestors` message, which lets an asset's definer replace the entire trusted-attestor list for a `spender_attested` asset at any time, with no check on whether users currently hold balances of that asset that depend on attestations issued under the previous list.

### Finding Description
When an asset is created with `spender_attested: true`, every payment of that asset requires the sender/issuer to be attested by one of the asset's currently-recognized attestors [1](#0-0) . The attestor list itself can be changed at any time via an `asset_attestors` message, validated by `validateAttestorListUpdate`, which only checks that the message is single-authored, well-formed, and sent by the asset's definer — it does not check the current holders of the asset or their attestation state before allowing the switch [2](#0-1) .

When resolving which attestors are authoritative, `storage.readAsset()`'s `addAttestorsIfNecessary()` looks up only the single **latest** stable `asset_attestors` unit for the asset and uses that list exclusively — it discards all previously valid attestor lists and any attestations issued under them the moment a newer list stabilizes [3](#0-2) . `filterAttestedAddresses()` then only recognizes attestations from `arrAttestorAddresses`, i.e. the new list [4](#0-3) .

This mirrors the report's root cause exactly: a privileged party (asset definer / Controller owner) can swap out a trusted reference (attestor list / collateral contract) with zero validation that existing, otherwise-legitimate holdings/positions created against the old reference remain honored.

### Impact Explanation
Any address holding units of the `spender_attested` asset whose only attestation came from an attestor removed in the new list instantly becomes unable to spend that asset: `validatePayment` will reject the payment with "none of the authors is attested" or "issuer is not attested" [1](#0-0) , and outputs will similarly fail the "some output addresses are not attested" check on transfer [5](#0-4) . This permanently freezes the affected users' funds with no recourse (unless the definer restores or extends the list), exactly analogous to the reported impact of users' collateral being "ignored" after an unchecked reference swap.

### Likelihood Explanation
This requires no special access beyond being the asset's definer — a role any ordinary unprivileged unit poster can assume simply by creating an asset with `spender_attested: true` (via `validateAssetDefinition` / `checkAttestorList`) [6](#0-5) , then later posting a single `asset_attestors` unit. Any user relying on such an asset (e.g., a stablecoin gated by KYC attestors) is exposed the moment the definer rotates attestors, with no protocol-level safeguard requiring outstanding balances to be reconciled or migrated first.

### Recommendation
Before allowing an `asset_attestors` update to take effect, require either (a) that the update be additive-only (new attestors can be added, but removing an attestor doesn't retroactively invalidate attestations already issued and currently backing a live balance), or (b) that the asset supports a migration/grace mechanism so that existing attested balances can be spent (e.g., to the definer or to a designated unwind address) before the old attestor list is fully deprecated. At minimum, document this as an explicit trust assumption of `spender_attested` assets so wallets/users can evaluate the definer's ability to unilaterally freeze funds.

### Proof of Concept
1. Definer issues asset `X` with `spender_attested: true` and `attestors: [A1]` [7](#0-6) .
2. Attestor `A1` attests address `U`; `U` receives and holds a payment of asset `X`.
3. Definer posts `asset_attestors` message changing the list to `[A2]` (`A1` removed) [8](#0-7) ; this passes `validateAttestorListUpdate` since it only checks definer authorship and list format [2](#0-1) .
4. Once this unit stabilizes, `readAsset` resolves attestors to `[A2]` only [9](#0-8) .
5. `U` attempts to spend their previously-received `X` balance; `filterAttestedAddresses` no longer includes `U` (attested only by `A1`), so `validatePayment`/`validatePaymentInputsAndOutputs` reject the transaction [1](#0-0) [5](#0-4) , permanently freezing `U`'s funds.

### Citations

**File:** validation.js (L2033-2042)
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
			break;
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

**File:** validation.js (L2745-2748)
```javascript
	// attestors
	var err;
	if ( payload.spender_attested && (err=checkAttestorList(payload.attestors)) )
		return callback(err);
```

**File:** validation.js (L2827-2864)
```javascript
}

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
