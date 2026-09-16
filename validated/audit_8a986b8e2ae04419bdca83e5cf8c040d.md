### Title
Asset definer can instantly revoke/replace the attestor list with `asset_attestors`, freezing existing holders' funds with no warning or grace period - ([File: validation.js])

### Summary
For any `spender_attested` asset, the asset definer (which can be an ordinary asset issuer, or an AA acting as its own definer) can post an `asset_attestors` message at any time to completely replace the list of trusted attestors. This change takes effect for the very next stable unit, with no event, no timelock, and no opportunity for existing token holders to react. Holders whose payments depended on being attested under the old list can immediately lose the ability to spend the asset they are holding, mirroring the "admin removes reward eligibility with no warning" bug class from the original report.

### Finding Description
`validateAttestorListUpdate` only checks that the message is single-authored, that the asset requires attestors, and that the sender is the asset's `definer_address`; it imposes no restriction on how the new list relates to the old one and no delay before the new list becomes effective: [1](#0-0) 

The only content constraints are enforced by `checkAttestorList`, which just validates address format, count limit, and sort order — it does not forbid emptying out or completely swapping the attestor set: [2](#0-1) 

Once such a unit becomes stable, `storage.readAsset` picks the *latest* attestor-list-update unit as the authoritative list, using the most recent unit by level with `main_chain_index<=last_ball_mci`, i.e. the new list is used immediately for every subsequent validation of the asset, with no legacy grace window: [3](#0-2) 

Payment validation for a `spender_attested` asset requires all authors of a payment (spenders) to be attested under the *current* attestor list, via `filterAttestedAddresses`/`loadAssetWithListOfAttestedAuthors`; if the authors are not attested under the new list, the payment is rejected outright: [4](#0-3) [5](#0-4) 

This means a definer (which the protocol explicitly allows to be an AA, per `aa_validation.js`'s handling of the `asset_attestors` app for AA-issued assets) can trigger a full replacement of the attestor list as an ordinary response message, instantly and irrevocably cutting off previously-attested holders from being able to move their existing balances of that asset — exactly the same failure mode as the reported issue: a privileged party silently removes an eligibility condition users were relying on, with zero warning and zero time to react. [6](#0-5) 

### Impact Explanation
Holders of a `spender_attested` asset who already hold balances and were relying on being on the attestor list lose the ability to spend/transfer their tokens the moment the attestor-list-update unit stabilizes. There is no on-chain signal (no dedicated notification), no cooldown, and no partial/staged rollout — the change is atomic and immediate at stabilization. This constitutes a fund-freezing condition for legitimate, previously-compliant holders, directly caused by a single message the definer (which can itself be an AA) can post at will.

### Likelihood Explanation
Any asset created with `spender_attested: true` (a supported, documented asset feature) is exposed. The definer only needs to author one `asset_attestors` message — no special coordination or race condition is required, and this is a completely legitimate, always-available protocol feature, not a bug requiring an edge case to trigger.

### Recommendation
Consider requiring attestor-list changes to only add/extend, or to enforce a minimum look-back/grace period during which the previous attestor list also remains valid for existing holders' outgoing payments, similar to how `address_definition_changes` require the change to be seen/stable before taking effect for signature verification. At minimum, document this risk clearly for asset designers/AA authors relying on `spender_attested`, since holders currently have no signal that their spending rights can vanish instantly.

### Proof of Concept
1. An asset (or an AA acting as definer) issues an asset with `spender_attested: true` and attestor list `[A]`.
2. Attestor `A` attests address `U`; `U` receives/holds a balance of the asset. `U`'s payments validate fine because `filterAttestedAddresses` finds `U` attested under attestor `A` (`storage.js:1960-1974`, `validation.js:2115-2122`).
3. The definer posts an `asset_attestors` message changing the attestor list to `[B]` (validated only by `validateAttestorListUpdate`/`checkAttestorList`, `validation.js:2829-2864`), with no delay and no notice to `U`.
4. Once that unit stabilizes, `storage.readAsset` picks this new list as authoritative (`storage.js:1917-1946`).
5. `U` attempts to spend the tokens acquired in step 2. Because `U` is not attested by `B`, `filterAttestedAddresses` returns an empty set, and `validatePayment` rejects the payment with "none of the authors is attested" (`validation.js:2115-2122`) — `U`'s existing balance is now frozen with no warning that this would happen.

### Citations

**File:** validation.js (L2113-2122)
```javascript
			return callback("must be cosigned by definer");
		
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

**File:** aa_validation.js (L338-353)
```javascript
				case 'asset_attestors':
					if (hasFieldsExcept(payload, ['asset', 'attestors', 'init']))
						return cb2("foreign fields in attestor list update");
					if (!isNonemptyString(payload.asset))
						return cb2("asset is not a string");
					var asset_formula = getFormula(payload.asset);
					if (asset_formula !== null) {
					}
					else if (!isValidBase64(payload.asset, constants.HASH_LENGTH))
						return cb2("bad asset in asset_attestors: " + payload.asset);
					validateFieldWrappedInCases(payload, 'attestors', validateAttestors, function (err) {
						if (err)
							return cb2(err);
						cb2();
					});
					break;
```
