### Title
Asset definer can silently update the trusted attestor list, retroactively changing spending authorization for a `spender_attested` asset - (File: validation.js)

### Summary
The Phuture report identifies that `addAsset` can be called repeatedly by the trusted Asset Manager to silently overwrite a critical, previously-set security parameter (`assetAggregator`), changing behavior relied upon by everyone using the asset, with no restriction preventing re-registration. The equivalent pattern in `ocore` is `validateAttestorListUpdate`, which lets an asset's `definer_address` post an unlimited number of `asset_attestors` messages that overwrite which attestor addresses are trusted to authorize spending of a `spender_attested` asset, with no restriction against redefining this security-critical list at any time.

### Finding Description
When an asset is created with `spender_attested: true`, an initial list of `attestors` is committed at issuance (`validation.js`, asset definition validation around line 2747, and `writer.js:229-235` inserting into `asset_attestors`). Thereafter, the same `definer_address` can post an `asset_attestors` app message at any time to redefine that list via `validateAttestorListUpdate`: [1](#0-0) 

The only checks performed are that the message is single-authored, that the asset requires attestors, that the sender is the current `definer_address`, and that the new list is well-formed (`checkAttestorList`): [2](#0-1) 

There is no restriction limiting this to a one-time initialization, no cooldown, and no requirement that the change be justified or bounded — the definer can call it repeatedly with entirely different attestor sets, exactly analogous to `addAsset` being callable repeatedly with a different `assetAggregator`. The validation only prevents **more than one such update per unit** (`validation.js:2036-2040`), not more than one update overall: [3](#0-2) 

This new attestor list is then used going forward for all spending validation of the asset. `readAsset` always fetches the *latest* attestor list up to `last_ball_mci`: [4](#0-3) 

And payment validation for the asset determines who is allowed to spend based on whether the payer's address has been attested to by one of the *currently* trusted attestors: [5](#0-4) [6](#0-5) 

### Impact Explanation
Because `readAsset`/`loadAssetWithListOfAttestedAuthors` always uses the current (latest confirmed) attestor list rather than the list in effect when a holder acquired coins, a single definer-controlled update can:
- **Freeze existing legitimate holders' funds**: removing a previously trusted attestor causes any address that was attested only by that attestor to lose the ability to spend outputs of the asset it already legitimately holds, since `validatePayment` requires `objAsset.arrAttestedAddresses.indexOf(issuer_address) !== -1` (and analogous checks for non-issue transfers) using the now-updated list.
- **Enable unauthorized spending / asset takeover**: swapping in a new, definer-controlled attestor address lets the definer immediately attest addresses of their choosing, granting them the ability to satisfy `spender_attested` checks for spending outputs that require attestation, subverting the trust assumptions that other participants placed in the original attestor set when accepting the asset.

This matches the accepted centralization/config-mutability bug class from the reference report: a single privileged asset-controlling actor can retroactively alter security-critical parameters that all downstream holders and consumers of the asset rely upon, causing fund freezing or unauthorized spending — impacts explicitly in scope (AA/asset fund loss or freezing, unauthorized spending).

### Likelihood Explanation
The `asset_attestors` message is a first-class oscript/DAG feature reachable by any ordinary user acting as an asset issuer/definer — no special network privilege is required, matching the "asset issuer" actor allowed by scope. Any asset creator who sets `spender_attested: true` automatically obtains this unrestricted, repeatable power over the attestor list for as long as the asset exists, so the precondition (creating a `spender_attested` asset) is trivial and entirely within a single unprivileged unit poster's control.

### Recommendation
- Consider bounding or governing changes to the attestor list after initial issuance, e.g., requiring a cooldown/timelock before an attestor-list change takes effect, or making changes only additive (never removing an attestor that has produced live attestations for spendable outputs) unless outputs attested under the old list are grandfathered.
- Alternatively, evaluate spending eligibility against the attestor list that was in effect at the time the specific output/attestation was made (similar to how `address_definition_changes` bounds re-use of an old definition to before the change), rather than always the latest list, to prevent retroactive freezing or re-authorization of spending rights.
- At minimum, document this centralization risk explicitly so wallets/users understand that trust in a `spender_attested` asset extends to trusting the definer indefinitely to not maliciously alter the attestor list.

### Proof of Concept
1. Asset issuer creates asset `X` with `spender_attested: true` and `attestors: [A]`. Holder `H` obtains asset `X` after being attested by attestor `A` (attestation posted via app `attestation`, recorded in `attestations` table).
2. `H` holds valid, spendable `X` outputs, since `filterAttestedAddresses` finds `H` attested by `A` in the current list.
3. Asset definer posts a new `asset_attestors` message for asset `X` with `attestors: [B]` where `B` is controlled by the definer (validated and accepted per `validateAttestorListUpdate`, since only single-update-per-unit is checked, not lifetime).
4. `readAsset` now returns `arrAttestorAddresses = [B]`; `H`'s prior attestation by `A` no longer counts, so `H`'s existing `X` balance becomes unspendable (`validatePayment` rejects `H` since `arrAttestedAddresses` from `filterAttestedAddresses` no longer includes `H`) — funds are frozen.
5. Conversely, the definer can have `B` self-attest an address they control and immediately gain the ability to satisfy spender-attestation requirements for the asset going forward, without any holders' consent.

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
