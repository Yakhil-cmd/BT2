### Title
Asset definer can unilaterally change the spender-attestation (KYC) requirement at any time, retroactively freezing legitimate holders' funds - ([File: validation.js])

### Summary
Ocore assets can be created with `spender_attested: true`, which requires payment senders/receivers of that asset to be attested by one of a defined set of attestor addresses. Unlike most other asset properties (`is_private`, `is_transferrable`, `cap`, etc.) which are fixed forever at issuance, the *list of accepted attestors* for such an asset is not fixed — the asset definer can post a new `asset_attestors` message at any time to replace it, exactly analogous to the OpenQ bug where the bounty issuer could toggle `kycRequired` after users had already started working under the original rules.

### Finding Description
When an asset is defined with `spender_attested: true`, its initial attestor list is set via the `attestors` field in the `asset` message [1](#0-0) . However, the definer can subsequently overwrite this list with a fresh `asset_attestors` message, validated only by:
```
if (objUnit.authors[0].address !== objAsset.definer_address)
    return callback("attestor list can be edited only by definer");
``` [2](#0-1)  There is no restriction on when this can happen, how often, or any requirement to preserve previously trusted attestors — the definer has complete, standing authority to redefine who counts as a valid attestor for the asset, indefinitely after issuance, just as the OpenQ bounty owner could redefine KYC/invoice/document requirements after work had begun.

Crucially, attestation checks are always evaluated against the *current* (as of `last_ball_mci`) attestor list, not the list that was in effect when a user acquired the asset or was originally attested. `filterAttestedAddresses` looks up the *latest* stable `asset_attestors` list before deciding whether an address's attestation counts [3](#0-2) [4](#0-3) , and this is what gates every subsequent transfer or issue of the asset in `validatePayment`/`validatePaymentInputsAndOutputs`: [5](#0-4) [6](#0-5) .

Consequently:
- A holder who received/held the asset while attested by attestor A can be locked out of spending it the moment the definer swaps the attestor list to attestor B (who has not attested them), because `arrAttestedAddresses` no longer contains their address.
- Conversely, the definer can add a colluding attestor at will and immediately grant itself or associates the ability to move funds that were previously gated behind a trusted KYC/attestation process, undermining the guarantee that participants relied on when engaging with the asset.

### Impact Explanation
This is a fund-freezing / trust-bypass issue for any asset that relies on `spender_attested`. Legitimate holders can have their funds frozen (unable to transfer or receive) purely due to a definer-controlled, retroactive rule change, with no on-chain safeguard, cooldown, or grandfathering of existing attestations. This matches the "AA fund loss or freezing" acceptance criterion, since AAs and users alike interact with such assets under an assumption of fixed rules, and the definer can weaponize the requirement change against any counterparty at any time — the same unfairness pattern as the reported OpenQ issue where issuers changed KYC/invoice requirements to disadvantage participants after they had already committed.

### Likelihood Explanation
Any asset issuer choosing `spender_attested: true` (a supported, first-class asset feature) already has unilateral control of the attestor list by design; no special permissions or attack chain are required beyond simply posting an `asset_attestors` message. Likelihood is therefore high for any asset that uses spender attestation and where the definer is not fully trusted (or changes incentives), which is a plausible and realistic usage pattern in ocore/AA-based token ecosystems.

### Recommendation
Consider one or more of:
- Making the attestor list immutable at asset definition (require a new asset if attestation policy changes), mirroring the "immutability" recommendation from the reference report.
- Grandfathering existing attestations: allow spends by addresses that were validly attested under *any* historical attestor list that was active when their attestation was granted, rather than only the current list.
- Adding a timelock/delay before a new attestor list takes effect, so participants have advance notice and time to react before the requirement changes.

### Proof of Concept
1. Definer issues asset `X` with `spender_attested: true` and initial `attestors: [A]`.
2. Attestor `A` attests user `U`'s address via an `attestation` message.
3. `U` receives/holds units of asset `X`, valid because `U` is in `objAsset.arrAttestedAddresses` per `filterAttestedAddresses`.
4. Definer posts an `asset_attestors` message for asset `X` with a new list `[B]`, which is accepted per `validateAttestorListUpdate` (only check is `author == definer_address`) [2](#0-1) .
5. `U` (never attested by `B`) attempts to spend/transfer asset `X`. `validatePayment` calls `loadAssetWithListOfAttestedAuthors` → `filterAttestedAddresses`, which now only recognizes attestations from `B`; `U`'s address is absent from `arrAttestedAddresses`, causing `"issuer is not attested"` / `"some output addresses are not attested"` validation failures [7](#0-6) [8](#0-7) .
6. `U`'s previously valid, unspent asset holdings are now frozen solely due to the definer's unilateral, retroactive change to the attestation requirement.

### Citations

**File:** validation.js (L2109-2122)
```javascript
			if (objAsset.issued_by_definer_only && issuer_address !== objAsset.definer_address)
				return callback("only definer can issue this asset");
		}
		if (objAsset.cosigned_by_definer && arrAuthorAddresses.indexOf(objAsset.definer_address) === -1)
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

**File:** validation.js (L2630-2642)
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
					},
```

**File:** validation.js (L2745-2750)
```javascript
	// attestors
	var err;
	if ( payload.spender_attested && (err=checkAttestorList(payload.attestors)) )
		return callback(err);
	if (!payload.spender_attested && "attestors" in payload && (objValidationState.last_ball_mci >= constants.pemCurvesFixMci || !objValidationState.hasBall && storage.getMinRetrievableMci() >= constants.pemCurvesFixMci))
		return callback("attestors should not be defined when spender_attested is false");
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

**File:** storage.js (L1898-1946)
```javascript
function readAsset(conn, asset, last_ball_mci, bAcceptUnconfirmedAA, handleAsset) {
	if (arguments.length === 4) {
		handleAsset = bAcceptUnconfirmedAA;
		bAcceptUnconfirmedAA = false;
	}
	if (last_ball_mci === null){
		if (conf.bLight)
			last_ball_mci = MAX_INT32;
		else
			return readLastStableMcIndex(conn, function(last_stable_mci){
				readAsset(conn, asset, last_stable_mci, bAcceptUnconfirmedAA, handleAsset);
			});
	}
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
