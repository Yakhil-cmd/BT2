## Title
Asset definer can instantly freeze all existing holders' funds of a `spender_attested` asset by rotating the attestor list - (File: `validation.js`)

### Summary
This is the ocore/Obyte analog of the Swapnet-lite bug in which the market owner could set `numPeriods=0` to instantly and permanently disable a market for everyone, including users who already had funds committed, with no time-delay or recourse. In ocore, the definer of an asset with `spender_attested: true` (an unprivileged "asset issuer" role reachable by any unit poster) can post an `asset_attestors` message at any time to swap out the trusted attestor list. Because the "is spender attested" check is evaluated against the *current* attestor list rather than the list that was valid when the holder acquired the funds, the definer can instantly revoke the ability of every existing holder to spend their already-received balance of the asset, with no grace period and no way for holders to recover funds - exactly the "owner disables the market instantly, trapping already-deposited funds" bug class from the report.

### Finding Description
When an asset is defined with `spender_attested: true`, every payment of that asset (both issuance and transfer) requires that the relevant addresses be attested by one of the asset's current `attestors`: [1](#0-0) 

The list of "current" attestors is not fixed at asset-definition time; the definer can update it at will via an `asset_attestors` message, and this update is validated only for well-formedness (non-empty, valid, sorted addresses) — there is no restriction preventing the definer from replacing the list with attestor addresses that have never attested (and will never attest) any of the addresses that currently hold the asset: [2](#0-1) 

At spend time, `storage.readAsset` always loads the *latest* attestor list for the asset (ordered by level, `LIMIT 1`), not the list that was in effect when the spender received the funds: [3](#0-2) 

`filterAttestedAddresses` then checks whether the spender's address has been attested by one of these *current* attestors: [4](#0-3) 

If a holder was only ever attested by an attestor address that the definer has since removed from the list, `arrAttestedAddresses` becomes empty for that holder, and `validatePayment` rejects any future payment from (or even issuance to) that address: [1](#0-0) 

The same check is enforced again in `validatePaymentInputsAndOutputs`, both for the owning address of inputs being spent and for output addresses receiving the asset: [5](#0-4) [6](#0-5) 

Only the asset's `definer_address` is allowed to post the `asset_attestors` update, and this authorization is the *only* control on the action: [7](#0-6) 

There is no cooldown, no requirement to keep a previously-valid attestor on the list, and no mechanism (analogous to Swapnet-lite's fixed `removeLiquidity`) that lets already-attested holders exit or continue spending their existing balance after the list is rotated.

### Impact Explanation
This lets a single-key asset definer, with one ordinary unit, instantly and permanently freeze the spendable balance of every current holder of a `spender_attested` asset (their tokens become permanently un-spendable, since the holder was attested only under the old, now-discarded, attestor list). This is a direct, unauthorized loss of access to funds for third parties who hold the asset in good faith, with no time-delay warning and no fallback path to recover the frozen balance — mirroring the Swapnet-lite root cause (an owner-controlled parameter change that instantly and irrevocably disables normal operation for existing participants).

### Likelihood Explanation
Any asset issuer that defines a `spender_attested` asset already has the unilateral, single-signature capability to post `asset_attestors` messages at any point after issuance; no special privilege beyond being the original definer is required, and the validation code imposes no safeguards against rotating out attestors that have already attested current holders. This makes exploitation trivial for any malicious or compromised asset definer, and it can also happen unintentionally (e.g., legitimate attestor rotation for compliance reasons breaks existing holders without the definer realizing it revokes previously-issued attestations).

### Recommendation
Consider one or more of the following:
- When checking `spender_attested` at spend time, honor attestations issued under *any* attestor list that was valid for the asset up to the point the funds were received/attested, rather than only the most recent list (i.e., validate the attestation was made by an attestor address that was trusted at the time of the attestation, not necessarily currently trusted).
- Add a time-delay/grace period between an `asset_attestors` update and its effect on already-attested holders, so users have a window to move funds before losing spend eligibility.
- Explicitly document in asset metadata/UX that `spender_attested` assets carry definer risk of retroactive freezing, so wallets can warn holders before they accept such assets.

### Proof of Concept
1. Definer `D` issues asset `X` with `spender_attested: true` and initial `attestors: [A]` (via the `asset` message in `writer.js`, `case "asset"`, inserting into `asset_attestors`) — see [8](#0-7) .
2. Attestor `A` posts an `attestation` message attesting address `H` (holder). `H` receives a payment of asset `X` and can spend it because `filterAttestedAddresses` finds `H` attested by `A` (the then-current attestor).
3. `D` posts an `asset_attestors` message for asset `X` with `attestors: [B]`, where `B` is a fresh address that never attests `H` (see [9](#0-8)  and [10](#0-9) ).
4. `H` attempts to spend their existing balance of asset `X`. `storage.readAsset` now returns the new attestor list `[B]`; `filterAttestedAddresses` finds no attestation of `H` by `B`, so `objAsset.arrAttestedAddresses` is empty and `validatePayment` rejects the unit with `"none of the authors is attested"` (`validation.js:2115-2122`).
5. `H`'s already-held balance of asset `X` is now permanently unspendable, with no way to regain attestation unless `D` voluntarily restores `A` to the list — which `D` fully controls and has no obligation to do.

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

**File:** validation.js (L2504-2507)
```javascript
							if (objAsset && objAsset.auto_destroy && owner_address === objAsset.definer_address)
								return cb("this output was destroyed by sending it to definer address");
							if (objAsset && objAsset.spender_attested && objAsset.arrAttestedAddresses.indexOf(owner_address) === -1)
								return cb("owner address is not attested");
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

**File:** writer.js (L218-235)
```javascript
						case "asset":
							var asset = message.payload;
							conn.addQuery(arrQueries, "INSERT INTO assets (unit, message_index, \n\
								cap, is_private, is_transferrable, auto_destroy, fixed_denominations, \n\
								issued_by_definer_only, cosigned_by_definer, spender_attested, \n\
								issue_condition, transfer_condition) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", 
								[objUnit.unit, i, 
								asset.cap, asset.is_private?1:0, asset.is_transferrable?1:0, asset.auto_destroy?1:0, asset.fixed_denominations?1:0, 
								asset.issued_by_definer_only?1:0, asset.cosigned_by_definer?1:0, asset.spender_attested?1:0, 
								asset.issue_condition ? JSON.stringify(asset.issue_condition) : null,
								asset.transfer_condition ? JSON.stringify(asset.transfer_condition) : null]);
							if (asset.attestors){
								for (var j=0; j<asset.attestors.length; j++){
									conn.addQuery(arrQueries, 
										"INSERT INTO asset_attestors (unit, message_index, asset, attestor_address) VALUES(?,?,?,?)",
										[objUnit.unit, i, objUnit.unit, asset.attestors[j]]);
								}
							}
```

**File:** writer.js (L244-251)
```javascript
						case "asset_attestors":
							var asset_attestors = message.payload;
							for (var j=0; j<asset_attestors.attestors.length; j++){
								conn.addQuery(arrQueries, 
									"INSERT INTO asset_attestors (unit, message_index, asset, attestor_address) VALUES(?,?,?,?)",
									[objUnit.unit, i, asset_attestors.asset, asset_attestors.attestors[j]]);
							}
							break;
```
