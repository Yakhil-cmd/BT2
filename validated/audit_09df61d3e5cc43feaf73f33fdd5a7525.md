## Analysis

The OtterSec report describes a class of bug where a semi-trusted manager can mutate a shared configuration value (`cooldown_period_sec`) that gates a state transition (unstake), and the check is re-evaluated at the *later* action using the *current* mutated value instead of the value that applied when the asset was locked. This lets the manager trap funds and later unilaterally release them to steal them.

The closest reachable analog in `ocore` is the `spender_attested` asset mechanism, where the asset **issuer/definer** (an explicitly in-scope actor) can freely update the attestor list at any time, and every subsequent spend of already-held coins is validated against the *latest* attestor list rather than the list in effect when the coins were acquired.

### Title
Asset issuer can freeze holders' funds at will by mutating the attestor list checked at spend-time rather than acquisition-time - (File: `validation.js`, `storage.js`)

### Summary
For a `spender_attested` asset, the definer publishes an initial attestor list and can subsequently update it via an `asset_attestors` message at any time, with no restriction tying it to the state that existed when other users acquired the asset. Every later payment (including ordinary transfers of previously-received/held coins, not just new issuance) is validated against the attestor list that is current as of the payment's `last_ball_mci`, not the list that applied when the holder received the coins.

### Finding Description
`validateAttestorListUpdate` allows the asset's `definer_address` to replace the attestor list for a `spender_attested` asset at any time, as long as it's the sole author: [1](#0-0) 

When a payment of that asset is later validated, the currently-applicable attestor list is loaded fresh via `readAsset`/`loadAssetWithListOfAttestedAuthors`, which explicitly selects "the latest list of attestors" relative to the payment's own `last_ball_mci`: [2](#0-1) [3](#0-2) 

`validatePayment` then requires that at least one author of the spending unit is attested under this *current* list, and specifically that the issuer is attested for issuance — but critically this same gate applies to ordinary transfers of coins the holder already owns: [4](#0-3) 

The per-input ownership/attestation check is likewise re-evaluated at spend time against the current list: [5](#0-4) 

And even the destination (output) addresses of a transfer must be attested under the current list at the time of the transfer, not at the time the sender received the coins: [6](#0-5) 

This is structurally identical to the reported bug class: a value that gates a later state transition (`cooldown_period_sec` in the report, the attestor list here) is controlled by a role that is trusted at *issuance* time but is re-read fresh at a *different, later* time (spend time) rather than being pinned to the state that existed when the asset/lock was established. Because the value is mutable and freely rewritable by that role, the role can trap other users' already-held funds after the fact, exactly as the farm manager could trap already-staked NFTs by raising `cooldown_period_sec` after staking.

### Impact Explanation
The asset definer can, at any point after users have legitimately acquired a `spender_attested` asset (via issuance or transfer), publish an `asset_attestors` update that removes some or all attestors (or removes attestation specifically for the addresses that hold balances). Because the check is applied on every subsequent spend attempt using the then-current list, this immediately and permanently blocks those holders from moving their existing balances — a fund-freezing condition triggered unilaterally by the issuer after the fact, with no mechanism for holders to prove attestation as of the time they received the funds. This matches the "AA fund loss or freezing" impact category, generalized to any holder of the asset.

### Likelihood Explanation
High. The asset issuer is one of the explicitly allowed reachable actors, and the mechanism requires only a single, ordinary `asset_attestors` message that passes existing validation (`validateAttestorListUpdate`/`checkAttestorList`) — no special privileges beyond being the asset's own definer, which any issuer possesses by design.

### Recommendation
Decouple the attestation requirement for spending previously-received coins from the *current* attestor list. Options:
- Snapshot/pin the attestor list (or a definer-signed commitment to it) at the moment of receipt, and validate later spends against that pinned snapshot rather than the always-latest list.
- Require that attestation checks for existing holders use the attestor list that was current at the `main_chain_index` when the funds were received (input's source unit), not the spending unit's `last_ball_mci`, mirroring how issuance already ties `issuer_address` attestation only at issue time.
- At minimum, document explicitly (and warn wallet UIs) that `spender_attested` grants the definer ongoing, retroactive power to freeze existing holders' funds, so this is understood as intended trust rather than a silent hazard.

### Proof of Concept
1. Definer `D` creates asset `A` with `spender_attested: true` and initial `attestors: [X]`. [7](#0-6) 
2. Attestor `X` attests user `U`'s address. `D` issues (or `U` receives via transfer) balance of `A` to `U`; this succeeds because `U` is attested by `X`, satisfying the check in `validatePayment`. [4](#0-3) 
3. `D` posts an `asset_attestors` message for asset `A` naming a new attestor list that excludes `X` (or any attestor covering `U`). [1](#0-0) 
4. `U` later tries to spend/transfer the previously-received balance of `A`. `readAsset`/`loadAssetWithListOfAttestedAuthors` picks up the *new* attestor list (latest before `last_ball_mci`), `U` is no longer attested, and the payment is rejected with "owner address is not attested" / "none of the authors is attested". [2](#0-1) [5](#0-4) 
5. `U`'s balance of `A` is now permanently frozen, unilaterally, by an action taken entirely by `D` after `U` already held the funds.

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

**File:** validation.js (L2725-2750)
```javascript
function validateAssetDefinition(conn, payload, objUnit, objValidationState, callback){
	if (objUnit.authors.length !== 1)
		return callback("asset definition must be single-authored");
	if (!isNonemptyObject(payload))
		return callback("asset definition must be a non-empty object");
	if (hasFieldsExcept(payload, ["cap", "is_private", "is_transferrable", "auto_destroy", "fixed_denominations", "issued_by_definer_only", "cosigned_by_definer", "spender_attested", "issue_condition", "transfer_condition", "attestors", "denominations"]))
		return callback("unknown fields in asset definition");
	if (typeof payload.is_private !== "boolean" || typeof payload.is_transferrable !== "boolean" || typeof payload.auto_destroy !== "boolean" || typeof payload.fixed_denominations !== "boolean" || typeof payload.issued_by_definer_only !== "boolean" || typeof payload.cosigned_by_definer !== "boolean" || typeof payload.spender_attested !== "boolean")
		return callback("some required fields in asset definition are missing");

	if ("cap" in payload && !(isPositiveInteger(payload.cap) && payload.cap <= constants.MAX_CAP))
		return callback("invalid cap");

	if (objValidationState.bAA) {
		if (payload.cosigned_by_definer !== false)
			return callback("cosigned_by_definer must be false because AAs can't cosign");
		if (payload.issued_by_definer_only === true && (payload.is_private !== false || payload.fixed_denominations !== false))
			return callback("assets issued by AA definer cannot be private or fixed denominations");
	}

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
