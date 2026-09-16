This confirms the mechanics. Now let's finalize the analysis based on what's found: `spender_attested` assets track only the **latest** attestor list (`storage.js` `readAsset`/`addAttestorsIfNecessary`, which does `ORDER BY level DESC LIMIT 1`), and any coin holder must currently be in `arrAttestedAddresses` to spend at all — regardless of whether they were validly attested when they received the funds.

### Title
Asset definer can silently freeze existing holders' funds by updating the attestor list of a `spender_attested` asset - (File: `validation.js`, `storage.js`)

### Summary
For `spender_attested` assets, spending an existing output requires the owner's address to be in the **current** (latest) attestor list, not the list that was valid when the coins were received. The asset definer can publish an `asset_attestors` message at any time, unilaterally replacing the attestor list, which instantly makes any previously-attested holder unable to spend or transfer coins they legitimately hold, freezing their funds — directly analogous to the JOJO bug where delisting a reserve broke withdrawal and safety checks for users who already held that collateral.

### Finding Description
When an asset is created with `spender_attested: true`, the definer must subsequently publish attestor lists via the `asset` message and/or `asset_attestors` messages [1](#0-0) . `storage.readAsset` resolves the attestor list to use by picking only the **single latest** `asset_attestors` unit for the asset, ordered by level/rowid, and discards any earlier list entirely: [2](#0-1) .

Any user's ability to move an already-owned output of that asset is gated on membership in this current list. Both the divisible-payment transfer path and the private fixed-denomination transfer path enforce this: [3](#0-2)  and [4](#0-3) . The output-address check on the sending side (making sure new recipients are attested) is likewise based on the current list: [5](#0-4) .

The attestor-list update itself is validated only by requiring single-authorship and that the sender is the asset's definer — there is no restriction preventing the definer from dropping previously-included attestors or shrinking the list to addresses that exclude current legitimate holders: [6](#0-5) , with the list content check only verifying sort order/format, not continuity with the prior list: [7](#0-6) .

Consequently, a user who received/held asset coins while validly attested under attestor A can find that, after the definer replaces the attestor list with attestor B (removing A), `arrAttestedAddresses` computed via `filterAttestedAddresses`/`loadAssetWithListOfAttestedAuthors` no longer includes them [8](#0-7) , and any subsequent payment message spending their existing outputs is rejected with `"owner address is not attested"`.

### Impact Explanation
This is analogous to the JOJO finding: a privileged party (definer) makes a configuration change (updating the attestor whitelist) that is intended to affect **future** attestation validity, but the code applies it retroactively to **already-held** funds by using only the latest list for spend checks. This can permanently freeze a legitimate holder's coins with no way to satisfy the current attestor requirement (they must convince a new attestor, i.e., a third party, to attest them — outside their control), matching the "delisting breaks withdrawal for existing users" bug class. This affects asset issuance and transfer conditions reachable by any unprivileged unit poster who happens to hold coins of such an asset, and the fund freezing is caused entirely by the definer's routine (non-malicious) whitelist rotation, not by an attacker.

### Likelihood Explanation
`spender_attested` assets and `asset_attestors` updates are a documented, first-class feature (used e.g. for KYC/whitelisted assets), and updating the attestor list is an expected periodic administrative action (e.g., rotating a compromised or discontinued attestor, adding a new KYC provider). Because the code keeps no historical snapshot of the list at the time each output was created/spent, this freezing occurs under normal, foreseeable asset-management operations rather than requiring an edge case or exploit, making it a realistic occurrence for any actively-managed `spender_attested` asset.

### Recommendation
Preserve spendability for holders who were attested at the time they received the coins, e.g., by recording (or re-validating against) the attestor list in effect when the output was created rather than only the current one, or by requiring attestor-list updates to be additive (never revoking previously valid attestors) unless holders are given an explicit migration path. At minimum, document/guard so that removing an attestor cannot retroactively block spending of outputs owned by addresses attested under a previous, still-honoured list.

### Proof of Concept
1. Definer creates asset `X` with `spender_attested: true` and initial `attestors: [A]` [9](#0-8) .
2. Attestor `A` attests address `H`; `H` receives a payment output of asset `X` (validated fine since `H` is in `arrAttestedAddresses`) [10](#0-9) .
3. Definer posts an `asset_attestors` message for asset `X` with `attestors: [B]`, dropping `A` [6](#0-5) .
4. `storage.readAsset` now returns only `[B]` as `arrAttestorAddresses`, since it selects just the latest `asset_attestors` unit [11](#0-10) .
5. `H`, still only attested by `A` (not `B`), tries to spend the existing output. `filterAttestedAddresses` no longer returns `H` [12](#0-11) , and the payment is rejected with `"owner address is not attested"` [3](#0-2) , permanently freezing `H`'s coins unless `B` also attests `H`, which `H` cannot compel.

### Citations

**File:** initial-db/byteball-mysql.sql (L248-248)
```sql
	spender_attested TINYINT NOT NULL, -- must subsequently publish and update the list of trusted attestors
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

**File:** validation.js (L2745-2751)
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
