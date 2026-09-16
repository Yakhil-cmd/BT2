Confirmed: `filterAttestedAddresses` (storage.js:1960-1974) only queries `attestations` joined against `objAsset.arrAttestorAddresses`, which is always the **latest** attestor list read by `readAsset`/`addAttestorsIfNecessary` (storage.js:1917-1946, 1898-1957). This proves that once the asset definer changes the attestor list, all previously valid attestations from the old attestor(s) become irrelevant for future validation — there is no grandfathering of already-attested holders.

### Title
Asset definer can unilaterally change the `spender_attested` attestor list via `asset_attestors` message and permanently freeze holders' existing balances - (File: validation.js, storage.js)

### Summary
An asset can be created with `spender_attested: true`, requiring every author of a payment spending that asset to be attested by one of the asset's designated attestors. The asset definer — a "RESTRICTED" role analogous to the FRAX admin — can later publish a single-authored `asset_attestors` message at any time to replace the attestor list, with no restriction preventing them from doing so after users already hold and are attested for the asset. This instantly and retroactively strips spending rights from any holder who is not attested under the new attestor set, freezing their funds with no recourse, exactly like the FRAX admin arbitrarily raising a redemption fee to 100% and trapping user funds mid-flow.

### Finding Description
`validateAttestorListUpdate` (validation.js:2829-2848) allows the `definer_address` of a `spender_attested` asset to submit an `asset_attestors` message that overwrites the attestor list at will: [1](#0-0) 

The only checks are that the sender is the definer and the new list is well-formed (`checkAttestorList`, validation.js:2850-2864); there is no cooldown, no timelock, no restriction preventing removal of the attestor(s) that previously attested existing holders, and no requirement to preserve any minimum overlap with the prior list.

When validating a payment of this asset, `validatePayment` calls `storage.loadAssetWithListOfAttestedAuthors`, which computes `arrAttestedAddresses` strictly from the **current/latest** attestor list, not the list in effect when the sender was attested: [2](#0-1) [3](#0-2) [4](#0-3) 

`validatePayment` then rejects any spend if the sender is not currently attested: [5](#0-4) 

So the sequence is: (1) definer issues asset with `attestors: [A]`; (2) attestor A attests user Bob, who legitimately receives/holds the asset; (3) definer publishes `asset_attestors` message changing the list to `[B]` (an attestor who will never attest Bob, or who is simply unreachable/non-functional); (4) Bob's previously-valid units are permanently unable to pass `validatePayment` because `arrAttestedAddresses` no longer contains Bob — his balance of this asset is frozen forever, with no way for any node to disagree (it's a deterministic consensus rule), matching the "concrete ... AA fund loss or freezing" acceptance criterion.

### Impact Explanation
This is a direct freezing of user assets caused solely by a unilateral, single-message action of a "RESTRICTED" privileged party (the asset definer), fully analogous to the FRAX admin raising the redemption fee to 100% to trap staked ETH. Holders who legitimately acquired and were previously permitted to spend the asset can be locked out with a single subsequent transaction from the definer, with no cap, delay, or protection in the protocol logic. Any Autonomous Agent (AA) or user relying on continued spendability of a `spender_attested` asset (e.g., private payment chains, AA-held balances) is vulnerable to permanent fund freezing.

### Likelihood Explanation
Likelihood is high for any asset opting into `spender_attested`: the definer only needs to submit one more `asset_attestors` message (validated in validation.js:2033-2042) at any point after issuance — no coordination, multisig, or special privilege beyond being the original definer is required, and the action is entirely legal per the consensus rules.

### Recommendation
Consider requiring that attestor-list updates preserve backward compatibility for already-attested addresses (e.g., grandfather clauses or a timelock/delay before a new list takes effect), or at minimum flag this as an inherent trust assumption of `spender_attested` assets so integrators and AA authors are aware that holding such assets carries an unbounded freezing risk controlled entirely by the asset definer.

### Proof of Concept
1. Definer issues asset X with payload `{spender_attested: true, attestors: ["ATTESTOR_A"], issued_by_definer_only: true, ...}` (validation.js `validateAssetDefinition`, storage.js writer.js:218-235 for persistence of `asset_attestors`).
2. `ATTESTOR_A` posts an `attestation` message for Bob's address; Bob receives asset X in a payment and is fully spendable (`arrAttestedAddresses` includes Bob via `filterAttestedAddresses`, storage.js:1960-1974).
3. Definer submits a single-authored `asset_attestors` message: `{asset: X, attestors: ["ATTESTOR_C"]}` where `ATTESTOR_C` never attests Bob. This passes `validateAttestorListUpdate` (validation.js:2829-2848) because the sender is still the definer and the list is well-formed.
4. `readAsset`/`addAttestorsIfNecessary` (storage.js:1898-1957) now resolves `objAsset.arrAttestorAddresses` to `["ATTESTOR_C"]` only.
5. Any subsequent unit where Bob attempts to spend asset X fails `validatePayment`'s `spender_attested` check (validation.js:2115-2121) because `arrAttestedAddresses` no longer contains Bob — his balance of asset X is permanently frozen.

### Citations

**File:** validation.js (L2115-2121)
```javascript
		if (objAsset.spender_attested){
			if (conf.bLight && objAsset.is_private) // in light clients, we don't have the attestation data but if the asset is public, we trust witnesses to have checked attestations
				return callback("being light, I can't check attestations for private assets"); // TODO: request history
			if (objAsset.arrAttestedAddresses.length === 0)
				return callback("none of the authors is attested");
			if (bIssue && objAsset.arrAttestedAddresses.indexOf(issuer_address) === -1)
				return callback("issuer is not attested");
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
