Confirmed: `readAsset` (storage.js:1898-1957) always uses only the **single latest** `asset_attestors` unit for a `spender_attested` asset — line 1924-1930 selects `unit FROM asset_attestors ... ORDER BY level DESC LIMIT 1`, and line 1934-1940 loads attestor addresses only from that latest unit. There is no fallback to older lists. `filterAttestedAddresses` (storage.js:1960-1974) only checks `attestor_address IN(?)` against `objAsset.arrAttestorAddresses`, i.e. the current list. `validateAttestorListUpdate` (validation.js:2829-2848) lets the asset **definer** freely replace the entire attestor set with any new list via the `asset_attestors` message, with no requirement to retain any previous attestor or preserve continuity, and no minimum-liveness/rollback rule enforced by `checkAttestorList` (validation.js:2850-2864) beyond sorting/format checks.

<br>

### Title
Asset issuer can permanently freeze all holders of a `spender_attested` asset by replacing the attestor list - (File: `validation.js`, `storage.js`)

### Summary
For any asset with `spender_attested: true`, spending is gated on the payer/output address being attested by one of the asset's **currently registered** attestors, determined solely from the single most recent `asset_attestors` unit. The asset definer can post a new `asset_attestors` message that completely replaces the attestor set (e.g., with an attestor who never attests anyone, or with attestors that will never attest existing holders). Because the check only consults the latest list, every holder previously attested under the old list instantly and permanently loses the ability to transfer or spend their existing holdings of that asset, mirroring the reported bug class where removing the sole registered depository/attestor locks out user redemption.

### Finding Description
`readAsset` in [1](#0-0)  looks up attestors for a `spender_attested` asset by finding the single latest `asset_attestors` unit (`ORDER BY level DESC LIMIT 1`) and loading only that unit's `attestor_address` rows into `objAsset.arrAttestorAddresses`. There is no aggregation of historically valid attestors — only the newest list counts.

`filterAttestedAddresses` in [2](#0-1)  then checks whether any address has an `attestations` row whose `attestor_address` is `IN` the current `arrAttestorAddresses`. If an address was attested only by an attestor who is no longer on the current list, it is excluded from `arrAttestedAddresses`.

`validatePayment` in [3](#0-2)  then rejects the payment with `"none of the authors is attested"` whenever `arrAttestedAddresses.length === 0`.

The attestor list itself is fully replaceable by the asset definer with essentially no constraint: `validateAttestorListUpdate` in [4](#0-3)  only requires the message be single-authored by `objAsset.definer_address` and that `checkAttestorList` pass, which merely checks the format/sorting of the new list ( [5](#0-4) ). Nothing prevents the definer from submitting a disjoint new attestor set, and nothing requires the new attestors to ever attest previously-attested holders.

Because this is a normal, permissionless-to-validate protocol message (any definer can send it, and it validates and commits like any other unit as shown in `writer.js` [6](#0-5) ), an asset issuer — malicious or simply careless (e.g., migrating to a new attestor/KYC provider) — can strand all existing token holders who relied on the old attestor's attestation, with the assets permanently unspendable unless the old attestor (who has no further protocol obligation) or a new compatible attestor reissues attestations for every affected holder.

### Impact Explanation
Any holder of a `spender_attested` asset (a legitimate, commonly used feature for compliance/whitelisting assets) can have their funds permanently frozen the moment the definer swaps the attestor list, with no way to recover on-chain short of the definer/attestor voluntarily re-attesting every address. This is a direct, protocol-level freezing of user funds for a large class of assets (any asset using `spender_attested`), matching the "AA fund loss/freezing" / "unauthorized... freezing" impact bar.

### Likelihood Explanation
Likelihood is high in practice: this requires only a single ordinary, already-supported `asset_attestors` message from the asset's definer — no privileged network role, no race condition, and no complex multi-step exploit. It can happen accidentally during routine attestor rotation, or deliberately to grief/rug holders, since the protocol does nothing to preserve continuity of attestation validity across list updates.

### Recommendation
When validating spending of a `spender_attested` asset, either (a) allow addresses attested by *any* attestor that was valid at the time the attestation was made (not just the current list), or (b) require that `asset_attestors` updates be additive-only (never fully remove attestors that have live attestations) unless a grace/migration period is enforced, or (c) explicitly document/warn that rotating the attestor list can strand existing holders and require the definer to keep old attestors' historical attestations valid for previously issued attestations.

### Proof of Concept
1. Definer issues asset A with `spender_attested: true`, `attestors: [X]`.
2. Attestor `X` attests holder `H`'s address via an `attestation` message (`attestations` table row with `attestor_address = X`).
3. `H` receives units of asset A and can freely spend them, since `filterAttestedAddresses` finds `H` attested by `X`, which is in the current `arrAttestorAddresses = [X]`.
4. Definer posts a new `asset_attestors` message for asset A with `attestors: [Y]` (a different attestor who has never attested, and will never attest, `H`). This passes `validateAttestorListUpdate` since the definer is the author and the list is well-formed.
5. `readAsset` now returns `arrAttestorAddresses = [Y]` for asset A (the single latest list).
6. `H` attempts to spend their existing asset-A output. `filterAttestedAddresses` queries `attestations` for `attestor_address IN (Y)` and finds nothing for `H` (only `X`'s old attestation exists). `arrAttestedAddresses` is empty, and `validatePayment` rejects with `"none of the authors is attested"`.
7. `H`'s asset-A balance is now permanently unspendable unless `Y` (or some future attestor) independently chooses to attest `H`, which the protocol does not require or incentivize.

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
