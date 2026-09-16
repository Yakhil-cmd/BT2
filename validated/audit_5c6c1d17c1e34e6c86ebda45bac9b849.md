I have enough to build the analog finding around the `spender_attested` asset mechanism, where the attestor list used for authorization is always re-evaluated against the *current* (latest) list rather than the list that was valid when the holder was attested/received the funds — mirroring the "state checked at use-time, not creation-time" root cause of the original report.

### Title
Asset definer can retroactively revoke attestor status and permanently freeze already-attested holders' funds - (File: storage.js, validation.js)

### Summary
For assets with `spender_attested=true`, spend-time validation always re-derives the set of "attested addresses" using the **current/latest** `asset_attestors` list published by the asset definer, rather than the attestor list that was in force when the holder actually received/was attested for the asset. If the definer later publishes a new `asset_attestors` unit that drops a previously trusted attestor, every holder whose only qualifying attestation came from that now-removed attestor instantly loses the ability to spend outputs of the asset they already legitimately hold — exactly the same "authorization re-checked with stale/changed external state at settlement time instead of at creation/acquisition time" pattern as the reported `settleInvoice()`/`_isSolverActive()` bug, just here it's `spender_attested`/attestor-list membership instead of solver-active status.

### Finding Description
`storage.readAsset()` computes `objAsset.arrAttestorAddresses` by always selecting the single most-recently-published `asset_attestors` unit for the asset (`ORDER BY level DESC LIMIT 1`), i.e., only the current attestor list is ever considered: [1](#0-0) 

That current list is then used by `filterAttestedAddresses()` to decide, at the moment of spending, which addresses count as "attested": [2](#0-1) 

This filtered set feeds directly into the payment validation logic (`validatePayment` / `validatePaymentInputsAndOutputs`), which requires the issuer to be attested for issuance and requires all output addresses to be attested for a transfer — using whatever `arrAttestedAddresses` was computed from the *current* list: [3](#0-2) [4](#0-3) 

Crucially, `validateAttestorListUpdate()` places no restriction preventing the definer from removing an attestor that has already attested addresses currently holding asset balance — it only checks that the caller is the definer and that the new list is well-formed: [5](#0-4) 

The individual `attestation` messages themselves remain permanently on the DAG and are never invalidated, but they only "count" if their `attestor_address` is a member of the *currently* active attestor list at spend time (`WHERE attestor_address IN(?) ...` using `objAsset.arrAttestorAddresses`, the latest list). So an address that was correctly attested and received asset outputs while attestor A was on the list becomes permanently unable to spend those outputs the moment the definer swaps out attestor A for attestor B — even though the address did nothing wrong and the funds were legitimately acquired.

This is structurally identical to the reported bug: a mutable external authorization state (`solver active` / `attestor in list`) is checked against an already-completed prior action (`invoice creation` / `asset receipt`) at the time of a later, unrelated action (`settlement` / `spend`), instead of being fixed/snapshotted at the time the right was granted.

### Impact Explanation
Any holder of a `spender_attested` asset can have their existing balance made permanently unspendable by a unilateral action of the asset definer (publishing a new `asset_attestors` message), with no way for the holder to remedy this other than obtaining an entirely new attestation from a currently-listed attestor (which may not be possible, e.g., if the attestor set is fully rotated or the attestor refuses/no longer operates). This freezes AA or personal wallet funds for a class of legitimate token holders, matching the "AA fund loss or freezing" impact category.

### Likelihood Explanation
This does not require any malicious peer/node/hub behavior — it is triggered purely by the asset definer (a normal, in-scope actor: "asset issuer") posting a standard `asset_attestors` message, which is explicitly supported and unrestricted with respect to already-attested holders. Any asset using `spender_attested` (used in multiple oscript samples in the repo, e.g. `test/samples/create_an_asset.oscript`, `futures_contract.oscript`) is exposed whenever the definer rotates attestors, making this a realistic, easily reachable scenario rather than a contrived edge case.

### Recommendation
When validating spend-time attestation, evaluate whether the address's attestation was valid under the attestor list that was current at the time the attestation was issued/recorded (i.e., record and honor the attestor-list membership at attestation time), rather than always re-checking membership against the current list. Alternatively, require the definer to leave a grace/migration mechanism (e.g., prevent removing an attestor while addresses attested only by them still hold a non-zero balance, or automatically re-attest/carry forward validity) before an `asset_attestors` update can take effect.

### Proof of Concept
1. Definer creates asset `X` with `spender_attested: true`, `attestors: [A]`.
2. Attestor `A` posts an `attestation` for holder address `H`.
3. `H` receives (via issuance/transfer) asset `X` outputs; validation passes because `H` is in `arrAttestedAddresses` computed from `readAsset`/`filterAttestedAddresses` while `A` is the active attestor.
4. Definer posts a new `asset_attestors` message for asset `X` with `attestors: [B]` (dropping `A`). `validateAttestorListUpdate` accepts this unconditionally as long as it is well-formed and signed by the definer: [5](#0-4) .
5. `H` now attempts to spend the previously-received output. `readAsset` recomputes `arrAttestorAddresses = [B]` (the new latest list): [6](#0-5) . `filterAttestedAddresses` finds no row for `H` because `attestor_address IN ([B])` excludes `A`'s attestation of `H`: [7](#0-6) .
6. `validatePaymentInputsAndOutputs` rejects the spend with `"owner address is not attested"` / `"some output addresses are not attested"`, permanently freezing `H`'s balance of asset `X` unless `B` also attests `H`.

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
