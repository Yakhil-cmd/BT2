This confirms the mechanism: `filterAttestedAddresses` checks the spender against the **latest** attestor list at validation time [1](#0-0) , and `readAsset`'s `addAttestorsIfNecessary` always fetches the most-recently-posted attestor-list unit (`ORDER BY ... DESC LIMIT 1`) rather than the list in force when the asset holder actually received/relied on their funds [2](#0-1) . `validateAttestorListUpdate` lets the asset **definer alone**, unilaterally and at any later time, replace the entire attestor list for a `spender_attested` asset with no restriction tying the update to a prior commitment, no minimum notice period, and no requirement that existing legitimate holders remain covered [3](#0-2) . Both divisible and indivisible payment validation gate spending strictly on membership in the *current* attestor-derived list, not the list that applied when the recipient obtained the funds [4](#0-3) [5](#0-4) .

### Title
Asset definer can retroactively change the attestor list to freeze already-held `spender_attested` asset funds - (File: validation.js)

### Summary
For any asset defined with `spender_attested: true`, the definer publishes an `asset_attestors` message naming the addresses whose `attestation` messages are trusted. Holders of the asset acquire and hold coins based on being attested by an address on that list at the time they received the funds. The `asset_attestors` app message can be republished by the definer at any later time, with `validateAttestorListUpdate` performing no check that prevents the definer from doing this after other parties have already relied on the previous list to hold, receive, or plan to spend the asset [3](#0-2) .

### Finding Description
`readAsset`'s `addAttestorsIfNecessary` always resolves the attestor list to the single most-recently-published `asset_attestors` unit for the asset, ordered by DAG level (`ORDER BY level DESC LIMIT 1`), not the list that was current when a spender received their coins [6](#0-5) . `filterAttestedAddresses` then checks whether the spending address has an `attestation` from one of these *current* attestors [7](#0-6) . `validatePayment` and `validatePaymentInputsAndOutputs` reject any spend where the owner address is not present in this dynamically recomputed `arrAttestedAddresses` set [4](#0-3) [5](#0-4) .

This is structurally the same class of bug as the reported Teller issue: a party (asset definer / "borrower") controls a piece of state (attestor list / collateral commitment) that a counterparty (asset holder / "lender") relies on when entering a position, and the controlling party can unilaterally rewrite that state afterward with no lock-in, invalidating the counterparty's expectations. Here, `validateAttestorListUpdate` (analogous to `commitCollateral`) only checks that the sender is the definer and that the new list is well-formed — it never checks whether existing holders were already attested under the old list, nor restricts changes after funds have been transferred to attested-dependent addresses [3](#0-2) .

### Impact Explanation
A definer of a `spender_attested` asset can issue/distribute the asset to a holder while the holder is attested, wait for the holder to accept/hold the funds, then post a new `asset_attestors` message dropping that holder's attestor from the list. On the very next spend attempt, `arrAttestedAddresses` will no longer include the holder, and the payment will be rejected with "none of the authors is attested" / "owner address is not attested", freezing the holder's coins entirely without their consent [4](#0-3) [5](#0-4) . This is a direct, unilateral fund-freezing/rug vector matching the reported bug class (state change by one party after a counterparty's reliance/commitment causes counterparty harm).

### Likelihood Explanation
Any asset definer can trigger this merely by posting one more `asset_attestors` unit — no special privilege, cooperation, or race condition is required beyond already being the asset's definer, which is an unprivileged role available to any unit poster who defines the asset in the first place.

### Recommendation
Snapshot and pin the attestor list that applied to each holder's output at the time the output was created (or at time of the attestation), rather than always resolving to the latest attestor-list unit at spend-validation time. Alternatively, require that attestor-list updates cannot retroactively de-attest addresses that already hold un-spent coins that were valid under the prior list, or introduce a grace/notice period during which previously-attested holders can still spend before the new list takes effect.

### Proof of Concept
1. Definer `D` posts an `asset` message with `spender_attested: true` and an initial `asset_attestors` list `[A]`.
2. Attestor `A` posts an `attestation` for holder `H`.
3. `D` (or someone) sends `H` some units of the asset; validation passes because `H` is in `arrAttestedAddresses` per the list `[A]` [4](#0-3) .
4. `D` posts a new `asset_attestors` message for the same asset with list `[B]` (dropping `A`) — `validateAttestorListUpdate` accepts this unconditionally since `D` is still the definer [3](#0-2) .
5. `readAsset` now resolves the attestor list to `[B]` since it is the latest unit by level [6](#0-5) .
6. `H` attempts to spend the previously received coins; `filterAttestedAddresses` finds no attestation from `B` for `H`, so `arrAttestedAddresses` is empty, and `validatePayment`/`validatePaymentInputsAndOutputs` reject the spend as "none of the authors is attested"/"owner address is not attested" — `H`'s funds are permanently frozen by `D`'s unilateral action [4](#0-3) [5](#0-4) .

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

**File:** validation.js (L2504-2507)
```javascript
							if (objAsset && objAsset.auto_destroy && owner_address === objAsset.definer_address)
								return cb("this output was destroyed by sending it to definer address");
							if (objAsset && objAsset.spender_attested && objAsset.arrAttestedAddresses.indexOf(owner_address) === -1)
								return cb("owner address is not attested");
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
