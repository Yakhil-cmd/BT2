## Analysis

The reported bug class is: a privileged actor can point a mapping used for computing rewards/authorization (`collateralToOracle`) to a null value, and because reward-claim logic always re-reads the *current* value of that mapping (rather than a value snapshotted at accrual time), historically-earned rewards become permanently unclaimable.

The closest reachable analog in `ocore` is the `spender_attested` asset mechanism. An asset issuer ("definer") can post an `asset_attestors` message at any time to replace the asset's list of trusted attestors [1](#0-0) . Validation of this message only checks that the new list is non-empty, sorted, and posted by the definer — it does not check the impact on holders who were attested under the *previous* list [2](#0-1) .

Every time a `spender_attested` asset output is spent (input) or received (output), the check is against the **current/latest** attestor list, not the list that was valid when the coins were originally received: `readAsset()` looks up only the newest `asset_attestors` unit by level [3](#0-2) , and `filterAttestedAddresses()` matches `attestations.attestor_address` against that current list [4](#0-3) . Both `validatePayment` (issue path) and `validatePaymentInputsAndOutputs` (input-owner and output-recipient checks) rely on this same current-list check [5](#0-4) [6](#0-5) [7](#0-6) .

Consequently, if the definer rotates the attestor set (e.g., drops an attestor that a holder relied on, without that holder obtaining a fresh attestation from a currently-recognized attestor), the holder's already-received, legitimately-owned coins become permanently unspendable — exactly the "live dependency blocks historical claim" pattern from the report, reachable by an in-scope actor (the asset issuer).

### Title
Asset definer rotating the attestor list via `asset_attestors` can permanently freeze existing holders' funds - (File: validation.js, storage.js)

### Summary
`spender_attested` assets require every spend (and receipt) to be validated against the *current* attestor list rather than the list that was valid when the tokens were received. Because the asset definer can freely replace the attestor list at any time, existing coin holders who are not re-attested under the new list lose the ability to spend coins they legitimately hold.

### Finding Description
When an asset is created with `spender_attested: true`, spending or receiving that asset requires the address to appear in the `attestations` table from an address currently listed in `asset_attestors`. `readAsset()` resolves `arrAttestorAddresses` using only the most recent `asset_attestors` unit (`ORDER BY level DESC LIMIT 1`) [3](#0-2) , and `filterAttestedAddresses()` filters holder addresses against that current set [4](#0-3) . This current-list result is then used to gate both issuance (`arrAttestedAddresses.indexOf(issuer_address)`) [5](#0-4)  and transfer, for both the input owner and every output recipient [8](#0-7) [7](#0-6) .

The asset definer can post a new `asset_attestors` message at any time; validation only requires the list be non-empty, valid addresses, sorted, and signed by the definer — there is no restriction preventing removal of attestors whose past attestations are relied upon by existing coin holders [9](#0-8) . Once the old attestor is dropped from the list (or ceases to attest new addresses), holders who received coins under the old regime and are not re-attested by a currently-recognized attestor can never satisfy `filterAttestedAddresses` again, exactly mirroring the reported issue where removing an oracle mapping blocks a downstream calculation that has no path to succeed for historical data.

### Impact Explanation
Coins already legitimately owned by holders of a `spender_attested` asset become permanently unspendable once the definer rotates the attestor set away from whoever attested them, with no built-in fallback that preserves rights based on the attestation status at time of receipt. This is a fund-freezing condition reachable without any special governance/consensus process — a single `asset_attestors` message from the definer (an in-scope, unprivileged-relative-to-core-consensus actor: the asset issuer) is sufficient.

### Likelihood Explanation
Likelihood is low because it typically requires either negligence (definer forgets to keep old attestors in the list, or an attestor becomes defunct and isn't replaced with continuity for existing holders) or deliberate action by the definer. It does not require a malicious network participant, only a legitimate but ill-considered administrative asset operation, matching the "High impact / Low likelihood" profile of the referenced report.

### Recommendation
- When checking `spender_attested` conditions for spending an existing output, validate attestation against the attestor list that was in effect at (or before) the moment the output was created/received, not only the list current as of the spending unit's last ball.
- Alternatively, introduce a grace/migration mechanism so that holders attested under a previous attestor list retain spendability for some period, or require the definer to explicitly acknowledge/carry forward attestations for existing balances when rotating attestors.
- More generally, any asset- or AA-level mapping that historical value-realization (spending owned coins, claiming accrued rewards) depends on should be resolved using the state at accrual/receipt time rather than unconditionally re-read at claim time.

### Proof of Concept
1. Definer creates asset `A` with `spender_attested: true` and initial attestor `X`.
2. Attestor `X` attests address `H`.
3. `H` receives/holds asset `A` outputs (via issuance or transfer), validated successfully because `H` is attested by `X`, which is in the current attestor list.
4. Definer posts a new `asset_attestors` message replacing the attestor list with `[Y]` (dropping `X`).
5. `H` attempts to spend the previously received `A` outputs. `readAsset()` now resolves `arrAttestorAddresses = [Y]`; `filterAttestedAddresses` finds no attestation of `H` by `Y`, so `objAsset.arrAttestedAddresses` does not include `H` [10](#0-9) .
6. `validatePaymentInputsAndOutputs` rejects the spend with `"owner address is not attested"` [6](#0-5) , and there is no mechanism to spend the coin using the attestation that was valid when it was received — the funds are frozen unless `H` manages to get attested by `Y` (outside `H`'s control).

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
