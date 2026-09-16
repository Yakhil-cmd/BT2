Confirmed: `validateAttestorListUpdate` at [1](#0-0)  lets the `definer_address` unilaterally replace the entire `attestors` list for a `spender_attested` asset at any time via an `asset_attestors` message, with the only constraints being single-authorship, ownership by definer, and `checkAttestorList` format checks [2](#0-1) . This list is enforced against every subsequent spend by all holders via `filterAttestedAddresses`/`arrAttestedAddresses` checks in `validatePaymentInputsAndOutputs` and `validatePayment` [3](#0-2) [4](#0-3) , and there is no requirement that the newly designated attestors ever actually attest anyone, nor any check that they are capable/willing/reachable actors.

### Title
Asset definer can unilaterally swap `spender_attested` attestor list to a non-cooperating set of addresses and permanently freeze all existing holders' funds - ([File: validation.js])

### Summary
An asset created with `spender_attested: true` binds every future spend of that asset to attestation by a currently-registered set of attestor addresses. The `definer_address` alone can post an `asset_attestors` message at any later moment (long after other users have already acquired and hold the asset) that atomically replaces the trusted attestor list with addresses that will never issue an attestation (e.g., addresses the definer does not control, addresses with no operator, or simply attestors who refuse to cooperate). This mirrors the Cooler `Cooler.sol` bug class where a party who already has an obligation toward a counterparty can, through a permitted "ownership/role transfer" step, hand control to an entity that will never satisfy the callback/attestation requirement the protocol depends on — forcing the counterparty (here, the coin holders) into a permanently unspendable ("defaulted") state.

### Finding Description
`validateAttestorListUpdate` only checks that the message is single-authored, that the author is the asset's `definer_address`, and that the submitted attestor addresses are syntactically valid and sorted: [1](#0-0) 

There is no restriction preventing the definer from changing the attestor list after the asset has been issued and is already held by third parties, and no check that the new attestors are capable of, or intend to, attest any address. Once this update is stable, `readAsset`/`loadAssetWithListOfAttestedAuthors` picks up the latest `asset_attestors` unit as the authoritative list (`ORDER BY ... DESC LIMIT 1`): [5](#0-4) 

Every subsequent spend of the asset — by any holder, not just the definer — is validated against this list. If the author (or output address, for transfers) is not in `arrAttestedAddresses`, the payment is rejected outright: [4](#0-3) [3](#0-2) 

Because the new attestor set can consist of addresses that never publish an `attestation` message (there is no protocol-level requirement or incentive forcing an attestor to attest anyone), the definer can make attestation permanently impossible for all current holders in one message, exactly analogous to the Cooler lender transferring loan ownership to an EOA that will never execute the required `onRepay` callback, forcing default. Here the "default" is a total freeze of the asset for every holder who trusted the definer's earlier attestor policy.

### Impact Explanation
This directly matches the accepted impact bucket of "AA fund loss or freezing" (more broadly, asset fund freezing): all coins of the affected asset become permanently unspendable for every holder except addresses the definer chooses to have attested (which, in the worst case, is nobody). Holders who acquired the asset while a legitimate attestor list was in place have no recourse — their balances are frozen forever with no on-chain mechanism to revert or challenge the definer's attestor-list change. This is a High-severity fund-freezing issue since it affects all outstanding balances of any asset using this feature, not just the definer's own funds.

### Likelihood Explanation
Likelihood is high for any asset that has been deployed with `spender_attested: true` and gained holders other than the definer. The definer is a single, unprivileged actor (from the protocol's point of view) who can trigger this at will by posting one ordinary `asset_attestors` message — no special network position, hub cooperation, or multi-party collusion is required. The only "cost" is reputational, but the protocol provides no technical safeguard.

### Recommendation
Consider adding one or more of the following technical safeguards to `validateAttestorListUpdate` (or asset semantics) in `validation.js`:
- Require newly listed attestors to have already attested at least one address (proof of an active attestor) before they can be accepted into the list, or
- Disallow full replacement of the attestor list in a single message — instead require append/timelocked removal, giving holders time to react, or
- Emit a way for holders to react to attestor-list changes (e.g., a mandatory delay before the new list becomes enforceable for existing outputs), preventing an immediate, retroactive freeze of already-held balances.

### Proof of Concept
1. Definer `D` creates asset `A` with `spender_attested: true` and an initial attestor list `{X}` who actively attests spenders.
2. Users acquire and hold `A`, relying on `X` attesting them so they can transact.
3. `D` posts a single-authored `asset_attestors` message for asset `A` with a new `attestors` list `{Y}`, where `Y` is an address `D` controls but will simply never issue any `attestation` message (or an address with no real operator).
4. This message passes `validateAttestorListUpdate` — it is well-formed, single-authored by `D`, and `Y` is a syntactically valid address [1](#0-0) .
5. From this point, `readAsset`/`filterAttestedAddresses` treats `{Y}` as the sole trusted attestor set [6](#0-5) .
6. Any holder attempting to spend `A` fails validation with `"none of the authors is attested"` / `"some output addresses are not attested"` forever, since `Y` never attests anyone [4](#0-3) , permanently freezing all balances of `A` held by anyone other than an address `Y` chooses to attest.

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

**File:** validation.js (L2630-2641)
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
```

**File:** validation.js (L2829-2847)
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

**File:** storage.js (L1959-1993)
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
