This confirms a strong analog. I have enough evidence to build the finding.

### Title
Locked (unspendable) attested funds when the asset definer removes an attestor via `asset_attestors` update - (File: [validation.js](https://github.com/Jortegata/ocore--020/blob/main/validation.js), [storage.js](https://github.com/Jortegata/ocore--020/blob/main/storage.js))

### Summary
For a `spender_attested` asset, an address can only hold/spend a divisible or fixed-denomination unit of that asset if it has been attested by an address that is currently in the asset's attestor list. The attestor list itself is mutable: the asset definer can publish an `asset_attestors` message at any time to replace the whole list (`checkAttestorList`). `storage.readAsset()` always uses only the *latest* attestor-list unit for the asset when validating attestations, with no retroactive grandfathering. If a previously-valid attestor is removed from the list, every holder whose *only* attestation came from that now-removed attestor becomes permanently unable to satisfy `spender_attested` checks, and their existing coins are frozen with no code path to unlock them — directly analogous to the reported `Staking.removeAuthorizedGame()` issue, where removing an authorized entity leaves previously-approved value stranded with no cleanup or exit mechanism.

### Finding Description
`spender_attested` assets require that any address holding/transferring the asset be attested by a trusted attestor address, checked in `validatePayment()`/`validatePaymentInputsAndOutputs()`: [1](#0-0) [2](#0-1) 
and for output addresses: [3](#0-2) 

The attestor list can be freely updated by the asset definer via an `asset_attestors` message, validated only for basic shape/sorting, with no restriction preventing removal of an attestor that is currently relied upon by existing holders: [4](#0-3) [5](#0-4) 

`storage.readAsset()` resolves attestor membership by looking only at the single *latest* attestor-list unit for the asset (`ORDER BY ... DESC LIMIT 1`), discarding all history: [6](#0-5) 

`filterAttestedAddresses()` then checks whether an address's attestation was made by an attestor address that is a member of that current (latest) list — it does not check whether the attestor was authorized *at the time of the attestation*: [7](#0-6) 

Consequently, once the definer issues a new `asset_attestors` message that drops an attestor address, any coin holder whose attestation came exclusively from the removed attestor immediately and permanently loses the ability to pass the `spender_attested` check on any future payment — both as an input owner (`"owner address is not attested"`) and as an output recipient (`"some output addresses are not attested"`). There is no mechanism to re-validate old attestations against the historical list, and no way for the holder to recover funds already received, mirroring the `Staking` contract's failure to protect `lockedLiquidity` when a game is deauthorized.

### Impact Explanation
This can permanently freeze legitimate holders' funds of a `spender_attested` asset with no way to spend, transfer, or issue further — a direct, unrecoverable loss of usable value for the affected addresses. It is Medium/High impact because it directly and irreversibly locks coins already legitimately held.

### Likelihood Explanation
The asset definer is a normal, permissionless actor in this feature (any address can define a `spender_attested` asset and update its attestor list at any time). Attestor-list churn (rotating attestors, dropping a compromised/inactive attestor, etc.) is an expected, routine administrative action for such assets, making the trigger condition (an attestor being dropped while previously-attested holders still exist) plausible and not requiring any malicious behavior — only a normal governance/maintenance action by the definer.

### Recommendation
When validating whether an address is "attested" for spending purposes, check the attestor list that was in effect (stable, confirmed) at the time the address's attestation was published, rather than only the current/latest attestor list — i.e., attestations should remain valid as long as the attestor was authorized at attestation time (or provide an explicit, safe migration/notice period before an attestor removal takes effect for previously-attested addresses).

### Proof of Concept
1. Definer creates asset `A` with `spender_attested: true` and initial `attestors: [X]`.
2. Attestor `X` attests address `H` (`attestation` message with `payload.address = H`).
3. `H` receives/holds units of asset `A`; `filterAttestedAddresses` currently returns `H` as attested because `X` is in the current attestor list, per `storage.js:1959-1974` and `validation.js:2115-2122`.
4. Definer publishes `asset_attestors` for asset `A` with a new list that no longer includes `X` (only requirement is `checkAttestorList` — nonempty, valid, sorted addresses; see `validation.js:2850-2864`). This is accepted regardless of `H`'s outstanding balance.
5. `storage.readAsset()` now resolves `objAsset.arrAttestorAddresses` from only this newest `asset_attestors` unit (`storage.js:1917-1946`).
6. `H` attempts to spend its previously received coins of asset `A`. `filterAttestedAddresses` no longer returns `H` (since `X ∉` new list), so validation fails with `"owner address is not attested"` (`validation.js:2506-2507`), and `H` can never move these funds again by any legitimate on-chain action.

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
