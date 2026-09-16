### Title
Asset definer can unilaterally replace the `spender_attested` attestor list at any time, permanently freezing already-issued/held asset balances - (File: `validation.js`, `storage.js`)

### Summary
Assets that use the `spender_attested` flag (an ocore analog of "upgradeable stablecoin" tokens, since the token's transferability rules are re-evaluated dynamically rather than fixed at issuance) require every spender/output address to be attested by a trusted attestor list. That list is **not fixed at asset-definition time** — the sole asset definer can publish an `asset_attestors` message at any later moment to completely replace the attestor set, and every subsequent spend check uses only the *latest* list. This lets a single actor (the asset definer, analogous to a stablecoin issuer upgrading its logic) retroactively invalidate the attestation of addresses that legitimately received and held the asset under the old rules, freezing their funds with no recourse.

### Finding Description
When an asset is defined with `spender_attested: true`, the initial attestor list is stored via the `asset` message, and can later be changed with an `asset_attestors` message [1](#0-0) . The only guard on this update is that it be single-authored by the asset's `definer_address`; there is no restriction preventing the definer from dropping previously-valid attestors or replacing them wholesale: [2](#0-1) 

When resolving an asset for validation, ocore always fetches the **latest** attestor list unit (i.e., the most recently published `asset_attestors` update, not the one in effect when a holder acquired the asset): [3](#0-2) 

This latest list is what gets used to filter "attested addresses" for every subsequent payment: [4](#0-3) 

At spend time, both divisible and indivisible payment validation re-check attestation against this current list:
- For divisible payments, all output addresses in a transfer must be attested under the current list: [5](#0-4) 
- For indivisible/private payments, the owner address of the coin being spent must be attested under the current list: [6](#0-5) 

`checkAttestorList` only validates address format, ordering, and a maximum count — it never enforces continuity with the prior list or protects existing holders: [7](#0-6) 

### Impact Explanation
A user can receive and legitimately hold a `spender_attested` asset while properly attested under the attestor list in effect at that time. The asset definer can later post a single `asset_attestors` unit dropping that attestor (or replacing all attestors with addresses under their control that refuse to attest anyone). Because attestation is evaluated against the *current* list rather than the list at the time funds were received, all previously-valid holders instantly lose the ability to spend or transfer their balances — validation will reject any payment with "owner address is not attested" or "some output addresses are not attested". This is a direct fund-freezing vector controlled entirely by one address (the definer), mirroring the external report's core concern that a privileged/upgradeable party can retroactively change token rules in a way that traps user funds, without any protocol-level protection, timelock, or grandfathering of existing balances.

### Likelihood Explanation
Likelihood is high for any asset that opts into `spender_attested`: the update path requires only a single, ordinary `asset_attestors` message signed by the definer address — no special privileges, cosigners, or additional consensus. Any asset issuer (malicious from inception, compromised, or simply changing business requirements) can trigger this at will, and the message format is a standard part of the protocol so no code changes are needed anywhere except by the definer.

### Recommendation
Consider anchoring attestation checks to the attestor list that was in effect either at the time an output was created/received, or introduce a grace period / timelock before a new `asset_attestors` update takes effect for existing outputs, so holders have a window to move funds before old attestors are invalidated. Alternatively, disallow removal of attestors that would strand already-issued, still-unspent balances, or require that spend-time attestation checks accept attestation under *any* historically valid attestor list for that asset rather than only the latest one.

### Proof of Concept
1. Definer `D` issues asset `A` with `spender_attested: true` and initial attestor `X`.
2. Attestor `X` attests address `U`; `U` receives a payment of asset `A` (validated fine, since `U` is attested by `X`, the current list).
3. `D` posts an `asset_attestors` message for asset `A` with a new list `[Y]` (dropping `X`) — validated per `validateAttestorListUpdate`, requiring only that `D` is the single author (`validation.js:2829-2848`).
4. `U` attempts to spend their previously received output. `storage.readAsset` → `addAttestorsIfNecessary` fetches the new latest list `[Y]` (`storage.js:1917-1946`); `filterAttestedAddresses` finds `U` is not attested by `Y` (`storage.js:1959-1974`).
5. Payment validation rejects the spend with "owner address is not attested" (`validation.js:2504-2507`) or "some output addresses are not attested" (`validation.js:2630-2641`), permanently freezing `U`'s balance of asset `A` unless `D` chooses to re-attest them.

### Citations

**File:** composer.js (L123-125)
```javascript
function composeAssetAttestorsJoint(from_address, asset, arrNewAttestors, signer, callbacks){
	composeContentJoint(from_address, "asset_attestors", {asset: asset, attestors: arrNewAttestors}, signer, callbacks);
}
```

**File:** validation.js (L2504-2507)
```javascript
							if (objAsset && objAsset.auto_destroy && owner_address === objAsset.definer_address)
								return cb("this output was destroyed by sending it to definer address");
							if (objAsset && objAsset.spender_attested && objAsset.arrAttestedAddresses.indexOf(owner_address) === -1)
								return cb("owner address is not attested");
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
