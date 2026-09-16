## Analysis

The reported bug class is: an admin/privileged action **removes an item from a list that other users still depend on for accessing already-earned/held value**, with no check that pending claims are settled first. The direct analog in ocore is the **asset attestor list** mechanism for `spender_attested` assets.

### How it maps

For a `spender_attested` asset, only addresses currently on the attestor-approved list can hold/spend the asset's outputs. The **asset issuer** (definer) can update this list at any time via an `asset_attestors` message, validated by `validateAttestorListUpdate`, which only checks that the sender is the definer and that the new list is well-formed — it does **not** check whether addresses that will be dropped from the effective attestor set are currently holding unspent balances of the asset. [1](#0-0) 

When resolving the "current" attestor list, ocore only uses the **single most recent** `asset_attestors` unit — not a cumulative/union history — meaning a new list update fully replaces the old one: [2](#0-1) 

Attestation status for a holder is then computed by intersecting `attestations` against this current `arrAttestorAddresses` list: [3](#0-2) 

Finally, when validating a payment, any *owner* of an existing output must appear in this freshly computed `arrAttestedAddresses` set or the whole transaction is rejected: [4](#0-3) 

### Why this matches the report's bug class

- Exactly like `removePlugin()`, which pops an entry from a list (`plugins`) without checking that pending yield tied to it is claimed first, the asset issuer's `asset_attestors` update instantly and retroactively invalidates spending rights for **already-issued, currently-held** asset balances of any address attested only by a removed attestor.
- The affected holders did nothing wrong — they legitimately received the asset while properly attested — but they lose the ability to move their existing (already-owned) balance the moment the definer republishes the list, with no grace period, no check for outstanding balances, and no partial/append semantics.
- This is reachable by a single privileged-but-ordinary actor explicitly in scope of the rules — the **asset issuer** — posting one ordinary unit (`asset_attestors`), matching the "unauthorized... AA fund loss or freezing" acceptance criteria (temporary freezing of user funds).

### Title
Asset attestor list replacement can freeze already-held balances of previously attested holders - (File: `validation.js`, `storage.js`)

### Summary
`asset_attestors` list updates fully replace the previous attestor list without verifying whether addresses that will lose attestation currently hold unspent balances of the asset, causing an unannounced freeze of legitimately-held funds.

### Finding Description
`validateAttestorListUpdate` only validates that the sender is the asset definer and that the submitted attestor list is well-formed (sorted, valid addresses, non-empty) via `checkAttestorList`. [5](#0-4)  It performs no check on whether the new list drops attestors whose attested addresses currently hold unspent outputs of the asset.

`storage.readAsset` resolves the "current" attestor list by taking only the single latest `asset_attestors` unit (`ORDER BY level DESC LIMIT 1`), discarding all history rather than accumulating it. [2](#0-1)  `filterAttestedAddresses`/`loadAssetWithListOfAttestedAuthors` then compute attestation status strictly against this current list. [3](#0-2) 

At spend time, `validatePaymentInputsAndOutputs` requires that the *current* owner of any spent output be in the (freshly recomputed) attested-address set, or rejects the unit with "owner address is not attested". [4](#0-3)  There is no allowance for outputs that were validly received while the holder *was* attested under a prior list.

### Impact Explanation
Holders who legitimately acquired the asset while properly attested can be locked out of spending their own already-held balance the instant the definer republishes an attestor list that drops their attestor (intentionally or by mistake, e.g. rotating an attestor key). This is a fund-freezing condition directly analogous to the source report's "user can withdraw only stake [not yield]" — here, the user cannot move any of their already-acquired asset balance until/unless attestation is restored. Because attestor-list updates are a normal, expected asset-management action (not requiring any coordination with holders), this can happen unintentionally during routine attestor rotation.

### Likelihood Explanation
The asset issuer/definer only needs to post a single ordinary `asset_attestors` unit to trigger this; no coordination with the previously attested holders is required, and no on-chain check will block it even if it strands existing balances. Any asset marked `spender_attested` with any attestor rotation is exposed.

### Recommendation
When validating/writing an `asset_attestors` update, or when checking spend eligibility, retain a grace/append mechanism: either (a) preserve attestation validity for holders attested under a still-recognized historical list revision until they move their funds, or (b) require the definer to prove (or the protocol to check) that no address relying solely on soon-to-be-removed attestors currently holds an unspent balance before allowing the list replacement to take effect immediately.

### Proof of Concept
1. Asset issuer creates a `spender_attested` asset with initial attestor `A`. [6](#0-5) 
2. Attestor `A` attests address `H`; `H` receives a payment of the asset while attested — this passes validation via `filterAttestedAddresses` matching `H` against `arrAttestorAddresses=[A]`. [7](#0-6) 
3. Definer posts `asset_attestors` replacing the list with attestor `B` only (valid per `checkAttestorList`, no balance check performed). [8](#0-7) 
4. `storage.readAsset` now resolves the asset's attestor list to `[B]` only (latest unit wins). [9](#0-8) 
5. `H` (attested only by `A`, never by `B`) attempts to spend their previously received output; `filterAttestedAddresses` no longer includes `H`, and `validatePaymentInputsAndOutputs` rejects the spend with "owner address is not attested", freezing `H`'s legitimately held balance. [4](#0-3)

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

**File:** storage.js (L1959-1992)
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
