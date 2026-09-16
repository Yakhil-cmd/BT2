### Title
Asset definer can permanently freeze any holder's balance of a `spender_attested` asset by updating the attestor list, with no recipient override to rescue funds - (File: validation.js)

### Summary
For assets defined with `spender_attested: true`, every spend of an existing balance requires that the **input owner address** currently appear in the asset's live attestor-derived attested-address list, not just the output/recipient. Because the definer can update the trusted attestor list at any time via an `asset_attestors` message, they can retroactively invalidate a holder's attested status and make that holder's existing balance permanently unspendable — with no protocol mechanism to move the funds anywhere (not even to the definer or via auto-destroy), mirroring the Beedle blacklist bug where a hardcoded recipient with no override left funds permanently stuck.

### Finding Description
When validating a payment's inputs for a `spender_attested` asset, the code requires the **owner address of the input being spent** to be in `objAsset.arrAttestedAddresses`, unconditionally of the transaction's outputs/destination: [1](#0-0) 

The same unconditional-on-destination check applies to private, fixed-denomination inputs: [2](#0-1) 

`arrAttestedAddresses` is computed from the asset's *current* (as of `last_ball_mci`) trusted attestor list, joined against attestation statements: [3](#0-2) [4](#0-3) 

Crucially, the trusted attestor list itself is not fixed at asset-creation time — the definer can publish an `asset_attestors` message at any later point to change which attestors (and thus, indirectly, which addresses) count as attested: [5](#0-4) [6](#0-5) 

Since `readAsset` always resolves the *latest* attestor list unit before the reference MCI: [7](#0-6) 

a holder who was attested when they received the asset can be silently un-attested later if the definer swaps out (or drops) the attestor that vouched for them. Because the input-spend check at validation.js:2506-2507 (and 2432-2433) does not consider the transaction's outputs at all — it blocks the spend outright regardless of whether the funds are being sent to the definer, back to self, or anywhere else — the holder has **no way** to recover or relocate their existing balance once un-attested. There is no recipient-override, no "send to definer to destroy" escape hatch, and no other spend path in `validatePaymentInputsAndOutputs`/`validatePayment` that bypasses this owner-attestation requirement: [8](#0-7) [9](#0-8) 

This is structurally identical to the Beedle bug class: a party's funds become permanently locked at their current holding location because the protocol/contract offers no way to redirect them once the counterparty (here, the asset issuer/definer) revokes eligibility — except here the freeze is enforced at the core consensus-validation layer, affecting every wallet and every AA holding the asset, not just one escrow contract.

### Impact Explanation
Any address (regular wallet or AA) holding a balance of a `spender_attested` asset can have that entire balance permanently frozen at the sole discretion of the asset definer, who only needs to publish one `asset_attestors` unit to drop the attestor that vouched for the victim address. The frozen funds cannot be transferred out under any circumstances (no recipient can rescue them, since the check is on the spender/owner side, not the destination), resulting in permanent loss of access to principal. If an AA's own address becomes un-attested, funds held by/routed through that AA for its users become frozen as well, which is a form of AA fund loss.

### Likelihood Explanation
Requires only the asset definer to publish a normal `asset_attestors` update — a legitimate, permitted operation with no special privilege beyond being the asset's definer (who by asset design already controls this list). Definers routinely rotate attestors (e.g., replacing a compromised or discontinued attestation provider), and any holder who happens to lose coverage in that rotation is retroactively and permanently locked out, even though they did nothing wrong and control none of the mechanism. Likelihood is medium: it requires a `spender_attested` asset and an attestor-list change, both of which are normal, expected asset-management operations rather than edge cases.

### Recommendation
Decouple the input-spend requirement from strict "owner is currently attested" to allow at least a restricted escape path, e.g.:
- Allow spending un-attested balances when the sole output is the asset's `definer_address` (an explicit "return to issuer" path), similar to the existing `auto_destroy`/non-transferable escape logic already present for non-transferable assets at validation.js:2616-2629.
- Or, evaluate the owner's attestation status against the attestor list that was valid at the time the balance was received (freeze-safe snapshot), rather than the always-current list, so that funds already held remain spendable even if the attestor list later changes, with new restrictions only applying to newly issued/received funds.

### Proof of Concept
1. Definer `D` creates asset `A` with `spender_attested: true` and `attestors: [X]`.
2. Attestor `X` attests address `H` as eligible; `H` receives a balance of `A` via a normal transfer (validated fine since `H` is in `arrAttestedAddresses` at that time).
3. Later, `D` publishes an `asset_attestors` message removing `X` from the trusted attestor list (validated per validation.js:2829-2848, only requires `D`'s authorship).
4. `H` now attempts to spend any input from their own address holding `A`, to any destination whatsoever (self, `D`, or a third party).
5. Validation reaches validation.js:2506-2507 (or 2432-2433 for private fixed-denomination inputs): `owner_address` (`H`) is no longer in `objAsset.arrAttestedAddresses` (recomputed against the new attestor list), so the payment is rejected with `"owner address is not attested"` — for every possible recipient, permanently.

### Citations

**File:** validation.js (L2033-2041)
```javascript
		case "asset_attestors":
			if (!isStringOfLength(payload.asset, constants.HASH_LENGTH))
				return callback("invalid asset in attestor list update");
			if (!objValidationState.assocHasAssetAttestors)
				objValidationState.assocHasAssetAttestors = {};
			if (objValidationState.assocHasAssetAttestors[payload.asset])
				return callback("can be only one asset attestor list update per asset");
			objValidationState.assocHasAssetAttestors[payload.asset] = true;
			validateAttestorListUpdate(conn, payload, objUnit, objValidationState, callback);
```

**File:** validation.js (L2115-2123)
```javascript
		if (objAsset.spender_attested){
			if (conf.bLight && objAsset.is_private) // in light clients, we don't have the attestation data but if the asset is public, we trust witnesses to have checked attestations
				return callback("being light, I can't check attestations for private assets"); // TODO: request history
			if (objAsset.arrAttestedAddresses.length === 0)
				return callback("none of the authors is attested");
			if (bIssue && objAsset.arrAttestedAddresses.indexOf(issuer_address) === -1)
				return callback("issuer is not attested");
		}
		validatePaymentInputsAndOutputs(conn, payload, objAsset, message_index, objUnit, objValidationState, callback);
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

**File:** validation.js (L2606-2629)
```javascript
		},
		function(err){
			console.log("inputs done "+payload.asset, arrInputAddresses, arrOutputAddresses);
			if (err)
				return callback(err);
			if (total_input > constants.MAX_CAP)
				return callback("total input too large: " + total_input);
			if (objAsset){
				if (total_input !== total_output)
					return callback("inputs and outputs do not balance: "+total_input+" !== "+total_output);
				if (!objAsset.is_transferrable){ // the condition holds for issues too
					if (arrInputAddresses.length === 1 && arrInputAddresses[0] === objAsset.definer_address
					   || arrOutputAddresses.length === 1 && arrOutputAddresses[0] === objAsset.definer_address
						// sending payment to the definer and the change back to oneself
					   || !(objAsset.fixed_denominations && objAsset.is_private) 
							&& arrInputAddresses.length === 1 && arrOutputAddresses.length === 2 
							&& arrOutputAddresses.indexOf(objAsset.definer_address) >= 0
							&& arrOutputAddresses.indexOf(arrInputAddresses[0]) >= 0
					   ){
						// good
					}
					else
						return callback("the asset is not transferrable");
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
