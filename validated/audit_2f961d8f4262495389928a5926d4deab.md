### Title
Asset attestor list is transferred in a single step with no confirmation from the new attestor - ([File: validation.js])

### Summary
Assets that require `spender_attested` delegate a critical "who can validate spenders" role to a list of attestor addresses. This list is changed with a single, one-step `asset_attestors` message signed only by the asset's `definer_address`. There is no mechanism requiring the new attestor address to acknowledge, confirm, or prove control of its key before the change takes effect — the exact "two-step ownership transfer" gap the external report flags for `Vault.sol`.

### Finding Description
The asset attestor list is set at asset creation and can subsequently be replaced via an `asset_attestors` message. Validation only checks that the message is single-authored and signed by the current `definer_address`: [1](#0-0) 

Once this unit stabilizes, `readAsset`/`filterAttestedAddresses` use the attestors from the *latest* stable `asset_attestors` (or the original `assets`) unit as the sole source of truth going forward: [2](#0-1) [3](#0-2) 

At payment-validation time, whether an address is allowed to issue or transfer such an asset depends entirely on being attested by an address on this current list: [4](#0-3) [5](#0-4) 

This is structurally identical to a one-step `setOwner()`: a single signature from the current privileged party (`definer_address`, analogous to `Vault.owner`) atomically and irrevocably replaces the addresses that everyone else's ability to transact depends on. There is no requirement that:
- the new attestor address be validated as reachable/controlled by anyone, or
- the new attestor confirm/accept the role before the change becomes effective.

The only sanity checks performed are format/uniqueness checks on the address strings themselves, not that the address is usable as an attestor: [6](#0-5) 

### Impact Explanation
If the `asset_attestors` update is broadcast with a mistyped, malformed-but-valid-looking, or otherwise unreachable/uncontrolled address (e.g., an address whose definition/key material nobody possesses), then from the moment the unit is stable, no holder of that asset can obtain a fresh attestation matching the new list. Because `spender_attested` payment validation strictly requires attestation from the *current* list, every future issuance/transfer of the asset that depends on `spender_attested` becomes permanently impossible for any address not already attested under the old list — i.e., concrete freezing of asset funds network-wide, with no path to recovery unless the definer (if their own key is still intact and functioning) can push a corrective update. If the definer's key itself is compromised or lost at the same time (or the definer intentionally griefs), the freeze is permanent.

### Likelihood Explanation
This requires only a single ordinary transaction from the asset's `definer_address` (an unprivileged asset issuer under the report's allowed reachability categories) — no protocol bug is needed to trigger it, only a mistake or malicious action during a routine attestor rotation, which is a normal maintenance operation for `spender_attested` assets. The absence of any secondary confirmation step from the new attestor(s) makes accidental or adversarial bricking straightforward.

### Recommendation
Adopt a two-step attestor-list update pattern analogous to `Ownable2Step`/`ProposableOwnable`:
1. Definer proposes a new attestor list via an `asset_attestors` message that is recorded as *pending*.
2. Each proposed attestor must publish a confirming message (e.g., signed acceptance) before that entry becomes part of the active/effective attestor list used in `validatePayment`/`filterAttestedAddresses`.

At minimum, keep the previous attestor list valid for a grace period after an update so that a bad update can be reversed by the definer before assets become unspendable.

### Proof of Concept
1. Issuer creates an asset with `spender_attested: true` and an initial valid attestor list (`attestors.js` payload in the `asset` message), validated by `validateAssetDefinition`.
2. Later, the definer sends a single `asset_attestors` message replacing the list with `["<TYPO_ADDRESS>"]` — a syntactically valid 32-byte address for which nobody holds the definition/private key. This passes `validateAttestorListUpdate` (only format/definer checks) and `checkAttestorList` (only shape/order checks).
3. Once stable, `readAsset`/`filterAttestedAddresses` treat `<TYPO_ADDRESS>` as the sole authorized attestor (`validation.js:2841`, `storage.js:1917-1946`).
4. Any address attempting to issue/transfer the asset that is not already attested under the old list now fails `validatePayment`'s `objAsset.arrAttestedAddresses.indexOf(...) === -1` check permanently (`validation.js:2115-2122`), freezing the asset for all such holders until/unless the definer (if still capable) issues another corrective `asset_attestors` update.

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

**File:** validation.js (L2606-2624)
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
