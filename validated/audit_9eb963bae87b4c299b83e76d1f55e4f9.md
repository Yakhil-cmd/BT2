### Title
Asset definer can freeze/deny all transfers of a `spender_attested` asset by revoking or corrupting the attestor list at any time - ([File: validation.js])

### Summary
The external report describes an owner who can push protocol parameters (fees) to extreme values and thereby steal earned income or block withdrawals. The closest reachable analog in `ocore` is the **asset definer's unilateral, unbounded control over the `spender_attested` attestor list** for an asset they created. Any asset issuer (a normal, unprivileged unit poster — not a special role) can define an asset with `spender_attested: true`, publish an initial attestor list, let users acquire/hold the asset, and then later post an `asset_attestors` message that empties the effective attestor list (points it to attestors who attest nobody) at any time, permanently freezing every holder's ability to transfer or spend the asset.

### Finding Description
When an asset is defined with `spender_attested: true`, `validateAssetDefinition` in `validation.js` requires an attestor list (`checkAttestorList`) but places no further restriction on how that list may be changed later: [1](#0-0) 

The definer can update the attestor list at any later point, with no timelock, no guardrails, and no requirement to preserve any existing attestors, via `validateAttestorListUpdate`, which only checks that the sender is the original `definer_address`: [2](#0-1) 

`storage.readAsset` always resolves the "current" attestor list to the *latest* stable `asset_attestors` unit for that asset, discarding all previous lists: [3](#0-2) 

At payment-validation time, if `spender_attested` is true, every payment (issue or transfer) requires at least one author to be in the attestor-derived `arrAttestedAddresses` list; if the list is empty (or points to attestors that never attest anyone), no payment can pass validation: [4](#0-3) 

Because `checkAttestorList` (used both at asset creation and at every subsequent update) only requires a non-empty, sorted, valid-address list — not that any of those addresses actually attest holders — the definer can supply attestor addresses that will never attest anyone, achieving a de facto empty attestation set: [5](#0-4) 

This mirrors the reported bug class exactly: a single actor (here, the asset definer, reachable by any ordinary unit poster who chooses to define such an asset) can unilaterally reconfigure a security-critical parameter post-deployment to an extreme value that traps other users' already-acquired funds, with no cap, cooldown, or consent mechanism.

### Impact Explanation
Once users have acquired units of a `spender_attested` asset (through payments or AA-issued tokens, e.g., via `create_an_asset.oscript`-style flows), the definer can revoke or corrupt the attestor list at will. From that point forward, `validatePayment` rejects all payment messages for that asset for any author not in the new/hollowed-out attestor set — freezing every current holder's balance indefinitely. This is a fund-freezing/DoS on asset spendability caused entirely by a centralization risk analogous to the reported "owner can deny withdrawals" issue.

### Likelihood Explanation
No special privilege beyond being the original asset definer is needed — any unprivileged unit poster who defines an asset can later exploit their own holders this way. There is no cap or restriction preventing the definer from setting an attestor list with zero effective attestors, nor any mechanism forcing consistency between old and new lists, making the attack trivially achievable at any time after the asset gains adoption.

### Recommendation
- Require attestor list updates to be more constrained: e.g., disallow reducing the attestor set to zero effective attestors, or require a subset/superset relationship, or add a cooldown/notice period before an attestor list change takes effect.
- Alternatively, validate that at least one attestor in an updated list has actually attested some address before accepting the `asset_attestors` message, so definers cannot trivially create a "no-op" attestor set that blocks all transfers.
- Consider emitting a clear on-chain signal / grace period so holders can move funds before a hostile attestor-list change takes effect.

### Proof of Concept
1. Attacker (definer) posts an `asset` message with `spender_attested: true` and an initial attestor list containing `attestorA` (a legitimate/cooperating attestor), per `validateAssetDefinition` (`validation.js:2725-2827`).
2. Users acquire/transfer the asset; `attestorA` attests them, satisfying `arrAttestedAddresses` checks in `validatePayment` (`validation.js:2115-2122`).
3. Once sufficient value has accumulated with holders, the definer posts an `asset_attestors` message (validated by `validateAttestorListUpdate`, `validation.js:2829-2848`) replacing the attestor list with a fresh, unrelated address (e.g., `attestorB`, who will never attest anyone).
4. `storage.readAsset`'s `addAttestorsIfNecessary` picks up this newest list as authoritative (`storage.js:1917-1946`).
5. Any subsequent payment/transfer of the asset by existing holders fails validation (`objAsset.arrAttestedAddresses.length === 0` → `"none of the authors is attested"`), permanently freezing all holders' balances of that asset — with the definer able to reverse or worsen this state at will.

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

**File:** validation.js (L2745-2748)
```javascript
	// attestors
	var err;
	if ( payload.spender_attested && (err=checkAttestorList(payload.attestors)) )
		return callback(err);
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
