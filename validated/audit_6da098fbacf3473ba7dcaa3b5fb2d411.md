## Title
Asset Definer Can Instantly Replace the `spender_attested` Attestor List With No Timelock, Freezing Already-Attested Holders' Funds - (File: validation.js)

### Summary
For any asset with `spender_attested: true`, the asset's `attestors` list is not immutable. The definer can post an `asset_attestors` message at any time to replace the entire attestor list, and this change takes effect for all future spend validations as soon as it stabilizes — with no notice period, no timelock, and no restriction requiring continuity with the previous list.

### Finding Description
When an asset is created with `spender_attested: true`, `checkAttestorList()` requires only that the initial attestor set be well-formed (sorted, valid addresses, not empty/too many) [1](#0-0) . Critically, the asset definer can later post a standalone `asset_attestors` message to overwrite this list, validated by `validateAttestorListUpdate()`, which only checks that the sender is the definer and that the new list is well-formed — it does not require overlap with the old list, a cool-down, or any advance notice: [2](#0-1) 

This new list is persisted via `writer.js`'s handling of the `asset_attestors` app [3](#0-2) , and once the containing unit becomes stable, `storage.readAsset()` picks the *latest* attestor-list unit (by level) as authoritative for all subsequent validations: [4](#0-3) 

Whether an address is currently allowed to spend the asset is computed by `filterAttestedAddresses()`, which intersects `attestations` rows against the **current** `arrAttestorAddresses` — meaning attestations issued by a since-removed attestor immediately stop counting: [5](#0-4) 

This is enforced on every payment of that asset in `validatePayment()`: if none of the author's addresses remain in `objAsset.arrAttestedAddresses` after the list changes, the payment is rejected outright with "none of the authors is attested" / "issuer is not attested": [6](#0-5) 

### Impact Explanation
This mirrors the reported bug class exactly: a privileged single party (the asset definer, analogous to the "Vault Admin") can unilaterally and immediately change a critical, user-facing parameter (the attestor whitelist gating the ability to spend/transfer a `spender_attested` asset) with no timelock or advance warning. Consequences:
- Holders who were legitimately attested under the old list can be instantly frozen out of their own funds once the definer swaps the attestor list, since their attestation no longer intersects the new `arrAttestorAddresses`.
- A malicious or compromised definer can front-run users who are mid-transaction: a user broadcasts a payment relying on the currently valid attestor list, but before that payment's last ball stabilizes, the definer's `asset_attestors` update stabilizes first, changing the outcome and causing the user's payment to fail validation ("issuer is not attested" / "none of the authors is attested").
- Because there is no delay or grace period, users have no opportunity to react (e.g., withdraw or move funds) before losing spend eligibility.

This constitutes concrete fund freezing for legitimate holders of a `spender_attested` asset, reachable purely by a definer posting a standard `asset_attestors` unit — no privileged network access required.

### Likelihood Explanation
Any asset definer of a `spender_attested` asset can trigger this at will by posting a single `asset_attestors` message; no special conditions or race are required beyond normal unit posting and eventual stabilization. Given that `spender_attested` is a documented, supported asset feature (also composable via AAs, see `aa_validation.js`'s `asset_attestors` case), the mechanism is straightforward to exploit by any adversarial or compromised definer.

### Recommendation
Introduce a delay/timelock for `asset_attestors` updates analogous to other security-critical parameter changes: e.g., require the update to be announced N main-chain-indexes or a fixed time before it becomes effective for spend validation, and emit it clearly so holders can react. Alternatively, require that removed attestors' existing attestations remain valid for a grace period, or that a new attestor list can only add attestors (not remove) unless holders are given advance notice.

### Proof of Concept
1. Definer issues asset A with `spender_attested: true`, `attestors: [X]`.
2. Attestor X attests holder H's address; H can now spend/transfer A per `validatePayment()`'s `spender_attested` check.
3. H broadcasts a payment of A (relying on current attestor list) and it is unstable/pending.
4. Definer posts `asset_attestors` message replacing the list with `[Y]` (removing X), validated only by `validateAttestorListUpdate()` — no timelock blocks this.
5. If the definer's update stabilizes before H's payment's final validation checkpoint, `storage.readAsset()`/`filterAttestedAddresses()` now use `[Y]`, H's old attestation from X no longer counts, and H's payment (and any future spend) is rejected — H's holdings of asset A become frozen despite having been legitimately attested moments earlier.

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

**File:** writer.js (L244-251)
```javascript
						case "asset_attestors":
							var asset_attestors = message.payload;
							for (var j=0; j<asset_attestors.attestors.length; j++){
								conn.addQuery(arrQueries, 
									"INSERT INTO asset_attestors (unit, message_index, asset, attestor_address) VALUES(?,?,?,?)",
									[objUnit.unit, i, asset_attestors.asset, asset_attestors.attestors[j]]);
							}
							break;
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
