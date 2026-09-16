### Title
Attestor list updates via `asset_attestors` message append instead of replace, allowing revoked attestors to remain trusted for spending a `spender_attested` asset - (File: writer.js)

### Summary
When the definer of a `spender_attested=true` asset publishes an `asset_attestors` message to update the trusted attestor list (e.g. to remove a compromised or revoked attestor and replace it with new ones), the write path only inserts the new attestor rows into the `asset_attestors` table without ever deleting the previously stored rows for that asset. This mirrors the RFPSimpleStrategy.setMilestones() bug class: "set" semantics are advertised/expected, but the implementation only appends.

### Finding Description
`asset_attestors` is a first-class message app, separate from the initial attestor list defined in the `asset` message, whose whole purpose is to let the asset definer update ("set") who is currently a trusted attestor for a `spender_attested` asset: [1](#0-0) 

`validateAttestorListUpdate` only checks that the sender is the asset definer and that `checkAttestorList` accepts the new list (non-empty, sorted, valid addresses) — it never compares the new list against the previously stored attestor list, nor does it signal any "replace" semantics to the writer: [2](#0-1) 

At write time, both the initial `asset` message and any subsequent `asset_attestors` message insert rows into the same `asset_attestors` table keyed by `(unit, message_index, attestor_address)`, with a `UNIQUE(asset, attestor_address, unit)` constraint — but the table is never cleared of previous attestor rows for that asset before the new ones are inserted: [3](#0-2) 

The same pattern exists in the AA composer's post-processing of AA-issued `asset_attestors` messages (sorting/normalization only, no removal step) and in `aa_validation.js`'s validation of the `asset_attestors` payload, which likewise only validates the new attestor array shape, never the relationship to the stored/previous list: [4](#0-3) [5](#0-4) 

The `asset_attestors` table schema itself confirms rows accumulate per-unit rather than being replaced in place — every attestor-list-update unit adds new `(unit, message_index, attestor_address)` rows without any corresponding delete of rows from prior units for the same `asset`: [6](#0-5) 

Because attested-spender lookups for a `spender_attested` asset are driven from this same `asset_attestors`/`attestations` data (an address is allowed to spend such an asset if some trusted attestor has attested it), and the trust list never removes previously-inserted attestor rows, an attestor address that the definer intended to revoke (by publishing a new `asset_attestors` message without that address) remains permanently "trusted" from the protocol's point of view. Any attestation previously (or even newly) issued by the revoked attestor can still be used to authorize spending of the asset by an attacker-controlled address that colludes with, or was previously certified by, the removed attestor.

### Impact Explanation
This breaks the security guarantee of `spender_attested` assets, whose entire threat model is "only addresses attested by a currently-trusted attestor may spend/receive this asset." If the definer legitimately revokes a compromised or misbehaving attestor by issuing a fresh `asset_attestors` list that omits it, the old attestor's authority silently persists at the protocol level. This can enable unauthorized spending/transfer of the `spender_attested` asset by parties who should no longer be eligible, and different validating nodes could, in principle, also disagree about which attestor set is "current" depending on how attested-author queries are constructed, since the underlying table never reflects a clean single "current" list. This qualifies as concrete unauthorized-spending impact directly enabled by an unprivileged unit poster's (the definer's, and any attestor who colludes) mistaken trust that "update" == "replace."

### Likelihood Explanation
This requires: (1) an asset created with `spender_attested: true`, (2) the definer later attempting to update/rotate the attestor list via `asset_attestors` (an explicitly documented, ordinarily-used feature for key rotation/compromise response), and (3) a previously-trusted (now supposed-to-be-revoked) attestor account/attestation being reused. Given that attestor rotation is exactly the scenario `asset_attestors` exists for, and the append-only insert path is unconditional (no defensive delete anywhere in `writer.js`, `storage.js`, or `aa_composer.js`), likelihood of exploitation the moment an attestor needs to be revoked is high; the bug is silent (no error, no bounce) so a definer would not necessarily discover it before damage occurs, exactly as described in the source report's "innocuous usage" scenario.

### Recommendation
Before inserting the new rows for an `asset_attestors` message (in `writer.js`, and mirrored in `aa_composer.js`/AA execution write-back paths), delete all existing `asset_attestors` rows for that `asset` (i.e. `DELETE FROM asset_attestors WHERE asset=?`) so that each `asset_attestors` message fully replaces the trusted attestor set rather than appending to it. Any code that reconstructs `attestors` for display/read purposes (e.g. `storage.js` readers of `asset_attestors`) should also be re-checked to ensure it only reflects the most recent replace, not a union of all historical inserts. Equivalent guards should be applied to `aa_validation.js`'s handling of AA-triggered `asset_attestors` payloads and to `aa_composer.js`'s post-processing, ensuring the write layer performs a proper replace transaction consistently across regular units and AA-emitted messages.

### Proof of Concept
1. Definer issues an `asset` message with `spender_attested: true` and initial `attestors: [A]`. `writer.js` inserts `(unit0, 0, asset, A)` into `asset_attestors`.
2. Attestor `A` is later compromised; the definer issues an `asset_attestors` message with `attestors: [B]` intending to revoke `A` and trust only `B`. `validateAttestorListUpdate` in `validation.js:2829-2848` accepts this since it only checks the new list's shape and the sender is the definer. `writer.js:244-251` inserts `(unit1, 0, asset, B)` — it does **not** delete `(unit0, 0, asset, A)`.
3. The `asset_attestors` table for `asset` now contains both `A` and `B` as "trusted" attestors, even though the definer's intent (and any UI/consumer that trusts the latest message) was to replace `A` with `B`.
4. Attestor `A` (or an address it colluded to attest earlier) can still be used to satisfy the spender-attestation requirement for the asset, allowing continued/unauthorized transfers that the definer believed were blocked after revocation.

### Citations

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

**File:** aa_composer.js (L1878-1884)
```javascript
			messages.forEach(function (message) {
				var payload = message.payload;
				if (message.app === 'asset' && isNonemptyArray(payload.denominations) && payload.denominations.every(d => isNonemptyObject(d) && ValidationUtils.isPositiveInteger(d.denomination)))
					payload.denominations.sort(sortDenominations);
				if ((message.app === 'asset' || message.app === 'asset_attestors') && isNonemptyArray(payload.attestors) && payload.attestors.every(ValidationUtils.isValidAddress))
					payload.attestors.sort();
			});
```

**File:** aa_validation.js (L338-353)
```javascript
				case 'asset_attestors':
					if (hasFieldsExcept(payload, ['asset', 'attestors', 'init']))
						return cb2("foreign fields in attestor list update");
					if (!isNonemptyString(payload.asset))
						return cb2("asset is not a string");
					var asset_formula = getFormula(payload.asset);
					if (asset_formula !== null) {
					}
					else if (!isValidBase64(payload.asset, constants.HASH_LENGTH))
						return cb2("bad asset in asset_attestors: " + payload.asset);
					validateFieldWrappedInCases(payload, 'attestors', validateAttestors, function (err) {
						if (err)
							return cb2(err);
						cb2();
					});
					break;
```

**File:** initial-db/byteball-sqlite.sql (L273-282)
```sql
CREATE TABLE asset_attestors (
	unit CHAR(44) NOT NULL,
	message_index TINYINT NOT NULL,
	asset CHAR(44) NOT NULL, -- in the initial attestor list: same as unit 
	attestor_address CHAR(32) NOT NULL,
	PRIMARY KEY (unit, message_index, attestor_address),
	UNIQUE (asset, attestor_address, unit),
	FOREIGN KEY (unit) REFERENCES units(unit),
	CONSTRAINT assetAttestorsByAsset FOREIGN KEY (asset) REFERENCES assets(unit)
);
```
