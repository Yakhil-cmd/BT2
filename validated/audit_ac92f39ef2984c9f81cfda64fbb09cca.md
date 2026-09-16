### Title
Asset attestor list update strands existing coin holders' funds with no settlement mechanism - (File: `validation.js`, `storage.js`)

### Summary
For any `spender_attested` asset, the asset definer can publish a new `asset_attestors` message at any time to replace the list of trusted attestors. Spendability of *every* existing output of that asset — including outputs already held by users before the update — is checked against only the **latest** attestor list, not the list that was in effect when the funds were received. Because there is no mechanism to force-settle or "convert" existing balances before/while the attestor list changes, a definer action can permanently freeze previously issued/transferred coins, exactly analogous to the reported `TokenManager`/`TokenPairs` issue where removing a pair leaves existing balances stranded with no automatic settlement.

### Finding Description
When an asset is created with `spender_attested: true`, both the owner of each spent input and every output address of a payment must appear in the asset's *current* attestor list:
- Input owner check: [1](#0-0) 
- Output address check for the whole payment: [2](#0-1) 

The "current" attestor list is resolved by always taking the single most-recent `asset_attestors` unit for the asset (no history of which list was valid when a given output was created): [3](#0-2) 

The attestor list can be freely replaced by the definer via a single-authored `asset_attestors` message, with no check that previously-attested addresses (who may be holding balances) remain attested, and no requirement to settle/allow withdrawal of existing balances before the switch: [4](#0-3) [5](#0-4) 

This mirrors the reported bug class: a privileged "asset issuer" action (`removeTokensAndPairs`/`_removePairByTokens` in the report vs. `asset_attestors` update in ocore) removes the precondition needed to move existing funds, without any built-in logic to settle, migrate, or grandfather the affected balances.

### Impact Explanation
Any user holding coins of a `spender_attested` asset can become permanently unable to spend them the moment the definer publishes a new attestor list that does not include that user's address (or that of any counterparty they would send to), since both the payer and every payee must be on the *current* list. Because there is no settlement path (e.g., automatic conversion, grace-period withdrawal, or snapshotting of the list valid at receipt time), funds are effectively frozen inside the ocore ledger — the analog of "user funds locked in an abandoned token contract" from the original report. This is a direct, permanent AA/asset-fund-freezing condition reachable by a legitimate ocore actor (the asset issuer/definer), matching the required impact category of AA/asset fund loss or freezing.

### Likelihood Explanation
Likelihood is contingent on the asset definer's deliberate action (publishing a new `asset_attestors` message), similar to how the original finding is contingent on a governance decision to remove a token pair. This is not an attacker-triggered exploit against a third party, but it is a realistic, foreseeable operational action for any compliance-gated (`spender_attested`) asset — attestor sets are expected to be updated over time (e.g., changing KYC providers), and the protocol provides no safeguard preventing this from stranding existing holders.

### Recommendation
When updating an asset's attestor list via `asset_attestors`, either:
1. Retain validity of the previous attestor list for a grace period so that addresses attested under it can still move/settle their existing balances, or
2. Track, per output, which attestor-list version was in effect when the output was created, and permit spending if the owner was attested under *that* list (in addition to, or instead of, only the latest list), or
3. Require the definer to provide an explicit migration/settlement path (e.g., an intermediate transitional attestor set that is the union of old and new attestors) before the change takes effect, so existing holders always have some byte3window to move funds out.

### Proof of Concept
1. Definer issues asset `A` with `spender_attested: true` and initial `attestors: [X]`.
2. Address `X` is attested by attestor `X` (or a third attestor) and receives/holds a balance of asset `A` via ordinary `payment` messages — validated successfully because `X` is in `arrAttestedAddresses` at that time (`validation.js:2506`, `2632-2641`).
3. Definer later posts a new `asset_attestors` message for asset `A` with `attestors: [Y]` (validated by `validateAttestorListUpdate`, `validation.js:2829-2848`, only requiring the definer's signature and a well-formed sorted list — no check on existing holders).
4. `storage.readAsset` now resolves the attestor list to only `[Y]` (`storage.js:1917-1946`).
5. Address `X` attempts to spend its existing coins of asset `A`. `filterAttestedAddresses`/`loadAssetWithListOfAttestedAuthors` checks `X` against attestor `Y`; since `X` was never attested by `Y`, the transfer fails both the owner-attestation check (`validation.js:2506`) and, even for a fresh recipient, the output-attestation check (`validation.js:2632-2641`).
6. `X`'s balance of asset `A` is now permanently unspendable with no code path providing settlement, migration, or grace period.

### Citations

**File:** validation.js (L2506-2507)
```javascript
							if (objAsset && objAsset.spender_attested && objAsset.arrAttestedAddresses.indexOf(owner_address) === -1)
								return cb("owner address is not attested");
```

**File:** validation.js (L2632-2641)
```javascript
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
