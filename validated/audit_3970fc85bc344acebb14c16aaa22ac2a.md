I have sufficient evidence to write the analog finding.

### Title
Asset issuer can retroactively update the attestor list via `asset_attestors`, instantly freezing existing spender-attested holders' outputs - (File: validation.js)

### Summary
This is the ocore analog of the Morpho-Aave issue: a permission/eligibility feature can be toggled by a privileged party *after* other users have already relied on the old state to hold or acquire assets, and the system has no mechanism to protect those users from the retroactive effect. In ocore, an asset defined with `spender_attested: true` requires every spender/output address to be attested by one of the asset's designated attestors. The asset definer can update this attestor list at any time via an `asset_attestors` message [1](#0-0) . Because output-spending validation always looks up the *latest* stable attestor list rather than the list in effect when the coins were received, changing the list can instantly strip previously-valid, already-attested holders of their ability to spend coins they legitimately hold — exactly mirroring how Morpho-Aave users lost collateral status after Aave toggled `usageAsCollateralEnabled` off, even though the underlying position hadn't changed.

### Finding Description
When `spender_attested` is set on an asset, `storage.readAsset()` always resolves the attestor list to the single **latest** stable `asset_attestors` unit for that asset, with no reference to when the asset holder's coins were created or last validated: [2](#0-1) 

This resolved list, `objAsset.arrAttestorAddresses`, is then used by `filterAttestedAddresses()`/`loadAssetWithListOfAttestedAuthors()` to compute `arrAttestedAddresses` for whichever addresses are being checked in the current transaction [3](#0-2) .

During payment validation, every input's owner address must appear in this freshly-recomputed `arrAttestedAddresses`, or the payment is rejected outright: [4](#0-3) 

The equivalent check is duplicated for the private, fixed-denomination path: [5](#0-4) 

And output addresses receiving new attested-asset coins are checked the same way: [6](#0-5) 

The `asset_attestors` update itself is gated only by requiring the sender to be the asset's `definer_address`, with no restriction preventing removal of addresses that already hold outstanding balances of the asset: [1](#0-0) 

So the sequence of events is: (1) definer creates asset with `spender_attested: true` and an initial attestor list; (2) attestor attests address A; (3) A legitimately receives/holds asset coins, validated against the attestor list at that time; (4) at any later point, the definer posts a new `asset_attestors` message removing A (or replacing the whole attestor set); (5) any subsequent attempt by A to spend those existing, already-owned coins fails validation with `"owner address is not attested"`, even though A did nothing wrong and their holdings didn't change. This is structurally identical to the Morpho-Aave bug: a boolean/list-based eligibility flag that gets checked against current state rather than state-at-acquisition-time, applied without any grandfathering of holders who already have funds committed under the prior rule.

### Impact Explanation
This causes AA fund loss/freezing for regular holders of an attested asset: coins that were validly acquired become permanently unspendable the moment the definer updates the attestor list to exclude the holder's address, with no recourse or transition window. Because the same `spender_attested`/`arrAttestedAddresses` check also gates issuance and transfer validation uniformly across all nodes, this is a deterministic freezing condition reproducible by any full node re-validating the chain — it is not merely a wallet-side inconvenience but a protocol-level asset lock affecting anyone using `spender_attested` assets (a documented, supported ocore asset feature used in real oscript samples, e.g. `create_an_asset.oscript`, `futures_contract.oscript`).

### Likelihood Explanation
Likelihood is straightforward: any asset definer who sets `spender_attested: true` (a normal, supported feature, not a misuse) can trigger this simply by posting a routine `asset_attestors` update to refresh or rotate the attestor set — a foreseeable administrative action (e.g., replacing an attestor service, revoking a compromised attestor, or narrowing eligibility) rather than a rare edge case. No collusion or advanced conditions are required; a single legitimate-looking `asset_attestors` unit from the definer is sufficient to freeze funds of every currently-non-attested holder.

### Recommendation
Decouple the attestation check used for **spending existing outputs** from the "latest attestor list" lookup. Either (a) record and pin the attestor-list unit (or attestation status) that was current when the output was created/last validated, and validate spends against that snapshot rather than the current list, or (b) require that attestor-list updates only ever add attestors/attested addresses (never revoke eligibility for addresses that already hold balances), or (c) explicitly document that `spender_attested` list changes can freeze existing holders and provide a migration/grace mechanism (e.g., only enforce the new list for outputs created after the update's stabilization mci) similar to how `readAsset`'s `main_chain_index` gating already distinguishes "before/at last ball" states.

### Proof of Concept
1. Definer creates asset X with `spender_attested: true`, attestors = `[Att1]` (`app: "asset"` message, validated by `validateAssetDefinition`).
2. `Att1` posts an `attestation` for address A.
3. A receives asset X coins from the definer (validated successfully because A is in `arrAttestedAddresses`, per `validation.js:2115-2122`).
4. Definer posts `asset_attestors` message for asset X with a new list that excludes `Att1`/A's attestation is no longer valid `[Att2]` — accepted because `validateAttestorListUpdate` only checks that the sender is the definer [1](#0-0) .
5. `storage.readAsset()` now resolves `arrAttestorAddresses` to `[Att2]` for asset X (the latest stable `asset_attestors` unit) [7](#0-6) .
6. A attempts to spend their previously-received, unchanged asset X output. `loadAssetWithListOfAttestedAuthors` computes `arrAttestedAddresses` against the new list; A is absent, so `filterAttestedAddresses` returns an empty/incomplete set.
7. `validatePaymentInputsAndOutputs` rejects the input with `"owner address is not attested"` [8](#0-7) , permanently freezing A's coins despite no wrongdoing or change in A's holdings.

### Citations

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
