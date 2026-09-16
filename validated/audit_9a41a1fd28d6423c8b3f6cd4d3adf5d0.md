### Title
Asset definer can instantly and unilaterally rewrite the attestor list of a `spender_attested` asset with no timelock, immediately invalidating or granting spending rights for holders and issuers - (File: validation.js)

### Summary
Assets marked `spender_attested` restrict who may issue or spend the asset to addresses currently on an attestor-controlled allow-list. The definer address alone can post an `asset_attestors` message at any time to replace this list completely, and the new list takes effect for any payment whose `last_ball_mci` is at or after the update, with no minimum interval, no bound on how often it can change, and no separate on-chain "event"/notice mechanism distinguishing this update from any other unit. This is the direct analog of a market owner instantly changing a fee parameter that immediately affects all pending trades, with no timelock for counterparties to react.

### Finding Description
`validateAttestorListUpdate` only checks that the poster is the asset's `definer_address` and that the new list is well-formed; it imposes no rate limit, no minimum notice period, and no upper/lower bound beyond `MAX_ATTESTORS_PER_ASSET`: [1](#0-0) 

At spend time, `loadAssetWithListOfAttestedAuthors`/`readAsset` resolve the *latest* attestor list as of `last_ball_mci` and use it to gate whether the payment's issuer or spender is authorized: [2](#0-1) [3](#0-2) 

This latest-list-wins resolution is then enforced unconditionally in `validatePayment`: [4](#0-3) 

Because the attestor list can be swapped by the definer in a single, un-timelocked unit that a user cannot foresee, a spender who already holds attested-asset funds (or who is mid-transaction) has no way to know their spending eligibility can vanish (or be granted to someone else) between the moment they compose a payment and the moment it becomes stable. There is no dedicated event separate from the ordinary `asset_attestors` message, and no governance-imposed cool-down, mirroring exactly the reported issue of arbitrary, un-telegraphed parameter changes that immediately affect counterparties.

### Impact Explanation
A malicious or compromised asset definer can:
- Instantly de-attest addresses that legitimately hold or are about to spend/issue the asset, freezing their outputs (their payment now fails `"owner address is not attested"` / `"issuer is not attested"` validation) even though the funds were valid when received.
- Instantly attest a new address (e.g., their own) immediately before/after a large batch of payments to redirect issuance rights, or race an in-flight payment against an attestor-list update to make honest nodes and the original sender disagree about payment validity depending on which unit's `last_ball_mci` each observer used, since the "latest list as of last_ball_mci" query result differs by the exact stabilization ordering of the `asset_attestors` unit versus the payment unit.
- This is materially worse for `is_private` assets, where attestation state cannot be independently re-verified by light clients (the code explicitly rejects light verification of private attested assets: `"being light, I can't check attestations for private assets"`), increasing the chance that a private-payment counterparty accepts a payment that becomes invalid, or is validated inconsistently, once the definer's unit stabilizes.

### Likelihood Explanation
Any address that defines a `spender_attested` asset (a normal, unprivileged action available to any unit poster) can exploit this at will — no special network role, hub, or peer position is required. The only precondition is that other users hold or transact in an asset with `spender_attested: true`, a documented, commonly-used asset feature.

### Recommendation
- Emit/require a distinguishable marker or minimum notice period (a timelock expressed in MCI count) before an `asset_attestors` update takes effect for spend validation, so holders can react before the new list becomes authoritative.
- Consider grandfathering already-issued outputs against the attestor list that was in effect when the funds were received, rather than always re-checking against the latest list at spend time, particularly for private, non-reversible payment chains.

### Proof of Concept
1. Address `D` defines asset `A` with `spender_attested: true`, `attestors: [D]` and `issued_by_definer_only: true` — `validateAssetDefinition` accepts this at issuance time (fields validated in `validation.js`).
2. `D` issues asset `A` to victim `V`; `V`'s balance is valid and spendable because `V` is not required to be an attestor to *hold* the asset issued to them by `D`, but any subsequent spend by `V` requires `V` (or, if issuing, `D`) to be on the attestor list per `validatePayment` (`validation.js:2115-2122`).
3. Before `V`'s spend unit stabilizes, `D` posts a new `asset_attestors` unit with an attestor list that no longer includes `V` (or arbitrarily includes only `D`). This passes `validateAttestorListUpdate` (`validation.js:2829-2848`) with no timelock, no cap on frequency, and no explicit prior warning.
4. Once `D`'s update unit's `last_ball_mci` precedes `V`'s payment stabilization, `V`'s in-flight/pending spend now fails `"owner address is not attested"` (`validation.js:2432`) or, for public spends, `"none of the authors is attested"`/`"issuer is not attested"` (`validation.js:2115-2121`), freezing `V`'s funds with no forewarning — the direct analog of a market owner instantly raising fees to 100% on unsuspecting traders.

### Citations

**File:** validation.js (L2109-2122)
```javascript
			if (objAsset.issued_by_definer_only && issuer_address !== objAsset.definer_address)
				return callback("only definer can issue this asset");
		}
		if (objAsset.cosigned_by_definer && arrAuthorAddresses.indexOf(objAsset.definer_address) === -1)
			return callback("must be cosigned by definer");
		
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
