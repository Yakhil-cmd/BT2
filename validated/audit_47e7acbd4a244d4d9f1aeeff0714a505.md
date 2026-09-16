### Title
Permanently frozen asset balances when an attestor is removed from `spender_attested` asset's attestor list - (File: `storage.js`, `validation.js`)

### Summary
An asset definer can permanently freeze already-received, previously-valid funds of any address holding a `spender_attested` asset by publishing a new `asset_attestors` message that removes the attestor who originally attested the holder. Because attestation eligibility is re-evaluated against the *current* (latest) attestor list every time a spend is validated — rather than the list in effect when the attestation/funding occurred — a holder whose only attestor was removed becomes permanently unable to spend the asset units they already legitimately hold.

### Finding Description
When an asset has `spender_attested: true`, every payment involving that asset requires all input/output addresses to be attested by one of the asset's *currently registered* attestors. The attestor list is not fixed at issuance time — the definer can update it any time via an `asset_attestors` message that fully replaces the list: [1](#0-0) 

`readAsset` always resolves the **latest** attestor list (by level, i.e. the most recent stable `asset_attestors` unit), not the list that was valid when a given address's attestation or funding took place: [2](#0-1) 

Every spend of the asset — for both public and private, divisible and indivisible payments — must pass `filterAttestedAddresses`/`arrAttestedAddresses` checks that are computed against this current, mutable `arrAttestorAddresses` list: [3](#0-2) 

The check is enforced at multiple points during validation, including the entry check that at least one author must be attested and the issuer-attestation check: [4](#0-3) 

and for private fixed-denomination coins whose source output owner must still be in the current attested list: [5](#0-4) 

and for output addresses of divisible payments: [6](#0-5) 

Because the `attestations` table records are permanent, but the `arrAttestorAddresses` list used to filter them is always the *current* one, any address whose sole attestation came from an attestor that the definer later removes (by publishing a replacement `asset_attestors` list without that attestor) instantly loses attested status. Since `spender_attested` is required on every subsequent transfer of that asset (not just at issuance), the address's already-received, previously-spendable balance in that asset becomes permanently unspendable — the funds are frozen with no path to recovery unless a still-registered (or new) attestor chooses to re-attest the same address, which is entirely outside the holder's control.

This mirrors the reported bug class exactly: a currently-queried, mutable registry (vaults in the external report; attestors here) determines eligibility for a historical entitlement (unclaimed rewards there; already-owned asset balance here), and removal of an entry from that registry after the entitlement was established causes it to become permanently unusable/locked.

### Impact Explanation
Any regular (unprivileged) address can define a `spender_attested` asset. Once other users acquire and hold balances of that asset (public or private, potentially across many private-payment chain hops), the definer can unilaterally and permanently freeze any holder's funds in that asset simply by publishing an updated `asset_attestors` message that drops the attestor(s) who attested those holders. This is a genuine, node-verifiable freezing of funds — the network will consistently reject any subsequent spend attempt from the affected address for that asset, matching the "AA/user fund freezing" impact category.

### Likelihood Explanation
The precondition is straightforward and requires no special privilege: any address can create an asset with `spender_attested: true`, and the same definer address can subsequently post `asset_attestors` updates to fully replace the attestor list at will — this is normal, permitted protocol usage per `validateAttestorListUpdate`. A malicious or even careless definer (e.g., rotating attestors for legitimate compliance reasons) can trigger the freeze inadvertently or intentionally.

### Recommendation
Do not require attestation to be re-validated against the *current* attestor list for every future spend of already-attested funds. Instead, either:
- record and pin the attestor list (or the specific attestation) that was valid at the time an address's balance/output was created, and validate spends against that pinned state; or
- treat attestation as a point-in-time gate only for issuance/first transfer, not for every subsequent transfer of already-owned coins; or
- require that attestor-list updates be additive-only (attestors can be added but not removed) unless a grace period elapses, giving holders a window to re-attest or move funds before an attestor's removal takes effect.

### Proof of Concept
1. Address `D` (definer) issues asset `A` with `spender_attested: true` and `attestors: [X, Y]`.
2. Attestor `X` posts an `attestation` message attesting address `H`.
3. `H` receives (is issued or transferred) units of asset `A`; validation passes because `H` is attested by `X`, which is in the current attestor list — see check in `validation.js:2115-2122`.
4. `D` posts a new `asset_attestors` message with `attestors: [Y]` (dropping `X`), per `validateAttestorListUpdate` (`validation.js:2829-2848`), which is fully valid and unstoppable by `H`.
5. `H` attempts to spend its previously-received units of asset `A`. `readAsset`/`filterAttestedAddresses` (`storage.js:1917-1992`) now resolve the attestor list to `[Y]` only; since `H` was never attested by `Y`, `H` no longer appears in `arrAttestedAddresses`.
6. The payment is rejected by `validation.js:2115-2122` (or `2430-2433` / `2630-2641` depending on payment type) with "none of the authors is attested" / "owner address is not attested" / "some output addresses are not attested".
7. `H`'s balance in asset `A` is now permanently unspendable unless `Y` (or a future attestor) independently chooses to attest `H`, which `H` cannot compel.

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

**File:** validation.js (L2430-2433)
```javascript
						if (objAsset.auto_destroy && owner_address === objAsset.definer_address)
							return cb("this output was destroyed by sending to definer address");
						if (objAsset.spender_attested && objAsset.arrAttestedAddresses.indexOf(owner_address) === -1)
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
