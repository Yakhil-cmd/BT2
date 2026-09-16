## Analog Found

### Title
Asset definer freezes previously received `spender_attested` asset holdings by updating the attestor list — ([File: validation.js])

### Summary
The Sherlock report describes `updateYieldStrategy` unconditionally cutting the link between the vault and its strategy after an incomplete withdrawal, permanently locking any remaining funds because the strategy's own access control is tied to the *current* pointer, not to what was true at the time funds were deposited. Obyte's `spender_attested` asset mechanism has the same structural flaw: whether a holder is allowed to *spend* an already-received coin of the asset is checked against the *current* attestor list at validation time, not against the attestor list that was in effect when the coin was received. An asset definer can post a new `asset_attestors` message at any time and unconditionally overwrite the list, instantly freezing every coin held by addresses that fall off the new list — with no mechanism to recover or grandfather those funds.

### Finding Description
When a payment spends a `spender_attested` asset, `validatePayment` loads the asset info via `storage.loadAssetWithListOfAttestedAuthors`, which internally calls `readAsset` → `addAttestorsIfNecessary`. This function always looks up the **latest, stable attestor list as of `last_ball_mci`** for the asset, regardless of which attestor list was in force when the coin being spent was originally issued or transferred to its current owner: [1](#0-0) 

The resulting `arrAttestedAddresses`/`arrAttestorAddresses` is then used at spend time to gate every output owner, both for base (divisible) payments: [2](#0-1) 

and for private/indivisible transfer inputs: [3](#0-2) 

The attestor list itself can be replaced at will by the asset definer through an `asset_attestors` message, validated only against the *current* asset definition and definer identity — there is no restriction preventing the definer from dropping addresses that already hold coins of the asset: [4](#0-3) 

The check is purely "attestor" membership at spend time — no code path preserves or checks the attestor list that applied when the coin was created or last transferred. Because attestation status is external to the coin/output record itself (unlike, say, `denomination` or `asset`, which are baked into the output), a definer's attestor-list change retroactively affects value that has already changed hands.

### Impact Explanation
Exactly as with the Sherlock `updateYieldStrategy` bug, an entity that legitimately received funds under one set of rules ("you're an attested spender") can have that authorization unconditionally revoked by a later, unrelated administrative action ("update the attestor list"), with the funds becoming permanently unspendable by the holder. There is no fallback: the coin cannot be spent (blocked by `"owner address is not attested"` / `"none of the authors is attested"`), and unlike the Sherlock case there is no way at all to reverse the switch and recover the funds — the definer would have to re-add the address to the attestor list, which is outside the holder's control. This is a direct fund-freezing vulnerability reachable by any asset issuer (definer) against any of their asset's holders, matching the "AA/holder fund freezing" impact class validated by the report's judge.

### Likelihood Explanation
This requires no adversarial complexity: any legitimate asset definer routinely maintaining an attestor whitelist (e.g., KYC-style assets) can trigger this by posting a normal `asset_attestors` update — a supported, expected operation — while other addresses are holding balances of the asset. No malicious peer/node/hub behavior is needed; it is a simple ordering issue (attestation checked at spend-time on current state, not issue-time state) inherent to the validation design, reachable by a standard unit poster (the definer).

### Recommendation
Bind attestation-eligibility to the coin/output at the time it is created or transferred (similar to how `denomination`/`asset` are recorded on the output), rather than re-evaluating against the *current* attestor list on every subsequent spend. Alternatively, allow holders whose address is removed from the attestor list to still spend (but not necessarily receive) coins they already held prior to the list update, e.g. by snapshotting attestation status per-output at the mci the output became stable, and checking eligibility against that snapshot instead of `readAsset`'s "latest list" lookup in `addAttestorsIfNecessary`.

### Proof of Concept
1. Definer `D` issues asset `A` with `spender_attested: true` and an initial attestor list `[X]`.
2. Attestor `X` (or someone attested by `X`) sends address `H` a payment in asset `A`. At validation time, `H` is checked as attested via `filterAttestedAddresses` and the payment succeeds — `H`'s output is now unspent and recorded, with no link to the attestor list used.
3. `D` posts an `asset_attestors` message for asset `A` removing `H` (or the attestor that vouched for `H`) from the list — this validates fine per `validateAttestorListUpdate`, since it only checks that `D` is the definer.
4. `H` attempts to spend the previously received coin of asset `A`. `validatePayment` calls `loadAssetWithListOfAttestedAuthors`, which now returns the *new* attestor list; `H` is no longer attested, so `validatePaymentInputsAndOutputs` rejects with `"owner address is not attested"` (divisible) or `"output owner is not among authors"`-type checks (private/indivisible) at [5](#0-4) .
5. `H`'s funds are now permanently unspendable, with no way for `H` to unilaterally recover them — mirroring the Sherlock scenario where funds get orphaned after an unconditional link/pointer switch.

### Citations

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
