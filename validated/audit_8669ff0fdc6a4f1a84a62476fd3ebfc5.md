### Title
Asset definer holds unilateral, non-timelocked control over the spender-attestor list, allowing instant freezing of any holder's funds - (File: validation.js)

### Summary
For any asset created with `spender_attested: true`, the single address that defined the asset (`definer_address`) can post an `asset_attestors` message at any moment to replace the entire list of trusted attestors, with no delay, no multisig requirement, and no on-chain grace period. Because every payment that involves this asset must send its outputs exclusively to attested addresses, the definer can instantly and unilaterally strip any address (including the holder's own change address) from the attestor list, freezing that user's holdings. This is a direct structural analog of the "owner holds too much power / no timelock" finding: a single privileged party fully controls a critical, continuously-enforced security parameter that governs other users' ability to move their own funds.

### Finding Description
When an asset is defined with `spender_attested: true`, `validateAssetDefinition` requires an initial `attestors` list [1](#0-0) . Afterward, the definer can update this list at will via the `asset_attestors` message. Validation of this update enforces only that the sender is the asset's `definer_address` — no other authorization, cosigners, or delay are required: [2](#0-1) 

This update takes effect for any payment referencing the asset once the update becomes part of the last stable ball (ordinary DAG stabilization, not a deliberate protocol timelock). Every payment of the asset is then checked against the *current* attestor list. On the issuance/authoring side, the issuer must be attested: [3](#0-2) 

And on every transfer, all output addresses (including change returned to the sender) must be attested, or the whole payment is rejected: [4](#0-3) 

The attestor list actually enforced is always the most recently stabilized one for the asset, as read by `readAsset`: [5](#0-4) 

Because the check applies to output addresses on every transfer (not just at issuance), a definer can, at any time and without any advance notice or lock-up period, remove a specific holder's address from the attestor list. From that point on, any payment that would send an output (including a change output) back to that now-unattested address is rejected by validation, effectively freezing the holder's ability to move or receive that asset through their own address.

### Impact Explanation
This is a concrete AA/asset fund-freezing vector reachable purely by posting ordinary units — no privileged node or protocol role is needed beyond being the original asset definer, a role any unprivileged user obtains simply by issuing the asset. A malicious or compromised definer can:
- Instantly de-attest any specific counterparty's address, freezing their existing balance of the asset (they can no longer receive change or would need an atomic full-balance transfer to a still-attested third party).
- Rug users who trusted the asset by revoking attestation broadly, effectively halting all transfers except to addresses the definer still favors.

This matches the External Report's core concern — a privileged party ("owner"/definer) can make a unilateral, irreversible-in-effect change that harms users with no protective delay — mapped onto ocore's asset issuance and transfer-condition machinery.

### Likelihood Explanation
High for any asset where users rely on `spender_attested` and do not fully control the identity/behavior of the definer (e.g., stablecoins, KYC/whitelisted tokens, or any asset issued by a third-party service on top of ocore). The action requires only a single, ordinary `asset_attestors` unit signed by the definer — no cooperation, multisig, or unusual conditions are needed, and validation imposes no rate limit, delay, or notice period.

### Recommendation
Since ocore has no protocol-level timelock primitive for this pattern, consider:
- Documenting/warning at the wallet and asset-explorer UI level that `spender_attested` assets carry unilateral revocation risk controlled solely by the definer.
- Allowing asset definitions to optionally require the attestor-list update to be co-signed by a broader definition (e.g., defining the attestor-update authority as a multisig/quorum address rather than always `definer_address`), so issuers who want less centralization can build that into their asset's definer address.
- For asset templates that mimic AAs (e.g., `create_an_asset.oscript`), consider composing the `asset_attestors`-issuing authority as an AA-governed address with an explicit delay/voting mechanism before an attestor removal takes effect, rather than an immediately-effective definer-controlled update.

### Proof of Concept
1. Definer `D` issues asset `X` with `spender_attested: true` and initial `attestors: [D, A]` via the `asset` message (validated by `validateAssetDefinition`, `validation.js:2725`).
2. User `A` receives and holds asset `X`.
3. `D` posts an `asset_attestors` message for asset `X` with `attestors: [D]` (removing `A`). This passes `validateAttestorListUpdate` because `D` is `definer_address` — no other checks apply (`validation.js:2829-2848`).
4. Once this unit stabilizes, any future payment of asset `X` with an output back to `A` (e.g., `A` trying to spend part of their balance and receive change) fails validation with "some output addresses are not attested" (`validation.js:2637-2638`), because `A` is no longer in `arrAttestedAddresses`.
5. `A`'s balance of asset `X` is effectively frozen unless they can construct an exact-amount, no-change transfer to another still-attested address — entirely at `D`'s discretion and reversible only if `D` chooses to re-add `A`.

### Citations

**File:** validation.js (L2115-2121)
```javascript
		if (objAsset.spender_attested){
			if (conf.bLight && objAsset.is_private) // in light clients, we don't have the attestation data but if the asset is public, we trust witnesses to have checked attestations
				return callback("being light, I can't check attestations for private assets"); // TODO: request history
			if (objAsset.arrAttestedAddresses.length === 0)
				return callback("none of the authors is attested");
			if (bIssue && objAsset.arrAttestedAddresses.indexOf(issuer_address) === -1)
				return callback("issuer is not attested");
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

**File:** validation.js (L2746-2750)
```javascript
	var err;
	if ( payload.spender_attested && (err=checkAttestorList(payload.attestors)) )
		return callback(err);
	if (!payload.spender_attested && "attestors" in payload && (objValidationState.last_ball_mci >= constants.pemCurvesFixMci || !objValidationState.hasBall && storage.getMinRetrievableMci() >= constants.pemCurvesFixMci))
		return callback("attestors should not be defined when spender_attested is false");
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
