### Title
Dynamic re-evaluation of `spender_attested` asset attestor lists can permanently freeze already-received coins - ([File: validation.js])

### Summary
For assets defined with `spender_attested: true`, `ocore` does not fix the attestation status of a coin at the moment it is received. Instead, every time that coin is later spent (payment, transfer, or issue), the validator re-checks whether the current owner address is present in `objAsset.arrAttestedAddresses`, which is recomputed from the asset's *current* attestor list at the `last_ball_mci` of the new spending unit. This is the same bug class as the reported UXD issue: a "whitelist" check is performed at redemption/spend time instead of at the time the value was created/received, so changing the whitelist (attestor list) after the fact can strand already-existing balances.

### Finding Description
`validatePaymentInputsAndOutputs` in `validation.js` enforces the attestation requirement at spend time for both transfer and issue inputs: [1](#0-0) [2](#0-1) 

and again for the issuer at issue time: [3](#0-2) 

and once more, for every output address, after the whole message is processed: [4](#0-3) 

`objAsset.arrAttestedAddresses` is populated by `storage.loadAssetWithListOfAttestedAuthors` (used in both `validatePayment` and the composer files) which queries attestation state as of the *current* `last_ball_mci`, i.e. against the asset's attestor list as it stands right now, not as it stood when the coin was created: [5](#0-4) 

Because the asset definer can update the attestor list at any time via an `asset_attestors` message (validated in `validateAttestorListUpdate`), and because `filterAttestedAddresses`/`loadAssetWithListOfAttestedAuthors` always evaluate attestation membership against the *live* attestor list rather than a snapshot taken at receipt time, any address whose attestation depended on an attestor that is later removed from the list becomes permanently unable to satisfy the `spender_attested` check. This mirrors the reported UXD pattern exactly: the "whitelist" (attestor list) check is baked into the redemption/spend path, so once the qualifying condition is revoked, value that already exists under the old rule becomes stuck — there is no grandfathering or exit path for previously-received, previously-valid balances.

### Impact Explanation
Coins of a `spender_attested` asset held at an address that loses its qualifying attestation (because the definer removed the attestor from the asset's attestor list, or the attesting party stopped being tracked) become permanently unspendable — the holder can never construct a valid transfer or the definer-cosigned redemption because `arrAttestedAddresses` will not contain that address at any future `last_ball_mci`. This is a fund-freezing bug reachable by any ordinary asset holder/attestor interaction, not requiring any malicious peer or privileged actor beyond the asset definer exercising a normal, permitted action (updating the attestor list). This matches the "Medium: freezing of funds" impact class of the reference report.

### Likelihood Explanation
Likelihood depends on the asset definer actually exercising the attestor-list-update capability (`asset_attestors` message) that `ocore` explicitly supports. Any asset creator who sets `spender_attested: true` and later revises which attestors are trusted (a normal governance/compliance action, exactly analogous to un-whitelisting an asset in UXD) will trigger this freeze for all previously-attested holders who are not re-attested by a currently-listed attestor. This requires no attacker collusion — it is a natural, foreseeable consequence of the whitelist-at-spend-time design.

### Recommendation
Decouple the *validity of a coin already received* from the *current* attestor list. Options:
- Snapshot/record the attestor (and attestation) that qualified an address at the time the output was created, and allow spending as long as that historical attestation remains valid, rather than re-querying the live attestor list on every subsequent spend.
- Alternatively, when validating a transfer/issue's `spender_attested` condition, allow satisfying the condition via any attestation valid at the time the input coin became stable, not only attestations from attestors on the asset's *current* list.
- At minimum, document this behavior clearly so asset definers are aware that removing an attestor from `asset_attestors` can permanently freeze existing holders' balances, and consider requiring a grace/migration period enforced in code (e.g., a transition window during which old attestations remain valid for outputs created before the list change).

### Proof of Concept
1. Definer issues asset `A` with `spender_attested: true` and attestor `X` in the attestor list.
2. Attestor `X` attests address `H`. `H` receives a payment of asset `A` (valid at the time, since `X` is on the list and `H` is attested — checks in `validation.js:2504-2507`/`2115-2121` pass).
3. Definer later sends an `asset_attestors` message removing attestor `X` from asset `A`'s attestor list (validated by `validateAttestorListUpdate`, referenced at `validation.js:2033-2042`).
4. `H` now tries to spend/transfer the previously received coins. `storage.loadAssetWithListOfAttestedAuthors` (called at `validation.js:2084`) recomputes `arrAttestedAddresses` using the *current* attestor list (no `X`), so `H` is no longer in `arrAttestedAddresses`.
5. The transfer input check `objAsset.spender_attested && objAsset.arrAttestedAddresses.indexOf(owner_address) === -1` (`validation.js:2506`, and the private/fixed-denomination equivalent at `validation.js:2432`) fails with `"owner address is not attested"`, and the output-side check at `validation.js:2632-2642` would also reject sending change back or forward.
6. `H`'s coins are now permanently frozen — there is no way to reconstruct the old attestor-list state to satisfy the check, since the query is always against the live/current list.

Note: I was unable to fully read `validateAttestorListUpdate` and `storage.filterAttestedAddresses`/`loadAssetWithListOfAttestedAuthors` implementations in this session (ran out of tool iterations), so the exact SQL/logic determining "attested" membership (e.g., whether it strictly follows the *current* attestor list vs. any historical attestor that was ever valid) could not be fully confirmed from source and should be verified directly in `storage.js` before treating this as fully proven.

### Citations

**File:** validation.js (L2082-2086)
```javascript
	var arrAuthorAddresses = objUnit.authors.map(function(author) { return author.address; } );
	// note that light clients cannot check attestations
	storage.loadAssetWithListOfAttestedAuthors(conn, payload.asset, objValidationState.last_ball_mci, arrAuthorAddresses, objValidationState.bAA, function(err, objAsset){
		if (err)
			return callback(err);
```

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

**File:** validation.js (L2632-2642)
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
					},
```
