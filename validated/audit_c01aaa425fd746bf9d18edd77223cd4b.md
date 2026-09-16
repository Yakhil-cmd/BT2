### Title
Asset attestor list can be arbitrarily updated by definer mid-flight, retroactively freezing already-held asset outputs - ([File: validation.js])

### Summary
The reported Solana bug allows a privileged `Guardian` to mutate critical sale parameters (`purchase_mint`, `payment_mint`, `guard_purchases`, etc.) after a sale has started, so buyers' expectations about the conditions under which their purchase transaction will be evaluated can change out from under them mid-flight. The same bug class exists in `ocore` for `spender_attested` assets: the asset **definer** (an ordinary, unprivileged asset issuer reachable by posting a unit) can update the attestor list of an already-issued, already-circulating asset at any time via `validateAttestorListUpdate`, and this new list is applied retroactively/immediately to every future spend validation of every existing output of that asset, with no lock, no grandfathering, and no time-based restriction.

### Finding Description
When an asset is defined with `spender_attested: true`, every output owner must be attested by one of the addresses in `objAsset.attestors` at the time a payment spending that output is validated: [1](#0-0) 

The attestor list itself is not fixed at asset-definition time forever — it can be changed later via the `attestor_list` app payload, whose validation is: [2](#0-1) 

The only restrictions enforced are: (1) the asset must have been defined with `spender_attested: true`, and (2) the sender must be the asset's `definer_address`. There is **no check on the sale/asset "start" state, no check on whether the asset is already circulating, no versioning/grandfathering of which attestor list applies to which output**, and no cooldown or lock window. `checkAttestorList` only validates the format/sortedness of the new list: [3](#0-2) 

Crucially, when a later payment tries to spend an existing (previously-received) output of this asset, the check `filterAttestedAddresses(... objValidationState.last_ball_mci ...)` resolves attestation status against the **current** (latest stable) attestor list, not the list that was in effect when the recipient received the output: [4](#0-3) 

This is structurally identical to the reported bug: a party who is not the buyer/recipient (here, the asset definer, analogous to the `Guardian`) can change a condition that downstream users rely on (who counts as an eligible/attested holder) at any point after the "sale" (the asset issuance and subsequent transfers) has already started, and this changed condition is applied to transactions that were formed under the old rules.

### Impact Explanation
A user who legitimately received units of a `spender_attested` asset — having been attested at the time they acquired it — can have that attestation silently revoked by the definer at any later point, without their consent or knowledge, by simply removing their attesting address (or replacing the whole attestor set) via a single `attestor_list` message. The next time that holder tries to spend/transfer their balance, `validatePaymentInputsAndOutputs` will reject the transaction with "some output addresses are not attested" / "owner address is not attested" (see the `spender_attested` check at `validation.js:2506` and `validation.js:2632-2641`), permanently freezing their previously acquired funds in that asset. Because AAs are also users of assets (and can hold/transact in `spender_attested` assets, including AA-issued ones per `aa_validation.js:297-300`), an AA's asset balance can likewise be frozen this way — falling squarely into the "AA fund loss or freezing" impact category. This is Medium-to-High severity: it allows a single unprivileged-but-trusted actor (the asset issuer, who is explicitly an in-scope "asset issuer" role) to unilaterally and retroactively invalidate spending rights on funds that were already transferred under different, previously-valid rules.

### Likelihood Explanation
Likelihood is high for any asset actually configured with `spender_attested: true` (a supported, intentional, documented asset feature). No special network conditions, races, or malicious peers are needed — a normal, validly-authored `attestor_list` unit posted by the asset definer is sufficient, and it will be accepted by every honest node running the current validation logic in `validation.js`. The only precondition is that the ecosystem uses `spender_attested` assets with third-party holders (a common design, e.g., KYC-gated tokens), which is explicitly supported by the codebase (`test/samples/*` and `aa_validation.js` handling of `asset_attestors`/`attestation` messages for AA-issued assets).

### Recommendation
Enforce a parameter lock analogous to the one the client added for `update_sale`: once an asset has begun circulating (i.e., once any `issue` or transfer input/output referencing the asset exists), disallow further attestor-list updates, or alternatively make attestation checks non-retroactive by recording, per output, the attestor list version that was in effect when the output was created, and validating spends against that recorded version rather than the current `last_ball_mci`-resolved list. At minimum, add a time/state check in `validateAttestorListUpdate` (mirroring the sale's `is_start_time_reached()` check) that rejects attestor-list changes after the asset has been transferred to non-definer addresses, so that holders' spending rights cannot be revoked after acquisition.

### Proof of Concept
1. Asset issuer defines asset `A` with `spender_attested: true`, `attestors: [Attestor1]`.
2. Attestor1 attests address `X`. `X` receives a payment in asset `A` (valid at receipt time because `X` is attested).
3. Asset definer posts an `attestor_list` message changing `attestors` to `[Attestor2]` (validated only by `validateAttestorListUpdate`, `validation.js:2829-2848`, no state/time lock).
4. `X` later tries to spend the previously-received output of asset `A`. `validatePaymentInputsAndOutputs` calls `storage.filterAttestedAddresses` against the current attestor list (`validation.js:2634-2638`), `X` is no longer attested (only Attestor2's attestees are), and the transaction is rejected with "some output addresses are not attested," permanently freezing `X`'s funds despite the fact that `X` acquired them in full compliance with the rules at that time.

### Citations

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
