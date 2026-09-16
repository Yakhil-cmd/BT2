### Title
Asset definer can arbitrarily change the `spender_attested` attestor list at any time, retroactively invalidating already-promised payments to counterparties - (File: validation.js)

### Summary
The `OpenQ` bug lets a bounty owner call `setPayout` at any time — including right before a claimer's payout is settled — to change payment terms and steal the value of already-performed work. The same class of bug (an unrestricted, un-timelocked, privileged "term-mutation" function that a counterparty relies on being stable) exists in ocore's `spender_attested` asset feature: the asset **definer** may post an `asset_attestors` message at *any* time to add or remove attestors/attested addresses, and this list is re-evaluated against the *last stable ball* (`last_ball_mci`) at the moment a payment using that asset is validated — not at the moment it was created and broadcast.

### Finding Description
When an asset is defined with `spender_attested: true`, every payment output paid in that asset must have its destination address attested by one of the asset's current attestors, as enforced in `validatePaymentInputsAndOutputs`: [1](#0-0) 

The attestor list itself, however, is not fixed at asset-definition time. It can be updated after the fact through the `asset_attestors` message type, whose only real constraint is that the sender is the asset's `definer_address` — there is no restriction on frequency, timing, or on removing addresses that were already relied upon: [2](#0-1) 

Because the attested-address check is performed against `objValidationState.last_ball_mci` (the last *stable* ball referenced by the unit being validated, i.e., resolved only at consensus/stabilization time, not at broadcast time), a definer can:
1. Attest a worker's address so the worker can be paid in the job-payment asset.
2. Let the worker do the job, expecting to receive/hold a spendable balance in that asset.
3. Post a fresh `asset_attestors` update removing the worker's attestation, timed/ordered so that it becomes stable before the worker's expected payment unit's `last_ball_mci`.
4. Because the payment's validity is checked against the attestor list *at consensus time* rather than at broadcast time, the previously-fine-looking payment to the worker becomes invalid ("some output addresses are not attested"), and the definer can instead spend the underlying funds elsewhere.

This mirrors the OpenQ pattern precisely: a privileged, unrestricted, always-callable "set the terms" operation (`setPayout` ↔ `asset_attestors`) that the counterparty (claimer/worker) has no way to prevent, and which is checked lazily/at settlement time rather than being locked in when the obligation is created.

### Impact Explanation
An asset issuer/definer using `spender_attested` assets to gate who may receive a payment (e.g., a job-completion/bounty payment token, similar in spirit to OpenQ's split-price bounty) can revoke the recipient's eligibility to be paid after work is completed but before the payment settles, effectively getting work done for free and recovering the funds for themselves. This is a direct loss of funds / freezing-of-funds scenario for the counterparty and satisfies "unauthorized spending" / "AA or asset fund loss" criteria, since spendable balances that were expected to go to the worker can be redirected by the definer at will.

### Likelihood Explanation
This requires the attacker to control the asset's `definer_address` — which is the expected "asset issuer" role explicitly in scope. No colluding third party or network-level attack is needed; the definer only needs to time an ordinary `asset_attestors` unit so that it stabilizes before the victim's payment unit's referenced last ball. Given ocore's DAG/ MCI-based finality, this is a normal, always-available capability for any definer of a `spender_attested` asset, making the likelihood high whenever such an asset is used as a payment/bounty mechanism relying on attestation for eligibility.

### Recommendation
- Snapshot/lock the attestor list (or specific attestations) that a payment depends on at the time the payment obligation is created, rather than re-checking it dynamically at `last_ball_mci` of the spending unit.
- Alternatively, disallow removal of previously-attested addresses that already have unconfirmed but broadcast outputs pending, or require a timelock/cooldown before an attestor-list change can affect already-created payment units.
- At minimum, documentation for `spender_attested` assets should strongly warn that the attestor list is mutable at any time by the definer and re-checked at stabilization, so it must not be used to represent an immutable payment guarantee to a third party.

### Proof of Concept
1. Definer creates asset `A` with `spender_attested: true`, `issued_by_definer_only: true` similar to `validateAssetDefinition`: [3](#0-2) , and posts an initial `asset_attestors` message attesting `worker_address`.
2. Worker performs the requested off-chain work, trusting that once paid in asset `A`, the payment to `worker_address` will be valid because it is currently attested.
3. Definer broadcasts a payment unit `U1` sending asset `A` to `worker_address` (satisfies attestation check at broadcast time).
4. Before `U1` stabilizes, definer broadcasts an `asset_attestors` unit `U2` (validated via `validateAttestorListUpdate`) removing `worker_address` from the attestor list, and ensures `U2` becomes included/stable before `U1`'s `last_ball_mci` is fixed.
5. When `U1` is finally validated against the now-current `last_ball_mci`, `validatePaymentInputsAndOutputs`'s attestation check fails (`some output addresses are not attested`), so `U1` is rejected/treated as invalid, and the definer can spend the same asset balance elsewhere, having received the worker's labor for free.

Note: I was not able to fully trace `storage.filterAttestedAddresses`/`storage.readAsset` implementation details (their bodies were not returned by search) to confirm exact query semantics for historical attestation state at arbitrary MCIs, so the precise ordering/race conditions around "becomes stable before `last_ball_mci`" should be verified against the full `storage.js` source before treating this as fully confirmed exploit mechanics.

### Citations

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

**File:** validation.js (L2725-2743)
```javascript
function validateAssetDefinition(conn, payload, objUnit, objValidationState, callback){
	if (objUnit.authors.length !== 1)
		return callback("asset definition must be single-authored");
	if (!isNonemptyObject(payload))
		return callback("asset definition must be a non-empty object");
	if (hasFieldsExcept(payload, ["cap", "is_private", "is_transferrable", "auto_destroy", "fixed_denominations", "issued_by_definer_only", "cosigned_by_definer", "spender_attested", "issue_condition", "transfer_condition", "attestors", "denominations"]))
		return callback("unknown fields in asset definition");
	if (typeof payload.is_private !== "boolean" || typeof payload.is_transferrable !== "boolean" || typeof payload.auto_destroy !== "boolean" || typeof payload.fixed_denominations !== "boolean" || typeof payload.issued_by_definer_only !== "boolean" || typeof payload.cosigned_by_definer !== "boolean" || typeof payload.spender_attested !== "boolean")
		return callback("some required fields in asset definition are missing");

	if ("cap" in payload && !(isPositiveInteger(payload.cap) && payload.cap <= constants.MAX_CAP))
		return callback("invalid cap");

	if (objValidationState.bAA) {
		if (payload.cosigned_by_definer !== false)
			return callback("cosigned_by_definer must be false because AAs can't cosign");
		if (payload.issued_by_definer_only === true && (payload.is_private !== false || payload.fixed_denominations !== false))
			return callback("assets issued by AA definer cannot be private or fixed denominations");
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
