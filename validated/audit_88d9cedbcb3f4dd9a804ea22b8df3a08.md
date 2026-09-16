### Title
Assets requiring `spender_attested` become permanently frozen once the definer publishes a new attestor list that drops a previously attested address - ([File: validation.js])

### Summary
Divisible/indivisible payment assets can be defined with `spender_attested: true`, meaning only addresses currently on the asset's attestor whitelist may hold/spend the asset. That whitelist is fully replaceable via an `asset_attestors` message, and only the *latest* published list counts. If the definer/attestor later publishes a new list that omits an address that legitimately received (and passed attestation checks for) coins earlier, those coins become permanently unspendable, exactly mirroring the reported "token can't be redeemed after removal from whitelist" bug class.

### Finding Description
When an asset has `spender_attested: true`, `storage.readAsset()` resolves the current attestor set by picking only the single most-recent `asset_attestors` unit (`ORDER BY level DESC LIMIT 1`), i.e. the list is fully overwritten rather than accumulated: [1](#0-0) 

`validateAttestorListUpdate` allows only the asset's definer to publish a brand-new attestor list for the asset, with no restriction requiring previously-attested holders to be preserved: [2](#0-1) 

At the time coins are received, the payment's output addresses must currently be in the attestor-derived `arrAttestedAddresses` set: [3](#0-2) 

But when that same holder later tries to spend (transfer) those coins as an input, `validatePaymentInputsAndOutputs` re-checks attestation against the *current* list and rejects the input if the owner address is no longer attested: [4](#0-3) 

The same re-check happens on the issuer/author side for `validatePayment`: [5](#0-4) 

Because attestation status is evaluated dynamically at spend-time against the newest list (rather than being tied to the attestation state at receipt time), the definer can publish an updated `asset_attestors` list that drops an address, and any coins already held by that address become permanently unspendable — there is no path (transfer condition, definer override, or grace period) to redeem or move funds already legitimately acquired while attested.

### Impact Explanation
This is a direct fund-freezing bug: legitimately-received asset balances become permanently locked and unspendable as soon as the address is dropped from a subsequent attestor-list update, with no recovery mechanism in the protocol. Any application or AA-issued asset using `spender_attested` for KYC/whitelist-style compliance is affected, and end users have no way to prevent or reverse the freeze once it occurs.

### Likelihood Explanation
Any asset issuer/attestor can (intentionally, mistakenly, or due to a compromised key) publish an `asset_attestors` update that omits an address currently holding coins; this is a normal, allowed operation requiring only the definer's signature (`validateAttestorListUpdate`, `validation.js:2829-2848`) and no special "malicious node" behavior. Given `spender_attested` assets are an in-protocol feature intended for regulated/whitelisted asset use cases, this is a realistically reachable scenario, not a hypothetical edge case.

### Recommendation
Decouple spend-time authorization from real-time attestor-list membership for coins already received while attested, e.g.:
- Snapshot/record attestation status at the time an output is created and allow spending based on that historical attestation rather than the latest list, or
- Provide an explicit unlock/redemption path (analogous to removing the whitelist check in `redeem()`) so previously-attested holders can still move/redeem coins they legitimately acquired even after being removed from the current attestor list, or
- Require attestor-list updates to be strictly additive (never removing previously attested addresses with existing balances) unless combined with an explicit migration/redemption mechanism for affected holders.

### Proof of Concept
1. Definer issues asset `A` with `spender_attested: true` and attestor list `[Attestor1]`.
2. `Attestor1` attests `Alice`'s address. Definer/asset issuer sends payment of asset `A` to `Alice` — this passes `filterAttestedAddresses` check in `validation.js:2630-2641` since `Alice` is currently attested.
3. Definer later publishes a new `asset_attestors` message for asset `A` with a list that no longer contains an attestation for `Alice` (e.g., `[Attestor2]`), which is accepted per `validateAttestorListUpdate` (`validation.js:2829-2848`) since only definer-signature is required.
4. `Alice` now tries to transfer/spend her previously received coins of asset `A`. `validatePaymentInputsAndOutputs` looks up `objAsset.arrAttestedAddresses` from the new (current) attestor list and rejects the input at `validation.js:2504-2507` ("owner address is not attested") — even though `Alice` was fully compliant and attested at the time she received the funds.
5. `Alice`'s coins remain permanently locked; there is no code path allowing her to redeem or move them.

### Citations

**File:** storage.js (L1921-1946)
```javascript
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

**File:** validation.js (L2504-2507)
```javascript
							if (objAsset && objAsset.auto_destroy && owner_address === objAsset.definer_address)
								return cb("this output was destroyed by sending it to definer address");
							if (objAsset && objAsset.spender_attested && objAsset.arrAttestedAddresses.indexOf(owner_address) === -1)
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
