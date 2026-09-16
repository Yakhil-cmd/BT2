The strongest analog in ocore to this "disable mechanism blocks both deposits *and* withdrawals" bug class is the `spender_attested` asset feature and its attestor-list update mechanism.

### Title
Asset attestor-list updates evaluate against the *current* attestor list rather than the list valid at receipt time, permanently freezing already-held coins for holders who lose attestation - ([File: validation.js])

### Summary
When an asset is defined with `spender_attested: true`, every payment (issue or transfer) of that asset requires all input owner addresses *and* all output addresses to be currently attested by one of the asset's attestors. The attestor list can be updated at any time by the asset definer via an `asset_attestors` message. Because the spend-time check always resolves against the *latest* attestor list rather than the list that was valid when the coins were received, a holder who is later removed from the attestor list becomes permanently unable to move coins they legitimately hold — even to their own change address — mirroring the external report's core defect where a "disable" mechanism blocks legitimate withdrawals along with the intended restriction.

### Finding Description
Asset definitions carry a `spender_attested` flag; when true, `validatePayment` requires that all authors (owners of inputs) be in the asset's attested-address list before allowing any spend, and separately `validatePaymentInputsAndOutputs` requires that all output addresses (including change returned to the sender) also be attested, via `storage.filterAttestedAddresses`. [1](#0-0) [2](#0-1) 

The attested address list used at validation time is always the most recently published list, resolved independently of when the spender actually received the coins: [3](#0-2) 

The list is updated via the `asset_attestors` message, which only requires that the sender is the asset's definer and that the new list is well-formed — there is no restriction preventing the definer from removing addresses that currently hold balances of the asset: [4](#0-3) 

Per-input ownership checks also re-verify attestation against the *current* list rather than the list valid when the output was created, both for divisible-asset spends and for private fixed-denomination assets: [5](#0-4) [6](#0-5) 

The result: once an address's attestation is revoked (or an attestor simply drops it in an update), any coins of that asset already held by that address become permanently unspendable — the holder cannot even send the coins back to a different one of their own attested addresses, because the *input* owner address itself must be currently attested, not just the destination.

### Impact Explanation
This is a fund-freezing bug directly analogous to the Lido-pause issue described in the external report: a control mechanism intended only to gate new activity (who may receive freshly-attested compliance status) instead also blocks the ability of existing, legitimately-received balances to be withdrawn/moved. For any `spender_attested` asset, an attestor-list update by the definer (which is a completely normal, expected administrative action for compliance-gated assets) can strand user funds with no path to recovery on-chain, since neither issuance rules nor payment rules make any allowance for previously-received balances.

### Likelihood Explanation
`spender_attested` assets are an explicit, documented feature of ocore intended for regulated/attested tokens, and attestor-list rotation (e.g., replacing a compromised attestor, or an attestor withdrawing service) is an expected, routine event for such assets over their lifetime. Any definer performing a normal attestor-list update that drops or fails to re-add an address that holds balance will trigger this freeze without any special or malicious intent required.

### Recommendation
Evaluate the input-owner attestation requirement against the attestor list that was in effect when the output being spent was created (or at least allow spending back to previously-attested addresses / to the definer) rather than always requiring current attestation of the owner. Alternatively, document and enforce that attestor-list updates cannot remove addresses with outstanding balances until those balances are moved, or provide an explicit unwind/exit path (e.g., an exception allowing return-to-definer or return-to-self transfers regardless of current attestation status) so that revoking attestation cannot strand funds.

### Proof of Concept
1. Definer creates asset `X` with `spender_attested: true` and attestor list `[A]`.
2. Attestor `A` attests address `H`.
3. `H` receives a payment of asset `X` (valid, since `H` is attested at the time — checked via `filterAttestedAddresses` in `validatePaymentInputsAndOutputs`). [2](#0-1) 
4. Definer posts `asset_attestors` message removing `H`'s attestation path (e.g., attestor `A` de-attests `H`, or the list is replaced without re-attesting `H`). [4](#0-3) 
5. `H` attempts to spend the previously received `X` coins, even just to send change back to itself: `validatePayment` fails with `"none of the authors is attested"` (or the per-input `"owner address is not attested"` check fails), because the check re-resolves attestation against the current list via `readAsset`/`filterAttestedAddresses`, not the list valid when `H` received the funds. [1](#0-0) [6](#0-5) 
6. `H`'s balance of asset `X` is now permanently frozen with no on-chain mechanism to release it.

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
