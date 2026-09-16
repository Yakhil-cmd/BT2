### Title
Spender-attested assets can permanently freeze existing holders' funds when the definer updates the attestor list, with no escape-valve equivalent to the `is_transferrable` exemption - ([File: validation.js])

### Summary
When an asset is defined with `spender_attested: true`, the set of addresses allowed to hold/move the asset is not fixed at issuance time but is re-evaluated dynamically against the *current* attestor list every time a payment is validated. The definer can update this list at any time via an `asset_attestors` message. A user who legitimately acquired the asset while attested can later be excluded from the attestor list and then becomes permanently unable to move the coins they already hold — not even back to the definer — because, unlike the `is_transferrable` check (which has an explicit exemption for sending to/from the definer), the `spender_attested` output check requires *all* output addresses of the payment to be currently attested, with no such exemption.

### Finding Description
`storage.readAsset()` resolves the attestor list dynamically by always fetching the *latest* `asset_attestors` unit before `last_ball_mci`, not the list that was in effect when the holder acquired the asset: [1](#0-0) 

The definer can push a new attestor list at any time; the only requirements are single-authorship and that the sender is the asset definer: [2](#0-1) 

At spend time, both inputs and outputs are checked against this current list. On the input/spend side, an owner address that is no longer attested cannot spend the coin it already holds: [3](#0-2) 

On the output side, **every** output address of the payment — including any change output back to the payer, or a payment sent to the definer/anyone else — must currently be attested, or the whole payment is rejected: [4](#0-3) 

Contrast this with the `is_transferrable` check just above it, which explicitly special-cases payments that send funds to, or return change from, the definer address, precisely so that a holder can still exit a non-transferrable asset back to its definer: [5](#0-4) 

No equivalent exemption exists for `spender_attested`. So a holder who becomes un-attested cannot even perform the "send back to definer" exit that is otherwise permitted for non-transferrable assets — their balance is fully stuck, with no available payment shape that satisfies the attestor check.

### Impact Explanation
This causes permanent freezing of already-issued, legitimately-held asset balances following a routine, non-malicious action by the asset definer (updating the attestor list, e.g. to remove a compromised or retired attestor, or to tighten compliance rules). Users who received the asset before the change find their funds unspendable in any direction — they cannot transfer to a third party, and they cannot even fall back to sending them to the definer as an exit path, since `filterAttestedAddresses` rejects the payment if any output address (including the definer's, if not itself attested/whitelisted at spend time) is not attested. This matches the "asset issuance and transfer conditions" freezing category and is a genuine loss-of-funds/availability issue for holders, not merely a resource/DoS concern.

### Likelihood Explanation
Reaching this requires only: (1) an asset issuer defining a `spender_attested: true` asset and publishing an initial attestor list (a normal, supported feature), (2) a user acquiring the asset while attested (normal usage), and (3) the definer later publishing an updated `asset_attestors` message that drops that user's attesting relationship (a routine, privileged but expected administrative action, analogous to the "protocol owner enables whitelist" step in the referenced report). No malicious peer, node, or network condition is required — a single posted `asset_attestors` unit by the legitimate definer is sufficient to trigger the freeze for existing holders.

### Recommendation
Add an escape-valve for `spender_attested` assets analogous to the one used for `is_transferrable`: allow payments whose outputs go solely to the asset's `definer_address` (or otherwise back to the payer as documented "return" outputs) to bypass the "all outputs must be attested" check in `validatePaymentInputsAndOutputs` (validation.js:2630-2641), so that holders who fall out of attestation always retain the ability to return/burn their balance to the definer even if they can no longer transfer it elsewhere.

### Proof of Concept
1. Definer issues asset `A` with `spender_attested: true` and an initial `attestors` list including attestor `X`.
2. Attestor `X` attests address `Alice`.
3. Alice receives a balance of asset `A` (payment validated successfully because she is attested — validation.js:2115-2122, 2506, 2632-2641).
4. Definer publishes a new `asset_attestors` message for asset `A` that no longer includes attestor `X` (or `X` revokes/ceases attesting `Alice`) — allowed unconditionally by `validateAttestorListUpdate` (validation.js:2829-2848), with no restriction protecting existing holders.
5. `storage.readAsset()` now resolves `objAsset.arrAttestorAddresses` to the new list (storage.js:1917-1946), and `filterAttestedAddresses` no longer returns `Alice` as attested.
6. Alice attempts to spend her existing balance — any payment she constructs, whether to a third party or back to the definer, fails the output-attestation check at validation.js:2632-2641 (`"some output addresses are not attested"`), and if she is the sole input owner she also fails the input check at validation.js:2506 (`"owner address is not attested"`). Her balance is permanently unspendable.

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

**File:** validation.js (L2504-2507)
```javascript
							if (objAsset && objAsset.auto_destroy && owner_address === objAsset.definer_address)
								return cb("this output was destroyed by sending it to definer address");
							if (objAsset && objAsset.spender_attested && objAsset.arrAttestedAddresses.indexOf(owner_address) === -1)
								return cb("owner address is not attested");
```

**File:** validation.js (L2616-2629)
```javascript
				if (!objAsset.is_transferrable){ // the condition holds for issues too
					if (arrInputAddresses.length === 1 && arrInputAddresses[0] === objAsset.definer_address
					   || arrOutputAddresses.length === 1 && arrOutputAddresses[0] === objAsset.definer_address
						// sending payment to the definer and the change back to oneself
					   || !(objAsset.fixed_denominations && objAsset.is_private) 
							&& arrInputAddresses.length === 1 && arrOutputAddresses.length === 2 
							&& arrOutputAddresses.indexOf(objAsset.definer_address) >= 0
							&& arrOutputAddresses.indexOf(arrInputAddresses[0]) >= 0
					   ){
						// good
					}
					else
						return callback("the asset is not transferrable");
				}
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
