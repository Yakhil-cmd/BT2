### Title
Asset definer can retroactively weaponize the mutable attestor list of a `spender_attested` asset to freeze already-held user funds - (File: `validation.js`)

### Summary
For any asset created with `spender_attested: true`, the asset definer can publish an `asset_attestors` message at any later time to arbitrarily replace the list of addresses allowed to hold/receive the asset. Validation of this update only checks that the sender is the definer and that the new list is well-formed — it does not preserve any commitment to holders who already acquired and are holding the asset under the previous attestor list. This mirrors the `BoostAggregator` bug: a party trusted at "deposit time" (issuance time) can unilaterally change a parameter afterward (attestor list ≈ protocol fee) and inflict a 100%-style loss of usability/value on users who already committed funds, even though the asset is "supposed to be publicly usable" by anyone who satisfied the attestation requirement at acquisition time.

### Finding Description
`spender_attested` assets require every output (recipient) address of a payment to be on the definer-controlled attestor list, checked in `validatePaymentInputsAndOutputs`: [1](#0-0) 

The attestor list itself is not fixed at asset-definition time; it is a separate, independently-updatable message type (`asset_attestors`) that the definer can send whenever they want, with essentially no restriction other than being the definer and supplying a syntactically valid list: [2](#0-1) [3](#0-2) 

Crucially, `readAsset`/`loadAssetWithListOfAttestedAuthors` always resolves to the *latest* attestor list at validation time, not the list that was in effect when a holder acquired the asset: [4](#0-3) 

So a user can legitimately receive/hold a `spender_attested`, transferable asset while attested, and later find that the definer published a new `asset_attestors` list that drops their address (or drops all addresses except the definer's own). Because the output-address attestation check in `validatePaymentInputsAndOutputs` applies to every payment, transferable or not, the holder can no longer move their balance to any address except (at best) the definer's own attested address — exactly the "owner controls a knob that lets them capture funds already committed by users" pattern from the `BoostAggregator` report, where the owner could raise `protocolFee` to 100% after users had already deposited/staked.

The bug class match:
- `BoostAggregator`: owner-controlled `protocolFee` (bounded 0–100%) can be changed post-deposit, with no snapshot of the fee at deposit time, letting the owner seize 100% of the user's already-accrued rewards.
- ocore analog: definer-controlled attestor list (also just a definer signature away) can be changed post-acquisition, with no snapshot of the attestor set that applied when the holder received the coins, letting the definer strand/redirect the user's already-held asset balance.

### Impact Explanation
Any holder of a `spender_attested`, transferable asset is exposed to having their balance frozen or effectively expropriated at the sole discretion of the asset definer, at any point after they acquired the asset — not just at issuance. This breaks the implicit guarantee that once an address is attested and holds the asset, it can keep transacting it under the rules in force when it acquired the funds. Because attestor updates are validated purely on "sender is definer" with no reference to prior holder state, this is systemic to every `spender_attested` asset in ocore, not merely a hypothetical single dApp.

### Likelihood Explanation
This requires only the (implicitly trusted) asset definer — the same trust boundary explicitly acknowledged by the judge for the original `BoostAggregator` finding ("a fair level of trust is assumed... but the loss... is serious, therefore medium is appropriate"). No cooperation from validators, witnesses, or other parties is needed; a single `asset_attestors` unit from the definer is sufficient and is fully within the documented, reachable message-validation path (`validateInlinePayload` → `validateAttestorListUpdate`). [5](#0-4) 

### Recommendation
When validating a payment's output addresses against the attestor list (`validatePaymentInputsAndOutputs`), do not simply use the attestor list current as of `last_ball_mci`; alternatively, when an `asset_attestors` update is published, only apply it to units created after the update, and/or grandfather already-attested holders so that a definer cannot retroactively de-attest existing balances. At minimum, follow the pattern the Maia team adopted for `BoostAggregator`: bind the applicable attestor list to the moment the holder received the funds (e.g., record/verify against the attestor list in effect at the time of the output-creating unit) rather than always resolving to the latest list at spend time.

### Proof of Concept
1. Definer creates asset `X` with `spender_attested: true`, `is_transferrable: true`, and an initial attestor list `[A]`.
2. Definer attests address `A` normally; user `A` receives/holds a balance of `X` (validated fine because `A` is attested per `validatePaymentInputsAndOutputs`/`filterAttestedAddresses`).
3. At any later time, definer publishes `{app: "asset_attestors", payload: {asset: X, attestors: [D]}}` (only `D`, the definer's own address). This passes `validateAttestorListUpdate` because it only checks `objUnit.authors[0].address === objAsset.definer_address` and `checkAttestorList`.
4. `readAsset` now returns `arrAttestorAddresses = [D]` for any subsequent validation (`storage.js:1917-1946`).
5. User `A` tries to send any of their existing `X` balance to any address other than `D`; `validatePaymentInputsAndOutputs` rejects it with `"some output addresses are not attested"` because `A`'s target address is no longer on the list — the balance is frozen/effectively expropriated despite having been acquired legitimately under the old attestor set.

### Citations

**File:** validation.js (L2033-2042)
```javascript
		case "asset_attestors":
			if (!isStringOfLength(payload.asset, constants.HASH_LENGTH))
				return callback("invalid asset in attestor list update");
			if (!objValidationState.assocHasAssetAttestors)
				objValidationState.assocHasAssetAttestors = {};
			if (objValidationState.assocHasAssetAttestors[payload.asset])
				return callback("can be only one asset attestor list update per asset");
			objValidationState.assocHasAssetAttestors[payload.asset] = true;
			validateAttestorListUpdate(conn, payload, objUnit, objValidationState, callback);
			break;
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
