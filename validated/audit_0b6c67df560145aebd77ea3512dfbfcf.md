### Title
Asset holders permanently lose ability to transfer/spend a `spender_attested` asset once the attestor list de-attests their address - ([File: validation.js])

### Summary
For assets defined with `spender_attested: true`, every payment message spending that asset requires **all** output addresses (not just the issuer) to currently be attested. Attestation status is dynamic: an `asset_attestors` message can change the attestor list at any time. If an address that legitimately received/held units of the asset while attested is later removed from the attestor list, it becomes permanently unable to move those units in any future payment - even a self-payment/change output - mirroring the reported bug class where de-whitelisting an asset locks users out of assets they already hold.

### Finding Description
`validatePaymentInputsAndOutputs` enforces, for every `payment` message spending a `spender_attested` asset, that all output addresses are attested at validation time: [1](#0-0) 

This check has no allowance for previously-received, now-unattested balances - unlike the adjacent `is_transferrable` check just above it, which explicitly special-cases sending change back to oneself or to the definer: [2](#0-1) 

The attestor list itself is fully mutable after asset creation via the `asset_attestors` message, validated here: [3](#0-2) 
and in the AA-definition validator: [4](#0-3) 

At issue/transfer time, the current attestor list is checked live via `objAsset.arrAttestedAddresses`, computed by `storage.loadAssetWithListOfAttestedAuthors`/`filterAttestedAddresses` against the current attestor set, not against the attestor set that was active when the units were received: [5](#0-4) 

Consequently, a completely ordinary sequence produces permanently frozen funds:
1. Asset X is defined with `spender_attested: true` and some attestor set A.
2. Attestor A attests address U. U legitimately receives units of asset X (issue or transfer to U passes the check).
3. The asset definer or an authorized party posts a new `asset_attestors` message removing U's attestor, or the attestor simply stops attesting U (attestation is per-message and can lapse/be revoked).
4. U now holds a balance of asset X but every future attempt to spend it - including sending it to another attested address, or splitting/returning it to itself - fails the check at `validation.js:2637` ("some output addresses are not attested"), because *all* outputs, including any change back to U itself, must be attested.

This is functionally identical to the reported UXD issue: an asset that was valid ("whitelisted") when acquired becomes unspendable once it is de-whitelisted, with no code path to exit the position.

### Impact Explanation
This causes concrete, permanent loss of access to funds (AA fund loss / freezing analog) for any holder of a `spender_attested` asset whose attestation is revoked after they received the asset. Because the check applies uniformly to issue and transfer, and covers every output address without exception for self-payments, there is no way for the affected address to ever move the balance again as long as it remains unattested - this is a real freezing-of-funds bug reachable by ordinary asset design (any user can define such an asset) and ordinary attestor behavior (attestors are expected to update attestations over time).

### Likelihood Explanation
`spender_attested` is a documented, supported asset feature and attestor lists are explicitly designed to be updatable via `asset_attestors`. Any asset issuer who builds a compliance/whitelist-style asset using this exact mechanism (a common use case for `spender_attested`) will, by design, eventually revoke attestations for departing/non-compliant users - immediately triggering this permanent freeze for those users' existing balances. This does not require any malicious actor; it is triggered by the normal, intended operation of the attestation feature.

### Recommendation
When `spender_attested` is true, allow spending to move the asset without requiring attestation for outputs that merely return funds to the input address(es) (i.e., mirror the same self-payment/change carve-out already implemented for `is_transferrable` at `validation.js:2617-2624`), or otherwise provide an explicit unwind/exit path (e.g., allow transfer to the definer, or allow burn) for holders whose attestation has been revoked, so that previously-attested holders are not permanently locked out of assets they legitimately acquired.

### Proof of Concept
1. Define asset X with `spender_attested: true`, `issued_by_definer_only: false`, attestors = [Attestor A].
2. Attestor A posts an `attestation` for address U's profile.
3. U receives a transfer of asset X (passes `validation.js:2632-2641` because U is attested).
4. Definer posts `asset_attestors` for asset X removing Attestor A (or Attestor A stops posting fresh attestations, and any mci-window/staleness rule invalidates U's prior attestation) - see `validation.js:2033-2041` for how the update is accepted.
5. U attempts to send/return any amount of asset X (even fully to itself) - `validateAssetPayment`/`validatePaymentInputsAndOutputs` calls `storage.filterAttestedAddresses` on the current attestor set (`validation.js:2634-2640`) which now excludes U, and the payment is rejected with "some output addresses are not attested," permanently freezing U's balance.

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

**File:** aa_validation.js (L338-352)
```javascript
				case 'asset_attestors':
					if (hasFieldsExcept(payload, ['asset', 'attestors', 'init']))
						return cb2("foreign fields in attestor list update");
					if (!isNonemptyString(payload.asset))
						return cb2("asset is not a string");
					var asset_formula = getFormula(payload.asset);
					if (asset_formula !== null) {
					}
					else if (!isValidBase64(payload.asset, constants.HASH_LENGTH))
						return cb2("bad asset in asset_attestors: " + payload.asset);
					validateFieldWrappedInCases(payload, 'attestors', validateAttestors, function (err) {
						if (err)
							return cb2(err);
						cb2();
					});
```
