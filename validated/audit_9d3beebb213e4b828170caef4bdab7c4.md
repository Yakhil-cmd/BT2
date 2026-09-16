### Title
Asset issuer can update the `asset_attestors` list to zero attestors, permanently freezing `spender_attested` asset holders' funds - (File: validation.js)

### Summary
This mirrors the `Freefall.removePool()` bug class: a privileged-but-reachable actor (the asset definer/issuer) can mutate a registry (`liquidityPool` → analog: the asset's attestor list) that a later validation gate (`isTokenSupported` → analog: the `spender_attested`/`arrAttestedAddresses` check in `validatePayment`) depends on, without any check for existing token holders. Once the gate fails for those holders, they have no path to move or reclaim their asset balance.

### Finding Description
An asset can be defined with `spender_attested: true`, requiring every spending author to be on the attestor list before a payment in that asset validates [1](#0-0) . The attestor list itself is not fixed at asset creation — it can be updated later via an `asset_attestors` message, which is validated once per asset per unit and dispatched to `validateAttestorListUpdate` [2](#0-1) .

When a payment in that asset is later validated, `validatePayment` loads the *current* attestor list via `loadAssetWithListOfAttestedAuthors`/`storage.filterAttestedAddresses` and hard-fails if none of the paying authors are attested, or (for issuance) if the issuer specifically is not attested [3](#0-2) . The transferability check itself is likewise gated purely by the asset's live attributes (`objAsset.is_transferrable`, `spender_attested`) with no accounting for outstanding balances held by addresses that are about to lose eligibility [4](#0-3) .

This is structurally identical to `removePool()`: the attestor-list state is deleted/replaced (analogous to `delete liquidityPool[_tokenAddress]`) without verifying that no address currently holding the asset would be locked out, and the downstream spend-validation gate (`arrAttestedAddresses.length === 0` / not-attested owner check) then permanently blocks every non-attested holder's payment message, exactly like `isTokenSupported`/`isActive` blocking `withdraw()`.

### Impact Explanation
Any holder of a `spender_attested` asset who is not on the attestor list after an update can never again spend, transfer, or move their balance of that asset — the payment message will always fail `validatePayment`'s attestation check [3](#0-2) . Since divisible-asset outputs also carry per-owner-address checks in the input path (`objAsset.spender_attested && arrAttestedAddresses.indexOf(owner_address) === -1`), even attempts to spend older unspent outputs from a since-deattested address are rejected [5](#0-4) . This is a fund-freezing condition equivalent in class to the reported issue: no escape hatch exists for a holder whose address falls off the attestor list, and the change is entirely at the discretion of the asset definer, with no explicit balance-safety check before the update is validated/applied.

### Likelihood Explanation
Reaching this requires only two ordinary, permission-less actions already supported by the protocol: (1) issuing/holding a `spender_attested` asset as a normal user, and (2) the asset's definer posting a standard `asset_attestors` update message (a normal single message type, not privileged network access) that removes or replaces attestors. No node collusion, hub compromise, or private key leak is needed — the definer role is a first-class asset-issuer capability explicitly reachable in ocore's message set, matching the exploitable actors permitted for this analysis (asset issuer). This can also happen accidentally, exactly like the original report describes for `removePool()`.

### Recommendation
Before allowing an `asset_attestors` update to take effect, or as part of `validateAttestorListUpdate`, require that any address holding a positive spendable balance of the asset either remains attested, or provide a fallback/redemption path (e.g., allow a payment to be validated using proof of a formerly-valid attestor list, or a definer-initiated escape/refund mechanism) so that de-attested holders are not permanently locked out of assets they already legitimately hold.

### Proof of Concept
1. Issuer `D` defines asset `A` with `spender_attested: true`, `attestors: [X]`.
2. User `H` receives a payment output in asset `A` (validated because `H` or `X` satisfies the attestor check at issuance time) — validated per `validatePayment`/`validatePaymentInputsAndOutputs` [6](#0-5) .
3. Issuer `D` posts an `asset_attestors` message removing `X`/replacing it with a different address list that does not include any address associated with `H`'s spending authority — processed via the `asset_attestors` case in `validateInlinePayload` [2](#0-1) .
4. `H` attempts to spend/transfer their previously-received asset `A` balance. `validatePayment` calls `storage.loadAssetWithListOfAttestedAuthors` with the new (updated) attestor list; `objAsset.arrAttestedAddresses` no longer includes `H`'s author address, so the check `arrAttestedAddresses.length === 0` (or non-inclusion for issuance) fails and the payment is rejected [3](#0-2) .
5. `H`'s balance of asset `A` is now permanently unspendable with no recovery mechanism in the codebase.

### Citations

**File:** validation.js (L2033-2041)
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
```

**File:** validation.js (L2115-2123)
```javascript
		if (objAsset.spender_attested){
			if (conf.bLight && objAsset.is_private) // in light clients, we don't have the attestation data but if the asset is public, we trust witnesses to have checked attestations
				return callback("being light, I can't check attestations for private assets"); // TODO: request history
			if (objAsset.arrAttestedAddresses.length === 0)
				return callback("none of the authors is attested");
			if (bIssue && objAsset.arrAttestedAddresses.indexOf(issuer_address) === -1)
				return callback("issuer is not attested");
		}
		validatePaymentInputsAndOutputs(conn, payload, objAsset, message_index, objUnit, objValidationState, callback);
```

**File:** validation.js (L2506-2507)
```javascript
							if (objAsset && objAsset.spender_attested && objAsset.arrAttestedAddresses.indexOf(owner_address) === -1)
								return cb("owner address is not attested");
```

**File:** validation.js (L2606-2641)
```javascript
		},
		function(err){
			console.log("inputs done "+payload.asset, arrInputAddresses, arrOutputAddresses);
			if (err)
				return callback(err);
			if (total_input > constants.MAX_CAP)
				return callback("total input too large: " + total_input);
			if (objAsset){
				if (total_input !== total_output)
					return callback("inputs and outputs do not balance: "+total_input+" !== "+total_output);
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
