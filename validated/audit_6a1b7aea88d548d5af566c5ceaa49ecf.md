### Title
Immutable AA logic can be permanently blocked from paying out an asset once its `spender_attested`/`transfer_condition`/`attestors` are set or changed by the (mutable) asset definer - ([File: aa_composer.js])

### Summary
An Autonomous Agent (AA) that forwards a custom asset to end-user addresses (e.g. acting as a pooled deposit/withdrawal contract) can be permanently unable to pay out that asset if the asset's `spender_attested`, `attestors`, or `transfer_condition` settings are added/changed by the asset definer after the AA is deployed and already holding balances. Since AA definitions are immutable once posted, and `aa_composer.js` only performs a partial, "optimistic" check of asset rules while composing the response (skipping `spender_attested`/`transfer_condition`/`cosigned_by_definer`), every trigger that requires the AA to send this asset to a recipient who cannot satisfy the (governance-controlled) condition results in a bounce, and the underlying accounting/queue state advance is rolled back with it — mirroring the EigenLayer `thirdPartyTransfersForbidden` bug where a party outside the affected contract's control can permanently block withdrawals.

### Finding Description
When an AA composes a response containing a `payment` message for a non-base asset, `aa_composer.js` loads the asset info via `storage.loadAssetWithListOfAttestedAuthors` and only rejects `fixed_denominations` and `is_private` assets at this stage: [1](#0-0) 

It does **not** check `objAsset.spender_attested`, `objAsset.transfer_condition`, or `objAsset.cosigned_by_definer` against the intended output addresses before finalizing and signing the response unit. Those checks are only performed later, during full unit validation inside `validation.js`: [2](#0-1) [3](#0-2) 

If any of these conditions fail (e.g. the recipient address is not attested, or the `transfer_condition` — an address/authentifier-based script controlled by the asset's definer, evaluated via `Definition.evaluateAssetCondition` — is not satisfied), `validateAndSaveUnit`'s callback receives an error, and the AA framework simply bounces the entire trigger: [4](#0-3) 

Because a bounce discards all state changes computed during the trigger (state vars, balances, secondary triggers) as if the trigger never ran, an AA that is designed to *always* forward this asset to the trigger's own address/user address (a common pattern for withdrawal/exit logic) will bounce on every subsequent trigger once the definer sets `spender_attested=true` and adds/removes attestors, or updates the `attestors` list via an `asset_attestors` message, or the `transfer_condition` becomes impossible to satisfy for the AA's fixed output-address logic: [5](#0-4) 

The asset definer is not the AA and is not the AA's trigger sender — an unprivileged asset issuer (a party the AA integrates with, such as a partner LP-token asset or a custom lending-collateral asset used by the AA) can unilaterally set these attributes at asset-definition time or later (attestor list updates), and because AA `oscript` code is immutable, there is no way for the AA to adapt its output addresses or add attestation flows after the fact. This is directly analogous to `thirdPartyTransfersForbidden`: an external, governance/definer-controlled setting on the underlying asset makes a legitimate, previously-working payout path from a smart-contract-like construct (the AA) permanently impossible, without any bug in the sender's own logic.

### Impact Explanation
Any AA that receives and later needs to distribute a third-party asset with `spender_attested` or a `transfer_condition` (or which the definer later restricts via `asset_attestors`) can become permanently unable to complete its designed payout flow to end users. Because every failed attempt bounces and rolls back state, user funds/deposits recorded in the AA's state variables remain "stuck" — the AA keeps accepting deposits (or already holds them) but can never execute the corresponding withdrawal/payment message, since the message composition step does not detect the problem early and the final validation always fails the same way. This is a fund-freezing condition equivalent in effect to the original EigenLayer report ("withdrawals are completely broken"), scoped here to Rio-network no, but to any ocore AA-based custodian/vault pattern paying out a governance-restricted asset.

### Likelihood Explanation
This requires an AA design that forwards a non-base asset it doesn't fully control the definition of (e.g. accepts deposits in an externally-issued asset and pays it back out to arbitrary addresses) — a realistic and encouraged AA pattern (vaults, pools, bridges). The asset's `spender_attested`/`attestors`/`transfer_condition` can be set at issuance or later updated by the definer via a single `asset_attestors` message, requiring no coordination with or permission from the AA. No malicious peer/node/hub behavior is needed — only a legitimate, permissionless action by the asset's definer/attestor-address holder.

### Recommendation
- In `aa_composer.js`, when composing outgoing asset payments, explicitly check `objAsset.spender_attested`, `objAsset.attestors`/attested status of the recipient addresses, and `objAsset.transfer_condition` before finalizing the response, and surface this as an explicit AA-level bounce reason rather than relying on late validation failure.
- Provide AA authors documentation/warnings that forwarding third-party assets subject to `spender_attested`/`transfer_condition` risks permanent payout failure, and consider allowing AAs to query these asset properties via getters at oscript-authoring time so contract authors can gate deposits of such assets.
- Consider disallowing AAs from accepting deposits of assets with `spender_attested`/`transfer_condition` enabled unless the AA definition includes a documented mitigation (e.g. paying to the definer/attestor as a fallback), similar to how EigenLayer's fix path would involve allowing an alternate withdrawal target when the primary is blocked.

### Proof of Concept
1. Deploy AA `V` that accepts a custom asset `A` as deposit and, on a later trigger, sends `A` back to `trigger.address` (a common "vault/exit" pattern), e.g.:
```
{
  app: 'payment',
  payload: { asset: 'ASSET_A', outputs: [{ address: '{trigger.address}', amount: '{trigger.output[[asset=ASSET_A]]}' }] }
}
```
2. Asset `A` is defined by an independent party without `spender_attested` initially, so deposits/payouts through `V` work normally.
3. The definer of asset `A` later posts an `asset_attestors` update setting a restrictive attestor list, or the asset was defined with `spender_attested: true`/`transfer_condition` from the start requiring conditions the AA cannot fulfill for arbitrary `trigger.address` recipients: [6](#0-5) 
4. From this point on, every trigger to `V` requesting withdrawal of `A` builds a response unit in `sendUnit` (which does not pre-check `spender_attested`/`transfer_condition`), fails final validation in `validatePaymentInputsAndOutputs`/`validatePayment`, and is bounced: [7](#0-6) 
5. Because the bounce reverts all associated state changes, user balances/deposit records tracked by `V`'s state vars remain unchanged, and there is no way — short of redeploying a new AA (users would need to be migrated) — to release the already-deposited `A` tokens held by `V`.

### Citations

**File:** aa_composer.js (L1323-1330)
```javascript
				storage.loadAssetWithListOfAttestedAuthors(conn, asset, mci, [address], true, function (err, objAsset) {
					if (err)
						return cb(err);
					assetInfos[asset] = objAsset;
					if (objAsset.fixed_denominations) // will skip it later
						return cb();
					if (objAsset.is_private) // it'll fail validation anyway due to lack of spend_proofs
						return cb("sending private asset from AA");
```

**File:** aa_composer.js (L1405-1411)
```javascript
						executeStateUpdateFormula(objUnit, function (err) {
							if (err)
								return bounce(err);
							validateAndSaveUnit(objUnit, function (err) {
								if (err)
									return bounce(err);
								updateFinalAABalances(arrConsumedOutputs, objUnit, function () {
```

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

**File:** validation.js (L2630-2659)
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
					function(cb){
						var arrCondition = bIssue ? objAsset.issue_condition : objAsset.transfer_condition;
						if (!arrCondition)
							return cb();
						Definition.evaluateAssetCondition(
							conn, payload.asset, arrCondition, objUnit, objValidationState, 
							function(cond_err, bSatisfiesCondition){
								if (cond_err)
									return cb(cond_err);
								if (!bSatisfiesCondition)
									return cb("transfer or issue condition not satisfied");
								console.log("validatePaymentInputsAndOutputs with transfer/issue conditions done");
								cb();
							}
						);
					}
				], callback);
```

**File:** validation.js (L2725-2755)
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

	// attestors
	var err;
	if ( payload.spender_attested && (err=checkAttestorList(payload.attestors)) )
		return callback(err);
	if (!payload.spender_attested && "attestors" in payload && (objValidationState.last_ball_mci >= constants.pemCurvesFixMci || !objValidationState.hasBall && storage.getMinRetrievableMci() >= constants.pemCurvesFixMci))
		return callback("attestors should not be defined when spender_attested is false");

	// denominations
	if (payload.fixed_denominations && !isNonemptyArray(payload.denominations))
		return callback("denominations not defined");
	if (!payload.fixed_denominations && "denominations" in payload)
```
