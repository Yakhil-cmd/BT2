### Title
Asset issuers can freeze AA funds and block liquidations by weaponizing `transfer_condition`/`spender_attested` on custom assets - ([File: validation.js])

### Summary
ocore lets an asset definer attach `issue_condition`/`transfer_condition` formulas and a mutable `attestors` allow-list (`spender_attested`) to any custom asset. These are evaluated on *every* payment of that asset, including payments composed by Autonomous Agents (AAs). Because the definer can update the attestor list at any time via an `asset_attestors` message, and the transfer condition can reference arbitrary formula logic, an asset that today satisfies an AA's collateral/liquidation payout can later be turned into a "pausable" asset whose transfers always fail — exactly the bug class described in the Sherlock report about pausable collateral tokens breaking `liquidateLoan()`.

### Finding Description
When an asset is defined, `validateAssetDefinition` in `validation.js` accepts `issue_condition`, `transfer_condition`, `spender_attested`, and `attestors` fields, and validates the conditions with `Definition.validateDefinition`: [1](#0-0) [2](#0-1) 

The definer of an asset with `spender_attested: true` can subsequently change the attestor list at will through `validateAttestorListUpdate`, which only checks that the sender is the original definer — there is no restriction preventing the definer from removing previously-attested addresses (e.g., an AA acting as a lending/collateral vault) from the list: [3](#0-2) 

Every payment of that asset — public or AA-generated — is checked against the current attestor list and the current `transfer_condition`/`issue_condition` at validation time, not at asset-definition time: [4](#0-3) 

`Definition.evaluateAssetCondition` evaluates the (possibly complex, data-feed-dependent) condition through the same expression engine used for address definitions: [5](#0-4) 

When an AA tries to compose and send a payment of such a custom asset, it calls `storage.loadAssetWithListOfAttestedAuthors`, builds the payment, and then calls `validateAndSaveUnit`. If validation fails (e.g. because the current attestor list no longer includes the payout address, or `transfer_condition` no longer evaluates to true), the AA aborts and calls `bounce(err)`, discarding the response messages that were supposed to update AA state and release/transfer the asset: [6](#0-5) [7](#0-6) 

Critically, an AA has no reliable way to detect in advance whether a transfer/issue condition will still be satisfied for a specific recipient/output — the `asset[...]` formula getter only exposes boolean/scalar metadata fields (`is_transferrable`, `spender_attested`, `cap`, etc.), not the actual evaluated result of `transfer_condition` for a hypothetical output: [8](#0-7) 

This means an AA (e.g. a lending/vault contract) that accepted a third-party asset as collateral, verifying only the boolean flags at accept-time, can later have its ability to transfer/release that same asset revoked unilaterally by the asset's definer, simply by publishing an `asset_attestors` update or by having designed the `transfer_condition` to reference mutable external state (a data feed, another address's definition, etc.) that they later flip.

### Impact Explanation
Any AA holding a custom, non-base asset as collateral, escrow, or any transferable balance is exposed to unilateral freezing by that asset's definer:
- The AA's attempt to send/release/liquidate the asset bounces, so the collateral remains stuck inside the AA's balance and the AA's state variables tracking the position are never updated to reflect a successful release.
- Because the trigger bounces, users cannot retrieve their funds or trigger liquidation through that AA, and the AA cannot progress its intended logic (e.g., it cannot pay out a borrower, cannot execute a liquidation transfer, cannot close a position) — this is an on-chain analog of `liquidateLoan()` reverting on a paused ERC20 in the original report.
- Since the condition/attestor list can be changed after the AA has already accepted deposits (there is no mechanism forcing conditions to be frozen at accept time), this is a genuine "AA fund loss or freezing" vector reachable by a normal, unprivileged asset issuer (their own asset definition + subsequent `asset_attestors` update), not a privileged/hub/node actor.

This qualifies as Medium severity: it requires the asset issuer to act (their own asset, reachable posting rights), but the resulting freeze of third-party AA funds/collateral is a direct, concrete consequence of ocore's design that any AA developer integrating third-party assets must account for and currently has no protocol-level protection against.

### Likelihood Explanation
Likelihood is moderate: it requires an AA to accept a non-base, condition-bearing or attestor-gated asset as collateral/escrow without restricting itself to base bytes or a small set of vetted assets, and it requires the asset's own definer (not a network attacker) to change the attestor list or exploit an already-adversarial `transfer_condition`. Because AA developers commonly build generic multi-asset vaults/lending markets, and because ocore's `asset[...]` formula getters do not let an AA foresee condition failures before attempting the transfer, this scenario is realistically triggerable, especially by a malicious or compromised asset issuer targeting an AA that has accepted deposits of their asset.

### Recommendation
- Provide AAs a way to pre-check whether a `transfer_condition`/`issue_condition` and the current attestor list would authorize a specific candidate payment (e.g., a formula getter that dry-runs `evaluateAssetCondition`), so AAs can refuse deposits of assets whose transferability can be revoked, or refuse to proceed with logic that depends on later releasing such an asset.
- Consider disallowing (or requiring an immutability flag for) `transfer_condition`/`spender_attested` updates on assets once they have non-zero balances held by AAs, or expose an on-chain flag distinguishing "condition can still change" from "condition is now frozen."
- At minimum, document prominently (and perhaps add a static-analysis/validator warning in `aa_validation.js`) that AAs holding third-party assets with `transfer_condition` or `spender_attested` are exposed to definer-controlled freezing, so AA authors can defensively avoid accepting/holding such assets as collateral.

### Proof of Concept
1. Asset issuer defines asset `X` with `spender_attested: true` and an initial `attestors` list that includes a lending AA's address `L` (so `L` can receive/hold/transfer `X`), per `validateAssetDefinition`/`checkAttestorList` in `validation.js`.
2. A borrower deposits `X` as collateral into AA `L` (a lending/vault AA). `L`'s definition, at accept time, only checks boolean flags such as `asset[X].is_transferrable` and `asset[X].spender_attested` via the `asset[]` formula getter (`formula/evaluation.js`), which reveal nothing about future condition satisfiability.
3. Time passes; the price of collateral drops, and the position becomes liquidatable. A liquidator triggers `L` to release/transfer the collateral `X` to the liquidator's address.
4. Before the liquidation trigger is processed, the asset issuer publishes an `asset_attestors` message removing the liquidator's address (or `L`'s address as an intermediate hop) from the attestor list, or — if a `transfer_condition` was defined — the issuer's condition (which may reference a data feed or another mutable address definition) now evaluates to false for this transfer, per `validatePaymentInputsAndOutputs` in `validation.js` (lines 2630-2659).
5. When `L` composes its response payment message for the liquidation and calls `validateAndSaveUnit` (`aa_composer.js`), validation fails with `"some output addresses are not attested"` or `"transfer or issue condition not satisfied"`; `L` calls `bounce(err)`, discarding the intended state update.
6. The collateral remains stuck inside `L`'s balance for asset `X`, the position is never marked as liquidated, and the liquidator/borrower cannot retrieve funds — mirroring the pausable-collateral `liquidateLoan()` revert scenario from the original report.

### Citations

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

**File:** validation.js (L2725-2731)
```javascript
function validateAssetDefinition(conn, payload, objUnit, objValidationState, callback){
	if (objUnit.authors.length !== 1)
		return callback("asset definition must be single-authored");
	if (!isNonemptyObject(payload))
		return callback("asset definition must be a non-empty object");
	if (hasFieldsExcept(payload, ["cap", "is_private", "is_transferrable", "auto_destroy", "fixed_denominations", "issued_by_definer_only", "cosigned_by_definer", "spender_attested", "issue_condition", "transfer_condition", "attestors", "denominations"]))
		return callback("unknown fields in asset definition");
```

**File:** validation.js (L2815-2827)
```javascript
	async.series([
		function(cb){
			if (!("issue_condition" in payload))
				return cb();
			Definition.validateDefinition(conn, payload.issue_condition, objUnit, objValidationState, null, true, cb);
		},
		function(cb){
			if (!("transfer_condition" in payload))
				return cb();
			Definition.validateDefinition(conn, payload.transfer_condition, objUnit, objValidationState, null, true, cb);
		}
	], callback);
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

**File:** definition.js (L641-643)
```javascript
function evaluateAssetCondition(conn, asset, arrDefinition, objUnit, objValidationState, cb){
	validateAuthentifiers(conn, null, asset, arrDefinition, objUnit, objValidationState, null, cb);
}
```

**File:** aa_composer.js (L1323-1344)
```javascript
				storage.loadAssetWithListOfAttestedAuthors(conn, asset, mci, [address], true, function (err, objAsset) {
					if (err)
						return cb(err);
					assetInfos[asset] = objAsset;
					if (objAsset.fixed_denominations) // will skip it later
						return cb();
					if (objAsset.is_private) // it'll fail validation anyway due to lack of spend_proofs
						return cb("sending private asset from AA");
					completePaymentPayload(payload, 0, function (err) {
						if (err)
							return cb(err);
						addOutputAddresses(payload.outputs);
						if (payload.outputs.length > 0) // send-all output might get removed while being the only output
							try {
								completeMessage(message);
							}
							catch (e) {
								return cb("completeMessage failed: " + e.toString());
							}
						cb();
					});
				});
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

**File:** formula/evaluation.js (L1531-1566)
```javascript
			case 'asset':
				var asset_expr = arr[1];
				var field_expr = arr[2];
				evaluate(asset_expr, function (asset) {
					if (fatal_error)
						return cb(false);
					evaluate(field_expr, function (field) {
						if (fatal_error)
							return cb(false);
						if (typeof field !== 'string' || !objBaseAssetInfo.hasOwnProperty(field))
							return setFatalError("bad field in asset[]: " + field, { arr }, false, cb);
						var convertValue = (value) => (typeof value === 'number' && mci >= constants.aa3UpgradeMci) ? new Decimal(value) : value;
						if (asset === 'base')
							return cb(convertValue(objBaseAssetInfo[field]));
						if (!ValidationUtils.isValidBase64(asset, constants.HASH_LENGTH)) {
							if (field === 'exists')
								return cb(false);
							return setFatalError("bad asset in asset[]: " + asset, { arr }, false, cb);
						}
						readAssetInfoPossiblyDefinedByAA(asset, function (objAsset) {
							if (!objAsset)
								return cb(false);
							if (objAsset.sequence !== "good")
								return cb(false);
							if (field === 'cap') // can be null
								return cb(convertValue(objAsset.cap || 0));
							if (field === 'definer_address')
								return cb(objAsset.definer_address);
							if (field === 'exists')
								return cb(true);
							if (field !== 'is_issued')
								return cb(!!objAsset[field]);
							if (objAsset.is_private)
								return cb(false); // not issued if private
							conn.query("SELECT 1 FROM inputs CROSS JOIN units USING(unit) WHERE type='issue' AND asset=? AND (main_chain_index<=? AND is_stable=1 AND sequence='good' " + (bAA ? "OR is_aa_response=1" : "") + ") LIMIT 1", [asset, mci], function(rows){
								cb(rows.length > 0);
```
