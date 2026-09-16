## Title
Asset issuer's attestor-list/condition changes can permanently trap user funds inside an AA (Autonomous Agent) - (File: `aa_composer.js`, `validation.js`)

### Summary
Obyte's asset system lets an asset definer make transfers conditional on a mutable attestor list (`spender_attested`) or an arbitrary `transfer_condition`/`issue_condition` formula that the definer can update at any later moment via an `asset_attestors` message. This is the ocore analog of a "pausable" ERC-20 token: after value has already been deposited on-chain into an AA, the definer (or an oracle referenced by the condition) can make the AA's programmed payout unable to satisfy the condition. Because the AA's bounce/refund logic in `aa_composer.js` does not verify in advance that a refund payment will itself pass the same condition, a revoked attestation (or a false condition) can cause both the primary response and the fallback bounce to fail, permanently freezing the deposited asset inside the AA.

### Finding Description
When composing a response, `aa_composer.js` only checks `fixed_denominations` and `is_private` before including an asset payment message; it does **not** pre-check `spender_attested`/`transfer_condition` for the destination address: [1](#0-0) 

The unit is only validated after being fully built, via `validateAndSaveUnit`, and any failure routes to `bounce(err)`: [2](#0-1) 

Final validation enforces the mutable attestor list and `transfer_condition`/`issue_condition` at commit time: [3](#0-2) 

The attestor list itself can be changed by the asset definer alone, at any main-chain index, with no restriction tying it to prior deposits: [4](#0-3) 

Crucially, `bounce()` has a single-attempt guard: if the refund payment it composes also fails final validation, the recursive `bounce(err)` call hits `bBouncing` and silently gives up with `finish(null)`, sending no unit at all: [5](#0-4) 

Sequence:
1. A user (private-payment counterparty / AA trigger sender) sends asset `A` (defined with `spender_attested: true` or a `transfer_condition`) into an AA as part of a trigger. This payment is validated and becomes stable — the deposit is irreversible.
2. The AA's normal response tries to pay asset `A` back out (e.g., swap proceeds, liquidation collateral, LP withdrawal). Meanwhile, the asset issuer (fully unprivileged w.r.t. the AA, acting only as asset definer) posts a new `asset_attestors` message removing the AA's or user's address from the attestor list, or the referenced `transfer_condition` formula (e.g., dependent on a data feed) now evaluates to false.
3. `validateAndSaveUnit` fails at `validation.js:2630-2659` ("some output addresses are not attested" / "transfer or issue condition not satisfied"), triggering `bounce(err)`.
4. `bounce()` tries to refund the trigger's original asset `A` output to `trigger.address` — but since the same attestation/condition problem applies to that address too, this refund unit **also** fails validation and calls `bounce()` again.
5. The recursive call hits `bBouncing` and calls `finish(null)`: no unit is emitted for this trigger at all. The asset `A` already credited to the AA's on-chain balance (from step 1) is never returned and there is no code path left to move it out while the condition remains unsatisfied.

### Impact Explanation
The user's asset is now stuck inside the AA's address with no way to retrieve it as long as the definer keeps the transfer condition/attestor list in the "blocking" state (which is entirely under the definer's/oracle's control, not the AA's or user's). This is a direct analog of "Liquidation and Settlement Flows can be blocked by Pausable ERC20 tokens" — AA fund freezing/loss for any AA that accepts and later needs to move a conditionally-transferable asset (e.g., DeFi swap, lending, liquidation, or LP-style AAs as seen in `test/ojson.test.js`'s Uniswap-like market maker sample). Severity is Medium-High because it results in concrete, unrecoverable fund loss/freezing for legitimate users, not merely a resource DoS.

### Likelihood Explanation
Likelihood is low-probability but realistic and not attacker-triggerable by the victim: it requires only the asset's own definer (or the referenced oracle for `transfer_condition`) to update the attestor list or condition inputs after deposits are already committed — an action fully permitted by `validateAttestorListUpdate`, which imposes no restriction preventing this from breaking already-pending AA obligations.

### Recommendation
- Before composing/sending a payment message for a `spender_attested` or condition-gated asset in `aa_composer.js`, evaluate the current attestor list / condition against the intended destination and refund addresses, and bounce early with a clear error rather than after balances have been tentatively spent.
- In `bounce()`, if the primary refund also fails validation, attempt an alternative bounce path (e.g., use a different asset, or explicitly track/queue the stuck balance instead of silently emitting no unit), or ensure the trigger's incoming payment can never render the AA balance for a conditionally-transferable asset non-refundable.
- Consider disallowing/warn against `spender_attested`/`transfer_condition`/`issue_condition` assets from being usable as first-class payment media for arbitrary AA flows without an explicit unlock/retry primitive.

### Proof of Concept
1. Definer creates asset `A` with `spender_attested: true` and publishes an initial attestor list including addresses `U` (user) and `AA` (an autonomous agent that swaps/holds `A`).
2. `U` sends a trigger to `AA` depositing `A`; unit becomes stable, `AA`'s on-chain balance of `A` increases.
3. Definer posts a new `asset_attestors` message (`validation.js:2829-2848`, definer-only) removing `U` and/or `AA` from the attestor list.
4. `AA`'s later response attempting to pay `A` to `U` fails at `validation.js:2630-2659`; `bounce()` is invoked (`aa_composer.js:1405-1411`).
5. `bounce()`'s own refund payment of the originally-deposited `A` back to `trigger.address` (`U`) also fails the same attestor check; the recursive `bounce()` call hits `bBouncing` and calls `finish(null)` (`aa_composer.js:923-927`), so no unit is ever sent — `A` remains stuck at `AA`'s address indefinitely.

### Citations

**File:** aa_composer.js (L909-945)
```javascript
	var bBouncing = false;
	function bounce(error) {
		console.log('bouncing with error', error, new Error().stack);
		objStateUpdate = null;
		error_message = error_message ? (error_message + ', then ' + error) : error;
		if (trigger_opts.bAir) {
			assignObject(stateVars, originalStateVars); // restore state vars
			assignObject(trigger_opts.assocBalances, originalBalances); // restore balances
			if (!bSecondary) {
				for (let a in trigger.outputs)
					if (bounce_fees[a])
						trigger_opts.assocBalances[address][a] = (trigger_opts.assocBalances[address][a] || 0) + bounce_fees[a];
			}
		}
		if (bBouncing)
			return finish(null);
		bBouncing = true;
		if (bSecondary)
			return finish(null);
		if ((trigger.outputs.base || 0) < bounce_fees.base)
			return finish(null);
		var messages = [];
		// iteration order is standardized since ECMAScript 2020
		for (var asset in trigger.outputs) {
			var amount = trigger.outputs[asset];
			var fee = bounce_fees[asset] || 0;
			if (fee > amount)
				return finish(null);
			if (fee === amount)
				continue;
			var bounced_amount = amount - fee;
			messages.push({app: 'payment', payload: {asset: asset, outputs: [{address: trigger.address, amount: bounced_amount}]}});
		}
		if (messages.length === 0)
			return finish(null);
		sendUnit(messages);
	}
```

**File:** aa_composer.js (L1323-1331)
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
