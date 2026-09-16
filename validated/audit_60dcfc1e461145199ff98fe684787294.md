### Title
AA funds become permanently stuck when returning a `spender_attested` / non-transferrable asset to the triggering address that is not eligible to receive it - ([File: aa_composer.js])

### Summary
An Autonomous Agent (AA) that receives a restricted asset (one with `spender_attested: true`, or `is_transferrable: false`, or a `transfer_condition`) from a trigger unit and later tries to return/forward that asset to `trigger.address` — either as part of normal AA logic or via the automatic `bounce()` mechanism — can have its response unit permanently rejected by validation if the trigger address does not satisfy the asset's restriction (not attested / not the definer / condition not met). Because the bounce path itself reuses `trigger.address` as the recipient, the second (bounce) attempt fails the same way, and the AA silently gives up (`finish(null)`), permanently locking the user's coins inside the AA with no way to recover them. This is the direct Obyte analogue of the reported issue: a token-level restriction (blacklist-equivalent) that prevents the protocol contract from ever returning previously staked/deposited funds to the depositor's own address.

### Finding Description
When an AA composes response messages, payment outputs are only lightly sanity-checked in `sendUnit` (valid address format, non-negative integer amounts, no unknown fields) — see the per-message checks in `aa_composer.js` (loop starting at `aa_composer.js:1247-1279`). Critically, this loop does **not** check `is_transferrable`, `spender_attested`, or `transfer_condition` for the asset being sent, even though these fields govern whether a payment output to a given address is actually valid: [1](#0-0) 

The composed AA response unit is only checked against these restrictions later, when it goes through full unit validation: [2](#0-1) [3](#0-2) 

If that validation fails (e.g., because `trigger.address` is not on the asset's attested list, or the asset is non-transferrable and `trigger.address` is not the definer), `sendUnit`'s call chain reaches `validateAndSaveUnit(objUnit, function(err){ if (err) return bounce(err); ...})`: [4](#0-3) 

This falls through to `bounce(error)`, which composes a *new* response unit that sends the trigger's received assets straight back to `trigger.address`, with no eligibility check at all: [5](#0-4) 

Because the bounce payment uses the very same `trigger.address` that already failed the asset's transfer restriction, the bounce attempt will fail identically during the eventual `validateAndSaveUnit` step. The `bBouncing` guard then causes the handler to give up silently: [6](#0-5) 

with `finish(null)` — i.e., no response unit is produced, the coins that were included in the trigger unit's payment to the AA remain part of the AA's balance, and there is no code path that allows recomposing the payment to a different, eligible recipient address (analogous to the missing "recipient" parameter fix suggested in the original report).

### Impact Explanation
A user (unprivileged trigger sender) who sends a `spender_attested` asset, a non-transferrable asset, or an asset with a restrictive `transfer_condition` to an AA — expecting the AA to forward it back or otherwise pay it out to `trigger.address` — can permanently lose access to those funds if their address is not/no longer eligible (not attested, attestation later revoked by a new `asset_attestors` update, or condition no longer satisfied) at the time the AA composes its response. The AA has no mechanism to redirect the payment to another address, so the funds become permanently trapped in the AA's balance: an "AA fund loss or freezing" outcome.

### Likelihood Explanation
Attestation-gated and non-transferrable assets (`spender_attested`, `is_transferrable`, `transfer_condition`) are a standard, publicly documented ocore asset feature exposed directly to AA authors via `aa_validation.js` asset message validation. Any AA that echoes assets back to `trigger.address` (a very common oscript pattern, seen throughout `test/aa.test.js` and the ojson sample templates like `just_a_bouncer.oscript`) is exposed to this if it ever handles such a restricted asset. The condition is entirely user/asset-issuer driven (e.g., an attestor revoking an address's attestation between the time coins were sent and the AA response is composed), requiring no privileged action from a node operator or attacker beyond normal asset administration.

### Recommendation
Before composing/sending a payment message for a non-base asset in `aa_composer.js`, validate the recipient(s) against the asset's `is_transferrable`, `spender_attested`/attestation list, and `transfer_condition`, and surface a clear formula-level error if the check would fail — so oscript authors can branch and choose an alternative, eligible recipient instead of relying on `bounce()`, which itself is not restriction-aware and reuses the same possibly-ineligible `trigger.address`. Additionally, consider exposing an AA-callable getter (e.g., `is_valid_address`/`is_attested_address`) so that oscript logic can check eligibility before attempting the transfer, avoiding permanent fund lock.

### Proof of Concept
1. Issuer defines an asset `A` with `spender_attested: true` and attestor `X`.
2. Deploy an AA whose oscript is a simple "bouncer/forwarder" pattern that sends asset `A` back to `trigger.address` (pattern identical to `test/samples/just_a_bouncer.oscript`).
3. Address `U` (attested by `X` at send time) sends asset `A` to the AA as a trigger.
4. Before the AA's response unit is composed/validated, attestor `X` publishes a new `asset_attestors` list that no longer includes `U` (a normal on-chain action by the asset's attestor, not requiring cooperation from the AA or the user).
5. The AA processes the trigger and composes a payment of asset `A` back to `trigger.address` = `U`.
6. `validateAndSaveUnit` rejects the unit per `validation.js:2637` ("some output addresses are not attested"); `sendUnit` calls `bounce(err)`.
7. `bounce()` composes a new unit sending the same asset `A` back to `trigger.address` = `U` (`aa_composer.js:940`), which fails validation identically.
8. `bBouncing` is already true, so `finish(null)` is invoked (`aa_composer.js:923-925`): no response unit is produced; asset `A` remains credited to the AA's balance with no code path to release it to `U` or any other address, permanently freezing `U`'s funds inside the AA.

### Citations

**File:** aa_composer.js (L909-944)
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
```

**File:** aa_composer.js (L1266-1279)
```javascript
			if (!Array.isArray(payload.outputs))
				return bounce("outputs must be array"); // empty array is okay
			if (!payload.outputs.every(o => ValidationUtils.isValidAddress(o.address)))
				return bounce("invalid addresses in outputs");
			if (payload.outputs.some(o => ValidationUtils.hasFieldsExcept(o, ['address', 'amount'])))
				return bounce("unknown fields in outputs");
			if ('asset' in payload && !(payload.asset === 'base' || ValidationUtils.isStringOfLength(payload.asset, constants.HASH_LENGTH)))
				return bounce("asset must be a string or omitted");
			// negative or fractional
			if (!payload.outputs.every(function (output) { return (isNonnegativeInteger(output.amount) || output.amount === undefined); }))
				return bounce("negative or fractional amounts");
			// filter out 0-outputs
			payload.outputs = payload.outputs.filter(function (output) { return (output.amount > 0 || output.amount === undefined); });
		}
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
