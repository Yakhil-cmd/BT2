### Title
AA response can permanently lose or freeze trigger-sender funds when a `spender_attested` asset payment back to `trigger.address` fails validation during bounce - ([File: aa_composer.js])

### Summary
The Sherlock finding describes a Solidity contract where `withdrawToken` sends an NFT to a hard-coded recipient (`bull`) that cannot be changed, and if that recipient's contract cannot accept the asset (no `onERC721Received`), the withdrawal permanently fails with no alternative recovery path. The ocore analog is in the Autonomous Agent (AA) response-composition logic in `aa_composer.js`, where the framework always directs bounce/refund payments to the fixed `trigger.address` (the unprivileged unit poster who triggered the AA), with no mechanism to redirect to another address if that payment cannot be validated.

### Finding Description
When an AA trigger causes an error, `handleTrigger`'s `bounce()` function composes payment messages that send the (fee-reduced) trigger outputs back to the fixed `trigger.address`: [1](#0-0) 

`bounce()` iterates over every asset in `trigger.outputs` (not just base bytes) and builds a payment message back to `trigger.address` for each one, then calls `sendUnit(messages)`. If the asset involved is defined with `spender_attested: true`, the eventual unit built by `sendUnit` must pass full protocol validation via `validatePaymentInputsAndOutputs`, which explicitly rejects the payment if the output address is not attested: [2](#0-1) 

Because `trigger.address` is fixed (it is always the address that authored the triggering unit — the AA cannot substitute a different, attested recipient), if that address is not on the asset's attested list, the bounce payment itself fails validation. That failure propagates back into `bounce(err)` again. Since `bBouncing` is already `true` from the first bounce attempt, the guard at the top of `bounce()` short-circuits to `finish(null)`: [3](#0-2) 

This mirrors the reported bug class exactly: a recipient address that is baked into the protocol logic (the trigger's own address, analogous to `bull` in `withdrawToken`) cannot be substituted, and if that address fails a receipt precondition (here, attestation, analogous to `onERC721Received` support), the refund path itself fails and the whole response silently resolves to no response/state change (`finish(null)`).

### Impact Explanation
When the double-bounce collapse to `finish(null)` occurs, the AA processes the trigger without producing any refund message to the sender, yet the sender's originally sent asset output was already consumed as an AA input on-chain (UTXO-style transfer is a fait accompli once the triggering unit is stable/spendable by the AA). Because no valid response unit compensates the sender, the funds transferred by the trigger remain in the AA's balance with no protocol-level path to return them to the (unattested) trigger address — a fund-freezing/loss condition for an ordinary, unprivileged unit poster, reachable simply by triggering an AA that handles a `spender_attested` asset and later needs to bounce.

### Likelihood Explanation
This requires: (1) an AA that accepts and can bounce a `spender_attested` asset, and (2) the trigger address not being in that asset's attested list at validation time. Both conditions are realistically achievable by any unprivileged actor — they simply send the asset to the AA without first obtaining attestation, or lose attestation between sending and bounce evaluation (attestation is checked against `last_ball_mci` state, which is fixed at trigger evaluation time but can differ from the sender's expectations). AA authors widely use bounce-on-error patterns (as seen throughout the test suite and sample AAs), so this is a plausible occurrence rather than a contrived edge case.

### Recommendation
- When composing bounce/refund payments for assets with `spender_attested` (or other output-address preconditions such as `is_transferrable` restrictions), verify the recipient address satisfies those preconditions before attempting the bounce; if it does not, either eat the funds explicitly with clear state accounting (rather than silently discarding via `finish(null)`), or fail response composition in a way that keeps the incoming asset recorded as an explicit AA balance credit that can later be recovered by a compliant address.
- Consider disallowing/warning when an AA's `bounce_fees`/message templates include non-transferable-condition assets whose bounce path could fail, or add a secondary, unconditioned "hold" mechanism so unattested trigger senders' funds are not silently absorbed.
- At minimum, ensure `finish(null)` paths triggered by a bounce failure are distinguishable from normal successful "no messages" cases in AA balance/state accounting so operators/auditors can detect stuck value.

### Proof of Concept
1. Deploy/define an asset with `spender_attested: true` and a small attested-address allowlist that does not include a generic user address `U`.
2. Deploy an AA whose template message set, on some condition, sends a payment of this asset back to `trigger.address` (a common bounce/refund idiom, e.g. `{address: "{trigger.address}", amount: ...}`), or rely on the built-in `bounce()` refund path by having the trigger include this asset among `trigger.outputs`.
3. From address `U` (not attested for the asset), send this asset to the AA along with enough bytes to cover `bounce_fees`, triggering a condition inside the AA that leads to an error (e.g., insufficient balance, a `bounce()` formula call, or any handled failure) after the asset was already received.
4. Observe `handleTrigger` → `bounce()` compose a refund message with `{address: trigger.address /* == U */, amount: ...}` for the asset.
5. `sendUnit` completes the unit and calls `validateAndSaveUnit`, which invokes `validation.js`'s `validatePaymentInputsAndOutputs`, which calls back with `"some output addresses are not attested"` because `U` is not attested — see [2](#0-1) .
6. This error re-enters `bounce(err)`; since `bBouncing` is already `true`, `finish(null)` is invoked — see [4](#0-3) .
7. Result: no response unit is produced, `U`'s originally sent asset amount is not returned and remains absorbed into the AA's balance permanently, with no on-protocol mechanism to redirect it to a different (attested) address, matching the "withdraw cannot work because the fixed recipient can't receive" bug class from the reference report.

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
