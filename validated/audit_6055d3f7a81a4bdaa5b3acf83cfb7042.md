### Title
Revoked spender attestation for one recipient in a batched AA payment can bounce and freeze funds destined for all bundled recipients - ([File: aa_composer.js], [File: validation.js])

### Summary
Obyte's `spender_attested` asset mechanism allows an asset's attestor (an "asset issuer"-controlled trust list) to gate which addresses may receive a spender-attested asset. When an autonomous agent (AA) composes a single response unit that pays out a `spender_attested` asset to multiple recipients (a common "distribute rewards / batch claim" pattern), the whole unit's validity is checked atomically. If even one output address in that batch loses its attestation (revoked by the attestor/asset issuer) before the unit is composed/validated, the entire unit fails validation and the AA response bounces, so none of the bundled recipients get paid - mirroring the reported "blocklisted `recipientAddress` freezes all other claimants" bug class.

### Finding Description
`validatePaymentInputsAndOutputs` checks, for `spender_attested` assets, that **all** output addresses of the payment are currently attested, in one all-or-nothing query: [1](#0-0) 

If any address in `arrOutputAddresses` fails the attestation filter, the function returns the error `"some output addresses are not attested"` for the **whole message**, not just for the unattested output: [2](#0-1) 

On the AA side, `sendUnit` composes a response unit that can combine outputs to several different addresses. Since `pemCurvesFixMci`, same-asset payment messages/outputs get merged into a single message via `mergeMessagesAndOutputs`, and the whole composed unit is validated with `validateAndSaveUnit`. Any validation failure (including the attestation check above) causes the AA to `bounce(err)` rather than being caught and only affecting the specific failing output: [3](#0-2) 

`bounce()` discards the entire `objStateUpdate`, restores prior state/balances, and either sends a smaller bounce-fee-only unit back to the trigger sender or does nothing at all - none of the intended payouts to other (still-compliant) recipients are sent: [4](#0-3) 

Because `spender_attested` re-checks attestation at spend time (not just once at asset creation), an attestor/asset issuer can revoke attestation for a single targeted address at any time, and this will retroactively block any AA-authored unit that still tries to pay that address alongside others, exactly like a USDC-style blocklist entry blocking a batched claim/distribution transaction.

### Impact Explanation
For an AA-based payout/distribution/claim contract (analogous to the `DonationVotingMerkleDistributionVaultStrategy.claim` pattern) that pays a `spender_attested` asset to several recipients within one response, a single revoked attestation freezes the funds meant for *all* recipients bundled in that unit, since the AA bounces and no payment is delivered. Funds already held by the AA for this batch remain undelivered (frozen) until the AA is re-triggered with a payout scheme that excludes the blocked address - which most naive "distribute in one shot" AA designs do not support, leading to AA fund freezing that is difficult or impossible for the other legitimate, unblocked recipients to unlock.

### Likelihood Explanation
`spender_attested` is an existing, supported asset feature; any asset issuer defining a spender-attested asset (or the attestor(s) they designate) can revoke an address's attestation at will. Any AA author who batches multiple `spender_attested` payouts into one response unit (a natural pattern for reward/airdrop/claim AAs) is exposed. No special privilege beyond being the asset's issuer/attestor is required to trigger the freeze, and no core protocol change is needed to exploit it - only building/using such an asset with an AA that batches payouts.

### Recommendation
- In AA payout logic operating on `spender_attested` (or otherwise conditionally-transferable) assets, avoid batching payments to multiple independent recipients within a single response unit; instead, process one recipient/claim per trigger response so a single failed recipient cannot block others.
- Consider adding an explicit warning/guideline in AA documentation about the atomicity of `spender_attested` checks and their DoS implications for multi-recipient payment messages.
- For core-level mitigation, consider allowing partial validation/skip-and-retry semantics for AA response messages so that failing outputs for one address don't invalidate the entire response unit's other outputs (would require careful protocol-level design since units must be atomic).

### Proof of Concept
1. Asset issuer defines an asset with `spender_attested: true` and designates an attestor.
2. Attestor attests addresses A, B, and C, allowing them to receive the asset.
3. An AA is deployed that, in a single trigger response, pays this asset to A, B, and C in one merged payment message (e.g., a reward-distribution AA).
4. Before the AA's trigger executes (or between trigger evaluation and unit composition/validation), the attestor revokes C's attestation (a normal, permitted `attestation`/`asset_attestors` update - no special exploit needed).
5. When the AA composes the response unit, `validateAndSaveUnit` runs `validatePaymentInputsAndOutputs`, which finds `arrAttestedOutputAddresses.length !== arrOutputAddresses.length` (C is unattested) and returns `"some output addresses are not attested"` [2](#0-1) .
6. `sendUnit` calls `bounce(err)` [5](#0-4) , and the response for this trigger is bounced - A and B receive nothing even though they remain properly attested, and the funds intended for them stay stuck in the AA until a future trigger with a payout mechanism that excludes C is composed (which most simple "distribute-all" AA implementations don't provide).

### Citations

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
