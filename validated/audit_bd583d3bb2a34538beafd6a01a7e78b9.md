## Title
Insufficient validation of forwarded amounts to secondary AA triggers causes permanent, unrecoverable fund loss - (File: aa_composer.js)

### Summary
When an Autonomous Agent (AA) forwards a payment to another AA address as part of its response (a "secondary trigger"), ocore never validates that the forwarded amount is sufficient for the receiving AA to actually execute successfully (e.g., cover its own `bounce_fees`, storage cost, or complexity budget). If the secondary AA's execution fails for any reason, the funds already transferred to it in the (already validated and saved) parent response unit are never returned and become permanently stuck, because bounce handling for secondary triggers is explicitly designed to swallow the funds rather than refund them. This is directly analogous to the reported CrossDomainMessenger issue: a message-forwarding step lacks a minimum "resource" check, so if the receiving side fails, the transferred value is unrecoverably lost with no possibility of retry.

### Finding Description
In `handleTrigger` (aa_composer.js), when a primary AA acts as the initiating trigger, it must have received enough funds to cover its own `bounce_fees` before the AA logic even runs: [1](#0-0) 

However, this check is explicitly skipped for secondary triggers — i.e., when one AA's response payment triggers *another* AA: [2](#0-1) 

The comment makes the design intent explicit: *"being able to pay for bounce fees is not required for secondary triggers as they never actually send any bounce response or change state when bounced."* This means the sending AA's response unit — which already moved real coins to the secondary AA's address and was validated/saved on-chain via `validateAndSaveUnit` in `sendUnit` — is never checked against what the receiving AA actually needs to succeed: [3](#0-2) 

When the secondary AA's `handleTrigger` invocation subsequently fails (bounces) for any reason — insufficient balance for its own payment outputs, exceeded complexity/ops budget, a failing `bounce()` call in its own oscript, etc. — the `bounce()` function takes an early, silent exit path for secondary triggers, without generating any bounce/refund message: [4](#0-3) 

Because `updateInitialAABalances` already credited the trigger's incoming outputs to the secondary AA's balance before evaluation began, and no debit or refund message is produced when `bSecondary` bounces, the funds permanently remain on the secondary AA's ledger balance with no state change and no way for the AA author's code path to release them (since the exact same deterministic trigger conditions that caused the failure will keep recurring for that unit/trigger). This is analogous to `sendMessage`'s `_minGasLimit` parameter in the Optimism report: there is no mechanism analogous to `baseGas()` validating that what is forwarded to the second hop is enough for it to complete successfully, and once the first hop's unit is finalized on-chain (funds already "spent"), there is no way to retry with more resources.

This is reachable by any unprivileged AA author (or even any user triggering an AA chain) whose forwarded amount to a nested/secondary AA is insufficient — whether due to a bug in their own oscript formula, a fee miscalculation, or unexpected state at the receiving AA (e.g., due to storage growth, complexity growth from state, or a race with other triggers changing balances at that AA).

### Impact Explanation
Funds transferred through a chain of AAs (a common pattern for bridges, DEXes, and multi-step contracts documented in the repo's own sample AAs) can become permanently and irrecoverably locked at the secondary AA's address if the amount forwarded is not enough for the secondary AA to complete its own logic. Unlike a primary trigger bounce (which explicitly refunds the sender when possible), a secondary-trigger bounce silently keeps the coins with no state update and no outgoing message — the value is stranded with no programmatic path to recovery, matching the "Medium" impact class of the reference report (unrecoverable fund loss due to missing minimum-resource validation on a forwarded cross-contract call).

### Likelihood Explanation
Any AA author building multi-hop AA logic (chains of AAs, as explicitly supported and tested by `test.cb.serial('chain of AAs', ...)`) must manually and correctly compute exactly how much every downstream AA needs to succeed, with zero engine-level safety net or minimum check comparable to `baseGas()`/`_minGasLimit` validation in the reference report. Given the complexity of AA storage-size fees, bounce fee requirements, and complexity budgets that can shift with state, an off-by-one or edge-case miscalculation is plausible in real-world AA deployments, making this reachable through ordinary AA usage rather than requiring a privileged or malicious actor.

### Recommendation
Introduce a minimum viability check before forwarding a payment to a secondary AA (or before completing the secondary trigger irrevocably): e.g., require that the forwarded amount to any AA address is at least the receiving AA's own declared `bounce_fees.base` (and per-asset fees, if applicable), or, upon a secondary-trigger bounce, generate the same explicit refund message used in primary bounces instead of silently swallowing the funds — mirroring how `bounce()` already handles primary triggers at aa_composer.js:928-944.

### Proof of Concept
1. Deploy `secondary_aa` requiring, say, `bounce_fees: { base: 10000 }`, with a payment message whose output amount formula depends on receiving at least a certain amount (e.g., `trigger.output[[asset=base]] - 2000`, which is negative/invalid if too little was sent).
2. Deploy `primary_aa` that forwards a payment to `secondary_aa`'s address with an amount smaller than `secondary_aa`'s effective requirement (e.g., `trigger.output[[asset=base]] - 39999` when the trigger sends less than `secondary_aa`'s bounce fee + expected output).
3. Trigger `primary_aa`. Its response unit is validated and saved with a real payment output to `secondary_aa`'s address, as shown in the passing `chain of AAs` test flow: [5](#0-4) 
4. `handleSecondaryTriggers` invokes `secondary_aa`'s trigger; because the forwarded amount is insufficient for `secondary_aa`'s payment output to succeed, `secondary_aa` bounces.
5. Since `bSecondary` is true, `bounce()` returns via `finish(null)` at aa_composer.js:926-927 without issuing any refund message; the coins credited to `secondary_aa`'s balance in `updateInitialAABalances` are never returned to `primary_aa` or the original trigger address, and no state changes occur to release them — the value is now permanently stuck at `secondary_aa`.

### Citations

**File:** aa_composer.js (L909-927)
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
```

**File:** aa_composer.js (L1403-1419)
```javascript
						objUnit.unit = objectHash.getUnitHash(objUnit);
						console.log('unit', util.inspect(objUnit, { depth: 6 }))
						executeStateUpdateFormula(objUnit, function (err) {
							if (err)
								return bounce(err);
							validateAndSaveUnit(objUnit, function (err) {
								if (err)
									return bounce(err);
								updateFinalAABalances(arrConsumedOutputs, objUnit, function () {
									if (arrOutputAddresses.length === 0)
										return finish(objUnit);
									fixStateVars();
									addResponse(objUnit, function () {
										updateStorageSize(function (err) {
											if (err)
												return revert(err);
											handleSecondaryTriggers(objUnit, arrOutputAddresses);
```

**File:** aa_composer.js (L1850-1863)
```javascript
		// being able to pay for bounce fees is not required for secondary triggers as they never actually send any bounce response or change state when bounced
		if (!bSecondary) {
			if ((trigger.outputs.base || 0) < bounce_fees.base) {
				return bounce('received bytes are not enough to cover bounce fees');
			}
			for (var asset in trigger.outputs) { // if not enough asset received to pay for bounce fees, ignore silently
				if (bounce_fees[asset] && trigger.outputs[asset] < bounce_fees[asset]) {
					return bounce('received ' + asset + ' is not enough to cover bounce fees');
				}
			}
			// skip this check for dry-run which uses genesis unit as trigger unit
			if (trigger.unit !== constants.GENESIS_UNIT && !trigger_opts.bAir && storage.assocStableUnits[trigger.unit].count_aa_responses && mci >= constants.pemCurvesFixMci)
				return bounce('a second primary trigger from the same unit is not allowed');
		}
```

**File:** test/aa_composer.test.js (L216-222)
```javascript
	aa_composer.dryRunPrimaryAATrigger(trigger, primary_address, primary_aa, (arrResponses) => {
		t.deepEqual(arrResponses.length, 2);
		t.deepEqual(arrResponses[0].aa_address, primary_address);
		t.deepEqual(arrResponses[0].bounced, false);
		t.deepEqual(arrResponses[0].response.error, undefined);
		t.deepEqual(arrResponses[0].objResponseUnit.messages.find(function (message) { return (message.app === 'payment'); }).payload.outputs.find(function (output) { return (output.address === secondary_address); }).amount, 39000);
		t.deepEqual(arrResponses[0].updatedStateVars[primary_address], {
```
