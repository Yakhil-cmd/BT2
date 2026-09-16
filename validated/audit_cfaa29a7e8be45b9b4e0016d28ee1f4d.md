## Title
AA payments of a `spender_attested`/`transfer_condition`-restricted asset can be permanently blocked, freezing funds an AA owes to a specific counterparty - ([File: aa_composer.js], [File: validation.js])

### Summary
The reported bug class is: a hard-coded/expected recipient becomes permanently unable to receive a payment (USDC blacklist), causing the whole repayment flow to always revert and permanently lock the debtor/creditor funds. Obyte's analog is an asset defined with `spender_attested` or `transfer_condition`, whose eligibility rules can change *after* an AA's business logic has already committed to paying a specific counterparty in that asset. Because attestor lists and transfer conditions are mutable at any later moment, an AA that must pay out such an asset to a fixed address (e.g. a treasury, oracle, arbitrator, or "creditor"-like counterparty in a lending/betting AA) can end up in a state where that specific payment can never validate, permanently bouncing and locking the corresponding AA balance.

### Finding Description
When an AA composes a response, `sendUnit()` builds payment messages and then calls `validateAndSaveUnit(objUnit, ...)`; any validation error causes an unconditional `bounce(err)`: [1](#0-0) 

Unit validation for a non-base-asset payment enforces two conditions that are entirely dependent on external, mutable state:
1. `spender_attested` — every output address must currently be on the attestor-approved list, checked via `storage.filterAttestedAddresses`.
2. `transfer_condition` — an arbitrary oscript/definition condition evaluated with `Definition.evaluateAssetCondition`. [2](#0-1) 

Both attestor lists and (depending on how `transfer_condition` is authored) the underlying facts they check (e.g. data feeds, other attestations) can be updated at any time after the asset and the AA that uses it were created, since the schema explicitly documents that spender attestors "must subsequently publish and update the list of trusted attestors": [3](#0-2) 

If an AA's immutable oscript logic is designed to pay out this asset to a specific counterparty address (analogous to the Solidity report's fixed `creditor`), and that counterparty's attestation is later revoked (or the `transfer_condition` becomes false for it), every subsequent AA response that tries to send this payment will fail unit validation, hit `bounce(err)`, and the corresponding AA-held balance for that asset is never actually transferred to the intended recipient. Because AA code cannot be upgraded and the sending message itself is unconditional or its `if` may not anticipate this failure mode, the payment keeps failing on every retry.

Additionally, the AA's own bounce-refund logic amplifies the impact: if any single asset amount sent in by the trigger is smaller than that asset's configured `bounce_fees` entry, `bounce()` aborts refunding of *all* assets/bytes for that trigger, not just the underrated one: [4](#0-3) 

### Impact Explanation
This matches the "AA fund loss or freezing" impact class explicitly listed as acceptable. A restricted asset (`spender_attested` or with a `transfer_condition`) used as the AA's payout currency to a specific counterparty can become permanently undeliverable to that counterparty once attestation/condition state changes, indefinitely bouncing the response and locking the AA's balance owed to that party, with no code-level recourse since AA definitions are immutable. This is a direct structural analog of the reported "borrower/creditor cannot receive funds due to blacklist, repay flow permanently DoS'd."

### Likelihood Explanation
Reachable by any unprivileged party: an AA author can build such logic (data-feed/loan/escrow AAs that pay third parties in a restricted asset are a normal use case), and any user can trigger the AA (e.g., posting a repay/withdraw trigger) once the counterparty's attestation status changes. No special privilege beyond normal AA usage and normal attestor behavior (attestors are expected to routinely update lists) is required, and the condition (attestor revocation or condition state change) is entirely realistic and outside the AA's control.

### Recommendation
- Document/require that AAs performing payments of `spender_attested`/`transfer_condition`-restricted assets validate the target address's current eligibility (e.g. via `storage.filterAttestedAddresses`/oscript equivalents inside the AA formula) before attempting the payment, and provide an alternate code path (e.g., send-to-self / hold-in-state) so funds are not indefinitely locked if the condition fails.
- Consider exposing attestation/condition-check getters usable from AA formulas so AAs can gracefully branch instead of relying on unit-validation failure and bounce.
- Reconsider the `bounce()` all-or-nothing refund behavior (`if (fee > amount) return finish(null);`), which can also cause otherwise-refundable bytes/assets to be silently retained when only one asset's amount underflows its bounce fee.

### Proof of Concept
1. Definer creates asset `A` with `spender_attested: true` and attestor list `[Att1]`, and deploys AA `L` whose logic (e.g., a loan/lending AA) unconditionally pays out asset `A` to `creditor_address` as part of normal repayment handling.
2. `Att1` initially attests `creditor_address` (via `attestation`/`asset_attestors` update) so it is eligible to receive `A`.
3. A user posts a valid trigger to `L` (e.g. a "repay" trigger) that is intended to result in `L` sending asset `A` to `creditor_address`; this succeeds while attestation holds — see `validatePaymentInputsAndOutputs`'s `spender_attested` branch [5](#0-4) .
4. `Att1` later revokes/updates the attestor list so `creditor_address` is no longer attested (permitted at any time per the schema comment on `asset_attestors`).
5. Any subsequent trigger to `L` that reaches the payout branch now fails unit validation ("some output addresses are not attested"), causing `sendUnit` to `bounce(err)` [1](#0-0) ; the AA's balance of `A` earmarked for `creditor_address` is retained by the AA and can never be delivered, matching the reported "borrower/creditor cannot be repaid" pattern.

### Citations

**File:** aa_composer.js (L928-944)
```javascript
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

**File:** validation.js (L2630-2658)
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
```

**File:** initial-db/byteball-sqlite-light.sql (L246-246)
```sql
	spender_attested TINYINT NOT NULL, -- must subsequently publish and update the list of trusted attestors
```
