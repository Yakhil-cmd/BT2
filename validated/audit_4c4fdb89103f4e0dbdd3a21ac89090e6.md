### Title
Atomic AA response bundling multiple asset payments can be permanently bricked by a single asset with an unsatisfiable transfer/issue condition or attestor requirement - (File: aa_composer.js)

### Summary
When an Autonomous Agent (AA) composes its response unit, it bundles all messages (payments in multiple assets, state changes, base-byte change/bounce-fee output) into **one atomic unit**. Before composing an asset payment, `aa_composer.js` only pre-screens two properties of the asset — `fixed_denominations` (skipped) and `is_private` (bounced immediately with a clear message) — but performs **no pre-check** for `spender_attested` (attestor whitelist) or `transfer_condition`/`issue_condition`. These conditions are only evaluated much later, during full unit validation (`validateAndSaveUnit`), and if they fail, the **entire response unit is bounced**, including any unrelated legitimate payments (bytes, other assets) that were batched together in the same unit. This is directly analogous to the OpenQ bug: a single "poisoned" token bundled with legitimate payouts in one atomic transfer causes the whole operation to revert, and if the poisoned asset is unconditionally part of a recurring code path, that path is permanently unusable.

### Finding Description
In `aa_composer.js`, when building payment messages for a non-base asset, the code does: [1](#0-0) 
It loads the asset info and only rejects `is_private` assets outright (line 1330) or defers `fixed_denominations` handling; it does **not** check whether the asset's `spender_attested` attestor list includes the intended recipient, nor whether its `transfer_condition`/`issue_condition` can be satisfied by the AA's forced deterministic output. It proceeds to `completePaymentPayload` and `completeMessage` as if the transfer will succeed.

The actual enforcement of these rules happens only during validation of the fully composed unit: [2](#0-1) 
Here, `spender_attested` assets require every output address to be attested (`"some output addresses are not attested"`), and `transfer_condition`/`issue_condition` must independently evaluate true (`"transfer or issue condition not satisfied"`).

Back in `aa_composer.js`, once the fully assembled unit (containing all bundled payment messages) is built, it is validated as a single atomic unit: [3](#0-2) 
If `validateAndSaveUnit` fails for *any* reason — including an unsatisfiable asset condition on just one of the bundled payments — `bounce(err)` is invoked, which discards **all** messages in the response, including unrelated legitimate byte/asset transfers that were correctly composed: [4](#0-3) 

Because asset definitions (`transfer_condition`, `issue_condition`, `spender_attested`/`attestors`) are set once at asset issuance and are immutable thereafter (see `validateAssetDefinition`), any asset that is a fixed, required part of an AA's bundled multi-asset payout (e.g., a vault/swap/dividend AA that always sends asset A together with asset B to the same output address) will **permanently and deterministically** fail every time that code path executes, if:
- the asset's attestor list never attests the AA-computed destination address, or
- the asset's `transfer_condition`/`issue_condition` references a filter that can never be satisfied for AA-generated outputs (e.g., referencing addresses/inputs the AA can never produce).

This is the direct analog of the reported bug class: a single malicious/misconfigured asset embedded in a push-style bundled payout can force reversion of the entire payout operation, freezing funds (both the poisoned asset and any legitimate assets/bytes bundled with it) belonging to everyone relying on that AA code path.

### Impact Explanation
Any AA logic that bundles a payment in a "problem" asset together with other legitimate payments (bytes for bounce fee, other assets, state updates) in the same response can be permanently DoS'd for that code path. This freezes both the malicious asset's balance and unrelated legitimate value in the AA, since the unit — and hence the whole trigger's effects — is always rolled back to the bounce state. Because bounce refunds cannot undo the fact that the intended business logic never completes, users triggering that AA function lose the ability to ever receive their expected payout via that path, and the AA's held funds for that path become stuck. This matches "High" severity: permanent freezing of funds/functionality without any privileged actor being at fault, triggerable by a normal, unprivileged asset issuer or AA integrator picking an asset with an unsatisfiable condition (deliberately or not).

### Likelihood Explanation
Any user can define an asset (`asset` message) with `spender_attested: true` and an attestor list they never update, or with a `transfer_condition`/`issue_condition` that cannot be satisfied by an AA's deterministic outputs. If an AA developer accepts arbitrary user-supplied assets in `trigger.data` (a common oscript pattern, as seen in the `futures_contract.oscript` and `option_contract.oscript` samples where `trigger.output[[asset!=base]].asset` is captured and later paid back), and later bundles a payout of that asset together with other logic in one atomic response, the condition is fully attacker-controlled at asset-definition time and requires no special privilege — only the ability to post an ordinary `asset` definition unit and interact with the AA once.

### Recommendation
Before composing a payment message for a non-base asset in `aa_composer.js`, pre-validate that the intended output addresses satisfy `spender_attested`/attestor and `transfer_condition`/`issue_condition` requirements (similar to the existing `is_private` check at line 1330), and bounce early with a clear, isolated error rather than allowing the check to be discovered only at full-unit validation time where it aborts the entire bundled response. Additionally, consider decoupling unrelated asset payments into independent messages/paths so failure of one asset's condition does not necessarily roll back unrelated legitimate transfers bundled in the same trigger response, or require AA authors to explicitly acknowledge/guard against holding non-whitelisted, freely-issued assets in code paths that bundle multiple payments atomically.

### Proof of Concept
1. Attacker issues an asset `X` via a normal `asset` definition unit with `spender_attested: true` and an attestor list containing only an address the attacker controls and never uses to attest anyone (or a `transfer_condition` referencing a filter/address that an AA-generated output can never match).
2. Attacker interacts with an AA whose oscript logic captures `trigger.output[[asset!=base]].asset` (a common pattern, e.g. `futures_contract.oscript`/`option_contract.oscript`) and later bundles a payment of that captured asset together with a base-byte payment/state update in one response (as in `sendUnit`'s message loop).
3. When the AA composes its response unit, `aa_composer.js`'s asset pre-check (lines 1323-1331) does not flag asset `X`'s attestor/condition problem, so the composer proceeds and later calls `validateAndSaveUnit` (lines 1405-1411).
4. `validatePaymentInputsAndOutputs` in `validation.js` (lines 2630-2659) fails with `"some output addresses are not attested"` or `"transfer or issue condition not satisfied"`.
5. `bounce(err)` (lines 1759-1783) discards the entire response, including the base-byte payment/state changes that would otherwise have succeeded, permanently repeating on every subsequent trigger that requires paying out asset `X` through that same code path — freezing both asset `X` and the logic bundled with it.

### Citations

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

**File:** aa_composer.js (L1759-1783)
```javascript
	function revert(err) {
		console.log('will revert: ' + err);
		if (bSecondary)
			return bounce(err);
		if (!trigger_opts.bAir)
			revertResponsesInCaches(arrResponses);
		
		// copy all logs
		var logs = [];
		arrResponses.forEach(objAAResponse => {
			if (objAAResponse.logs)
				logs = logs.concat(objAAResponse.logs);
		});
		if (logs.length > 0)
			objValidationState.logs = logs;
		
		arrResponses.splice(0, arrResponses.length); // start over
		if (trigger_opts.bAir)
			return bounce(err);
		Object.keys(stateVars).forEach(function (address) { delete stateVars[address]; });
		batch.clear();
		conn.query("ROLLBACK TO SAVEPOINT initial_balances", function () {
			console.log('done revert: ' + err);
			bounce(err);
		});
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
