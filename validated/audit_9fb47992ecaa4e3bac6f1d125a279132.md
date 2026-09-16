### Title
A single attacker-deposited asset with an unsatisfiable transfer/issue condition (or unattested-recipient requirement) can atomically bounce an entire multi-asset AA response, freezing all bundled payouts - (File: `aa_composer.js`)

### Summary
Any unit can pay an arbitrary, attacker-defined asset (with an `issue_condition`/`transfer_condition`/`spender_attested` list crafted by the attacker) to an Autonomous Agent — there is no whitelist or filter on what assets an AA can receive, exactly as OpenQ accepted arbitrary ERC-20 deposits. When the AA later composes a response unit that bundles a payment in this "rogue" asset together with payments in other, legitimate assets/bytes (a normal AA pattern, e.g. paying out two different assets to a claimant in one trigger response), `aa_composer.js`'s `sendUnit`/`completePaymentPayload` never checks `transfer_condition`, `issue_condition`, or attestor lists before building the unit. The check only happens later in full validation (`validateAndSaveUnit` → `validatePaymentInputsAndOutputs` → `Definition.evaluateAssetCondition`). A failure there causes the whole response to `bounce()`, discarding every message in the unit — including the payouts denominated in unrelated, perfectly valid assets that were bundled in the same response.

### Finding Description
`aa_composer.js`'s `completePaymentPayload` (used inside `sendUnit`) only checks `fixed_denominations` and `is_private` for a payment asset before picking inputs and building outputs: [1](#0-0) 
It never evaluates `transfer_condition`/`issue_condition` or the `spender_attested` attestor list for the destination addresses. Those checks are only performed afterwards, when the fully composed unit is validated and saved: [2](#0-1) 
The actual condition/attestation checks live in `validatePaymentInputsAndOutputs`, executed only at this later validation stage: [3](#0-2) 

Because all messages composed for one trigger response are packed into a single unit, and `sendUnit` treats validation failure of that single unit as fatal for the *entire* response: [2](#0-1) 
any single message failing the deferred asset-condition/attestation check causes `bounce(err)` for the whole unit, wiping out every other message (payments in other assets, in bytes, state updates) that were bundled together: [4](#0-3) 

An attacker only needs to define an asset (a normal, unprivileged action — asset issuance is open to anyone) whose `transfer_condition` can never be satisfied for a given recipient, or that requires `spender_attested` with an attestor list the attacker controls, or that is simply `is_transferrable: false` in a way the AA doesn't anticipate: [5](#0-4) 
and then pay that asset into the target AA as part of (or alongside) a normal trigger. If the AA's business logic subsequently tries to pay that balance out together with unrelated legitimate balances in the same response (a pattern explicitly used in the codebase's own sample AAs, which pay out multiple different assets in one trigger response): [6](#0-5) 
the entire response — including the legitimate assets' payouts — is bounced. `bounce()` only refunds the current trigger's own `trigger.outputs`, not any previously-accumulated AA balance in other assets that the response was attempting to distribute: [7](#0-6) 
so those other parties' funds remain locked inside the AA with no privileged recovery mechanism, since AAs have no admin/owner override.

### Impact Explanation
This allows an unprivileged attacker (asset issuer / AA trigger sender) to permanently freeze bundled AA fund distributions: any legitimate assets or bytes that an AA tries to send out together with a poisoned asset in the same response unit are stuck, because the atomic all-or-nothing bounce semantics of `sendUnit` do not skip or isolate the failing asset. This matches the "AA fund loss or freezing" impact category — repeated triggers attempting the same distribution will bounce indefinitely as long as the AA logic keeps trying to pay the poisoned asset together with other balances.

### Likelihood Explanation
Likelihood is high for any AA pattern that batches multiple asset payouts (or an asset payout plus a byte payout) into a single trigger response — a common and encouraged AA design shown even in the repository's own sample oscripts. Issuing an asset with a hostile `transfer_condition`/`issue_condition`/`spender_attested` list is unrestricted and cheap for any user, and there is no check anywhere in `aa_composer.js` that filters or whitelists assets accepted into or paid out of an AA balance.

### Recommendation
- In `completePaymentPayload`/`sendUnit`, pre-evaluate `transfer_condition`, `issue_condition`, and `spender_attested`/attestor requirements for every non-base asset message before finalizing the unit, and bounce (or drop) only the offending message instead of failing the entire unit.
- Alternatively, change `sendUnit` so that a validation failure isolated to one payment message causes just that message (and its associated state effects) to be retried without the offending asset, rather than reverting the whole batched response.
- Document clearly for AA authors that bundling multiple assets in one response is unsafe against adversarial asset definitions, and provide a supported primitive for atomic per-asset payout attempts.

### Proof of Concept
1. Attacker issues asset `X` with `transfer_condition` set to an address-based condition that can never be true for the AA's intended recipient (allowed per `validateAssetDefinition`, see `validation.js:2789-2803`).
2. Attacker sends units paying asset `X` to target AA `A`, which pools deposits and is designed to later pay out asset `X` and asset `Y` (both belonging to different depositors/claimants) together in one response, as in the `futures_contract.oscript`/`option_contract.oscript` pattern.
3. A legitimate user triggers `A` to claim their share of assets `X` and `Y`.
4. `aa_composer.js`'s `sendUnit` builds messages for both `X` and `Y` without checking `X`'s `transfer_condition` (`aa_composer.js:1323-1330`).
5. `validateAndSaveUnit` fails on the `X` payment due to unmet `transfer_condition` (`validation.js:2643-2658`), causing `bounce(err)` (`aa_composer.js:1405-1411`).
6. The entire response, including the valid `Y` payout, is discarded; `Y`'s legitimate funds remain stuck in AA `A`'s balance with no way to be distributed as long as the AA logic pairs it with the poisoned `X` payout.

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

**File:** validation.js (L2789-2803)
```javascript
			return callback("has no cap but denominations are capped");
		if (total_cap_from_denominations && payload.cap !== total_cap_from_denominations)
			return callback("cap doesn't match sum of denominations");
	}
	
	if (payload.is_private && payload.is_transferrable && !payload.fixed_denominations)
		return callback("if private and transferrable, must have fixed denominations");
	if (payload.is_private && !payload.fixed_denominations){
		if (!(payload.auto_destroy && !payload.is_transferrable))
			return callback("if private and divisible, must also be auto-destroy and non-transferrable");
	}
	if (payload.is_private && ("issue_condition" in payload || "transfer_condition" in payload) && (objValidationState.last_ball_mci >= constants.noPrivateAssetsWithConditionsUpgradeMci || !objValidationState.hasBall && storage.getMinRetrievableMci() >= constants.noPrivateAssetsWithConditionsUpgradeMci))
		return callback("if private, cannot have issue or transfer conditions");
	if (payload.cap && !payload.issued_by_definer_only)
		return callback("if capped, must be issued by definer only");
```

**File:** test/samples/futures_contract.oscript (L36-57)
```text
			{ // issue USD and GB assets in exchange for bytes, it's ok to issue them even after expiry or blackswan
				if: "{trigger.output[[asset=base]] >= 1e5 AND var['usd_asset'] AND var['gb_asset']}",
				messages: [
					{
						app: 'payment',
						payload: {
							asset: "{var['usd_asset']}",
							outputs: [
								{address: "{trigger.address}", amount: "{ trigger.output[[asset=base]] }"}
							]
						}
					},
					{
						app: 'payment',
						payload: {
							asset: "{var['gb_asset']}",
							outputs: [
								{address: "{trigger.address}", amount: "{ trigger.output[[asset=base]] }"}
							]
						}
					},
				]
```
