### Title
AA payment messages for fixed-denomination (indivisible) assets are silently dropped, while state changes are still committed - (File: aa_composer.js)

### Summary
`sendUnit` in `aa_composer.js` filters out any `payment` message whose asset has `fixed_denominations` set, but the surrounding AA logic (state updates, `init`/response formulas) is evaluated and committed independently of whether the corresponding payment ever gets sent. This mirrors the `VE3DRewardPool` bug class: the contract's payout path silently assumes it can transfer/handle an asset type it actually cannot handle, and the "reward" leg of the transaction is lost while bookkeeping proceeds as if it succeeded.

### Finding Description
When an AA composes its response, each `payment` message is checked against the asset's properties in `sendUnit`: [1](#0-0) 
If the asset is `fixed_denominations` (i.e. an indivisible/private-style NFT-like asset paid by discrete coin denominations rather than an arbitrary formula amount), the payload is not completed and is simply skipped with `return cb();`. Later, after all messages are processed, any remaining payment messages for such assets are stripped out entirely: [2](#0-1) 
If this filtering empties the message list, the AA falls back to `handleSuccessfulEmptyResponseUnit(null)`, i.e., the trigger is treated as a normal, successful, no-response execution: [3](#0-2) 

Critically, the AA's `state` formula (balance decrements, "paid" flags, counters, etc.) is evaluated together with the payment message templates during `evaluateAA`, and is applied via `executeStateUpdateFormula` independently of whether the payment message itself survives the fixed-denominations filter: [4](#0-3) [5](#0-4) 

This is exactly analogous to the reported `VE3DRewardPool` issue: the contract's core payout function assumes the reward token behaves like the expected deposit token, and when that assumption breaks (BAL rewards vs. 80/20 BAL/ETH LP deposits), the function either always reverts or, in ocore's case, silently no-ops the payout while continuing to consider the operation "successful" and update internal state.

Any AA author who defines payout logic using a token they expect to be divisible/transferable-by-amount (the vast majority of AA sample templates use plain `amount` formulas, e.g. `test/samples/create_an_asset.oscript`, `test/aa.test.js`) but whose token later becomes (or already is) a `fixed_denominations` asset will have that payout permanently and silently dropped on every trigger, while any accompanying `state` bookkeeping (e.g., marking a purchase as fulfilled, decrementing a pool balance, incrementing a claimed counter) proceeds as though the payment happened.

### Impact Explanation
Users interacting with such an AA lose the ability to ever receive the fixed-denomination asset they are owed, while the AA's internal accounting treats the obligation as discharged (state vars are still updated, and no bounce/error is surfaced to the trigger sender - it looks like a normal "no messages" success). This constitutes AA fund loss/freezing: the asset units remain trapped at the AA address indefinitely (since the same code path fires on every future trigger for that asset), and legitimate claims are permanently denied without any error signal that alerts the sender to the misconfiguration.

### Likelihood Explanation
This is conditional on an AA being programmed against or later handling an asset that has (or converts to) `fixed_denominations: true`. This is not an edge case unique to a rare integration - `fixed_denominations` is a first-class, commonly used asset property in ocore (used for indivisible/NFT-like or privacy-preserving fixed-denomination assets), documented and validated throughout `aa_validation.js` and `validation.js`. Any AA developer who does not specifically special-case fixed-denomination assets (which is the default assumption baked into virtually all sample AA templates using formula-computed `amount` outputs) will trigger this silently. Similar to the C4 finding being rated Medium because it is "conditional on configuration" rather than universally exploitable, this ocore analog is Medium: it requires the AA to be paired with (or migrate to) a fixed-denomination asset, but once that condition holds, the failure is deterministic and silent on every execution.

### Recommendation
- When a `payment` message's asset turns out to be `fixed_denominations`, `bounce()` the trigger (as is already done for other message-level errors) instead of silently filtering the message and falling through to a "successful" empty response.
- Alternatively, decouple execution of `state`/response-var formulas from message delivery so that state changes tied to a specific payment output are rolled back (or never applied) when that payment message is dropped due to asset incompatibility.
- Document explicitly in AA developer guidance that using plain formula `amount` outputs is incompatible with `fixed_denominations` assets, and consider adding a getter/validation-time check that flags AA definitions with plain-amount payment messages for assets that could be `fixed_denominations`.

### Proof of Concept
1. Deploy an AA whose response messages include a `state` update that marks `var[trigger.address] = 'paid'` together with a `payment` message paying out `some_asset` with a computed `amount` (e.g., `{trigger.data.amount}`), similar to the pattern in `test/samples/create_an_asset.oscript`. [6](#0-5) 
2. Configure/issue `some_asset` with `fixed_denominations: true` (a normal, supported asset configuration per `aa_validation.js`). [7](#0-6) 
3. Send a trigger requesting payout. In `sendUnit`, the payment message payload is skipped (`return cb()`) because `objAsset.fixed_denominations` is true. [8](#0-7) 
4. The message is subsequently filtered out entirely: [2](#0-1) 
5. Observe that the trigger completes as `handleSuccessfulEmptyResponseUnit`, no bounce is returned to the sender, and the AA's `state` variable marking the request as fulfilled is committed via `executeStateUpdateFormula`, permanently preventing the sender from ever being paid the fixed-denomination asset they are owed. [4](#0-3)

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

**File:** aa_composer.js (L1349-1355)
```javascript
				// remove messages with no outputs again (send-all outputs might get removed if nothing found for them)
				messages = messages.filter(function (message) { return (message.app !== 'payment' || message.payload.outputs.length > 0); });
				if (messages.length === 0) {
					error_message = 'no messages after removing 0-outputs (2nd pass)';
					console.log(error_message);
					return handleSuccessfulEmptyResponseUnit(null);
				}
```

**File:** aa_composer.js (L1356-1361)
```javascript
				messages = messages.filter(function (message) { return (message.app !== 'payment' || !message.payload.asset || !assetInfos[message.payload.asset].fixed_denominations); });
				if (messages.length === 0) {
					error_message = 'no messages after removing fixed denominations';
					console.log(error_message);
					return handleSuccessfulEmptyResponseUnit(null);
				}
```

**File:** aa_composer.js (L1431-1450)
```javascript
	function executeStateUpdateFormula(objResponseUnit, cb) {
		if (bBouncing)
			return cb();
		if (!objStateUpdate) {
			const rv_len = getResponseVarsLength();
			if (rv_len > constants.MAX_RESPONSE_VARS_LENGTH)
				return cb(`response vars too long: ${rv_len}`);
			return cb();
		}
		var opts = {
			conn: conn,
			formula: objStateUpdate.formula,
			trigger: trigger,
			params: params,
			locals: objStateUpdate.locals,
			stateVars: stateVars,
			responseVars: responseVars,
			bStateVarAssignmentAllowed: true,
			bStatementsOnly: true,
			objValidationState: objValidationState,
```

**File:** aa_composer.js (L1841-1886)
```javascript
	updateInitialAABalances(function (err) {

		// these errors must be thrown after updating the balances
		if (err)
			return bounce(err);
		if (arrResponses.length >= constants.MAX_RESPONSES_PER_PRIMARY_TRIGGER) // max number of responses per primary trigger, over all branches stemming from the primary trigger
			return bounce("max number of responses per trigger exceeded");
		if ("max_aa_responses" in trigger && arrResponses.length >= trigger.max_aa_responses)
			return bounce(`max_aa_responses ${trigger.max_aa_responses} exceeded`);
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

		evaluateAA(arrDefinition, function (err) {
			if (err)
				return bounce(err);
			var messages = template.messages;
			if (!messages)
				return bounce('no messages');
			// this will also filter out the special message that performs the state changes
			messages = messages.filter(function (message) { return (isNonemptyObject(message) && 'payload' in message && (message.app !== 'payment' || isNonemptyObject(message.payload) && Array.isArray(message.payload.outputs))); });
			if (messages.length === 0) { // eat the received coins and send no response, state changes are still performed
				error_message = 'no messages after filtering';
				console.log(error_message);
				return handleSuccessfulEmptyResponseUnit(null);
			}
			messages.forEach(function (message) {
				var payload = message.payload;
				if (message.app === 'asset' && isNonemptyArray(payload.denominations) && payload.denominations.every(d => isNonemptyObject(d) && ValidationUtils.isPositiveInteger(d.denomination)))
					payload.denominations.sort(sortDenominations);
				if ((message.app === 'asset' || message.app === 'asset_attestors') && isNonemptyArray(payload.attestors) && payload.attestors.every(ValidationUtils.isValidAddress))
					payload.attestors.sort();
			});
			sendUnit(messages);
		});
```

**File:** test/samples/create_an_asset.oscript (L32-43)
```text
			{
				if: "{trigger.data.issue AND trigger.data.asset AND var[trigger.data.asset] == trigger.address}",
				messages: [{
					app: 'payment',
					payload: {
						asset: "{trigger.data.asset}",
						outputs: [
							{address: "{trigger.address}", amount: "{trigger.data.amount}"}
						]
					}
				}]
			},
```

**File:** aa_validation.js (L225-229)
```javascript
				case 'asset':
					if (hasFieldsExcept(payload, ["cap", "is_private", "is_transferrable", "auto_destroy", "fixed_denominations", "issued_by_definer_only", "cosigned_by_definer", "spender_attested", "issue_condition", "transfer_condition", "attestors", "denominations", "init"]))
						return cb2("unknown fields in asset definition in AA");
					if (payload.fixed_denominations === true && !isNonemptyArray(payload.denominations))
						return cb2("denominations not defined");
```
