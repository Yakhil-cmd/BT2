## Title
AA bounce mechanism permanently freezes incoming asset funds when the compensating payment to `trigger.address` fails asset transfer restrictions - (File: aa_composer.js)

### Summary
`aa_composer.js`'s `handleTrigger()` implements an automatic "bounce" mechanism: whenever an AA response fails to validate, the framework tries to refund the trigger's payment back to `trigger.address`. This refund path assumes it can always succeed. If the asset being refunded has `spender_attested`, `transfer_condition`, or `is_transferrable` restrictions that make `trigger.address` an invalid recipient at bounce time, the refund attempt fails validation, which recursively calls `bounce()` again — but the recursive call is silently swallowed by a re-entrancy guard, producing no response unit at all. The funds received from the trigger are then permanently stuck in the AA's balance with no possible path to recovery.

### Finding Description
`bounce()` builds a payment message that sends `trigger.outputs` back to `trigger.address` and calls `sendUnit(messages)`: [1](#0-0) 

`sendUnit()` composes and validates this payment. Asset checks such as `spender_attested` and `transfer_condition` are evaluated only during full unit validation (`validateAndSaveUnit`), not during the earlier `loadAssetWithListOfAttestedAuthors` prefetch in `sendUnit`: [2](#0-1) 

If unit validation fails (e.g., because `trigger.address` is no longer on the asset's attestor list, or fails the `transfer_condition`, or the asset's `is_transferrable` rules reject this input/output combination), the error propagates back and `bounce(err)` is invoked a second time: [3](#0-2) 

The relevant asset validation rules that can make an address (including the original trigger sender) an invalid recipient are: [4](#0-3) 

Because `bBouncing` was already set to `true` on the first bounce attempt, the second invocation of `bounce()` hits the guard and calls `finish(null)` instead of retrying or erroring loudly: [5](#0-4) 

`finish(null)` records only an internal `aa_responses` row with `response.error` and returns no response unit — no payment message is ever issued to move the coins anywhere: [6](#0-5) 

Because the original trigger unit (the payment into the AA) is validated and confirmed independently of what the AA does afterward, the AA legitimately takes custody of those asset coins as soon as the trigger confirms. If the automatic refund can never succeed, those coins become permanently unspendable — the AA has no other code path to dispose of coins that it received but couldn't legally forward.

An attacker can force this condition deliberately, e.g.:
- Issue a `spender_attested` asset, keep themselves attested, send it (with a trigger) to an AA that will fail to consume it properly (e.g., unmatched `if` conditions, exceeding `max_aa_responses`, or any other legitimate bounce trigger), then de-attest themselves (via an `asset_attestors` update) before the bounce is processed, causing the refund back to their own `trigger.address` to fail the `spender_attested` check.
- Use an asset with a `transfer_condition` that is state-dependent and can be flipped false by the attacker at will after sending the trigger, making the refund evaluate to "condition not satisfied."

### Impact Explanation
This causes permanent freezing of asset funds inside the AA — the coins can never be spent by anyone once the double-bounce failure occurs, since the "eat the funds silently" fallback (`finish(null)`) leaves them as an untouched, unspendable UTXO belonging to the AA address, with no code path in `handleTrigger` designed to recover or redirect them. This matches the accepted impact category of "AA fund loss or freezing."

### Likelihood Explanation
Any unprivileged asset issuer/attestor can trigger this by controlling both the asset's transfer conditions and the timing of a change to those conditions relative to when their trigger unit's AA response gets processed. No special privileges beyond normal asset definition (`asset`, `asset_attestors` messages) and AA-triggering payments are required.

### Recommendation
- Do not treat `trigger.address` as an unconditionally valid bounce recipient; validate the refund payload against the asset's `spender_attested`/`transfer_condition`/`is_transferrable` rules before attempting `sendUnit`, and handle failure explicitly (e.g., forward to the asset definer, or otherwise surface a distinguishable, retryable/refundable failure) rather than silently absorbing the funds via `finish(null)` on the recursive `bounce()` call.
- Consider making the second-level bounce failure produce a response unit or clear on-chain marker so custody of the stuck coins is auditable and potentially recoverable rather than perpetually inert.

### Proof of Concept
1. Attacker issues asset A with `spender_attested: true`, attestor list initially includes attacker's address, via an `asset` message (validated per `validateAssetDefinition`): [7](#0-6) 
2. Attacker sends a trigger payment of asset A to an AA whose logic will legitimately bounce for some other reason (e.g., unmet `if` condition, exceeded response limits) — see the standard bounce path: [8](#0-7) 
3. Before the trigger's MCI stabilizes and the AA processes it, the attacker posts an `asset_attestors` update removing their own address from the attestor list.
4. When `handleTrigger` runs and reaches `bounce()`, `sendUnit` composes a payment of asset A back to the attacker's `trigger.address`. `validateAndSaveUnit` fails the `spender_attested` check (`some output addresses are not attested`) per: [9](#0-8) 
5. This failure calls `bounce(err)` again; since `bBouncing` is already `true`, `finish(null)` is invoked, no response unit is produced, and the asset A coins remain permanently held by the AA with no way to be spent by the AA or the attacker.

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

**File:** aa_composer.js (L1298-1348)
```javascript
		async.eachSeries(
			messages,
			function (message, cb) {
				if (message.app !== 'payment') {
					try {
						if (message.app === 'definition')
							message.payload.address = objectHash.getChash160(message.payload.definition);
						completeMessage(message);
					}
					catch (e) { // may error if there are empty objects or arrays inside
						return cb("some hashes failed: " + e.toString());
					}
					return cb();
				}
				var payload = message.payload;
				if (payload.asset === 'base')
					delete payload.asset;
				var asset = payload.asset || null;
				if (asset === null) {
					if (objBasePaymentMessage)
						return cb("already have base payment");
					objBasePaymentMessage = message;
					// we'll add output addresses later, after possibly removing a send-all output
					return cb(); // skip it for now, we can estimate the fees only after all other messages are in place
				}
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
			},
			function (err) {
				if (err)
					return bounce(err);
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

**File:** aa_composer.js (L1671-1700)
```javascript
	function finish(objResponseUnit) {
		if (bBouncing && bSecondary) {
			if (objResponseUnit)
				throw Error('response_unit with bouncing a secondary AA');
			if (!bAddedResponse && objValidationState.logs) // add the logs from the final bouncing unit
				arrResponses.push({ logs: objValidationState.logs });

			if (typeof error_message === 'string') {
				error_message = { message: error_message };
			}

			let errorObj = { address };
			if (error_message.address) {
				errorObj.next = error_message;
			} else {
				errorObj = { ...errorObj, ...error_message };
			}
			return onDone(null, errorObj);
		}
		fixStateVars();
		saveStateVars();
		addResponse(objResponseUnit, function () {
			updateStorageSize(function (err) {
				if (err)
					return revert(err);
				addUpdatedStateVarsIntoPrimaryResponse();
				onDone(objResponseUnit, bBouncing ? error_message : false);
			});
		});
	}
```

**File:** aa_composer.js (L1841-1863)
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
```

**File:** validation.js (L2616-2659)
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

**File:** validation.js (L2725-2755)
```javascript
function validateAssetDefinition(conn, payload, objUnit, objValidationState, callback){
	if (objUnit.authors.length !== 1)
		return callback("asset definition must be single-authored");
	if (!isNonemptyObject(payload))
		return callback("asset definition must be a non-empty object");
	if (hasFieldsExcept(payload, ["cap", "is_private", "is_transferrable", "auto_destroy", "fixed_denominations", "issued_by_definer_only", "cosigned_by_definer", "spender_attested", "issue_condition", "transfer_condition", "attestors", "denominations"]))
		return callback("unknown fields in asset definition");
	if (typeof payload.is_private !== "boolean" || typeof payload.is_transferrable !== "boolean" || typeof payload.auto_destroy !== "boolean" || typeof payload.fixed_denominations !== "boolean" || typeof payload.issued_by_definer_only !== "boolean" || typeof payload.cosigned_by_definer !== "boolean" || typeof payload.spender_attested !== "boolean")
		return callback("some required fields in asset definition are missing");

	if ("cap" in payload && !(isPositiveInteger(payload.cap) && payload.cap <= constants.MAX_CAP))
		return callback("invalid cap");

	if (objValidationState.bAA) {
		if (payload.cosigned_by_definer !== false)
			return callback("cosigned_by_definer must be false because AAs can't cosign");
		if (payload.issued_by_definer_only === true && (payload.is_private !== false || payload.fixed_denominations !== false))
			return callback("assets issued by AA definer cannot be private or fixed denominations");
	}

	// attestors
	var err;
	if ( payload.spender_attested && (err=checkAttestorList(payload.attestors)) )
		return callback(err);
	if (!payload.spender_attested && "attestors" in payload && (objValidationState.last_ball_mci >= constants.pemCurvesFixMci || !objValidationState.hasBall && storage.getMinRetrievableMci() >= constants.pemCurvesFixMci))
		return callback("attestors should not be defined when spender_attested is false");

	// denominations
	if (payload.fixed_denominations && !isNonemptyArray(payload.denominations))
		return callback("denominations not defined");
	if (!payload.fixed_denominations && "denominations" in payload)
```
