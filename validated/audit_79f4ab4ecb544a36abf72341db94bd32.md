### Title
Unprivileged trigger sender can permanently freeze AA funds by including a restricted asset that always fails automatic bounce/refund - (File: `aa_composer.js`)

### Summary
Any unprivileged unit poster can trigger an Autonomous Agent (AA) with a payment that includes, alongside bytes, an asset whose issuer-defined `transfer_condition`, `cosigned_by_definer`, `spender_attested`, or `is_transferrable` restrictions make it impossible for the AA to send that asset back to the trigger address. When the AA's automatic bounce logic tries to refund this asset, unit composition/validation fails, the failure re-enters the bounce handler, and the re-entrancy guard silently drops the trigger with no refund and no error surfaced to the user — permanently absorbing the sent funds into the AA's balance with the trigger irreversibly marked as processed.

### Finding Description
`handleTrigger()` in `aa_composer.js` processes any incoming trigger unit permissionlessly. If AA evaluation fails (bad formula, insufficient response, etc.) it calls `bounce(error)`: [1](#0-0) 

`bounce()` sets `bBouncing = true` and constructs refund messages for *every* asset the trigger sent (not just bytes), sending the leftover amount (`amount - bounce_fees[asset]`) back to `trigger.address` via `sendUnit(messages)`.

Crucially, the guard at the top of `bounce()`:
```
if (bBouncing) return finish(null);
```
means that if `sendUnit()` itself fails for any reason (e.g., the payment doesn't validate) and calls `bounce()` a second time, the function no longer attempts anything — it just calls `finish(null)`, i.e., no response unit, no error propagation, no further attempt to salvage the trigger's funds.

`sendUnit()` builds the payment for each non-base asset via `loadAssetWithListOfAttestedAuthors` and `completePaymentPayload`, and ultimately calls `validateAndSaveUnit`, which enforces the standard asset-transfer checks in `validation.js`: [2](#0-1) [3](#0-2) 

and the `cosigned_by_definer` check: [4](#0-3) 

Since the AA authors the refund unit as `authors: [{ address: address }]` (the AA's own address, not the definer nor the trigger's address): [5](#0-4) 

any asset that was defined with `cosigned_by_definer: true`, `spender_attested: true` (and `trigger.address` not attested), or `is_transferrable: false` (and `trigger.address`/AA is not the definer) can **never** be successfully sent back by the AA — the refund payment will always fail validation. On failure, `bounce(err)` is invoked again inside `sendUnit`'s error paths: [6](#0-5) [7](#0-6) 

This second call hits the `if (bBouncing) return finish(null);` guard and the trigger is finalized with no response unit, yet it is still permanently recorded as processed: [8](#0-7) 

Because `aa_responses` is keyed by `(trigger_unit, aa_address)`, this same trigger will never be reprocessed, and the assets it carried remain credited to the AA's address in the `outputs` table without any accompanying bounce/refund message ever having been produced for the user.

This is directly analogous to the Notional Finance report: a permissionless action (there, `settleVaultAccount`; here, AA trigger processing/bounce) attempts an unconditional push-transfer to a recipient address, and that recipient-side restriction (blacklist there; asset transfer/cosign/attestation conditions here) causes the push to revert, which in turn blocks the entire supposedly-permissionless flow instead of degrading gracefully.

### Impact Explanation
- The trigger's assets (both the restricted asset and any bytes sent with it) are absorbed into the AA's address balance without ever being refunded to the sender, and the sender has no way to force a retry because the trigger is marked as already handled in `aa_responses`. This is a direct freezing/loss of user funds sent to any AA (matches the "AA fund loss or freezing" impact criterion).
- This is trivially reachable by any unprivileged unit poster: they simply need to author a payment to any AA that includes such a restricted asset (which they can define themselves via an `asset` message with `cosigned_by_definer: true` or `spender_attested: true`, then send it into an AA trigger), no special permissions or victim cooperation are required.
- Because the failure path is silent (`finish(null)`, no thrown error, no bounce message), it does not just fail loudly and safely — it destroys the possibility of a subsequent bounce attempt for that specific trigger.

### Likelihood Explanation
Any user can create an asset with `cosigned_by_definer: true` or `spender_attested: true` (attestors list can be anyone including addresses that never attest), then send that asset together with enough bytes into an existing/target AA. This does not require cooperation of the AA developer or any race condition — it is entirely under the attacker/self-harmed user's control, making the likelihood high whenever a user (accidentally or intentionally) sends such an asset to an AA.

### Recommendation
When constructing bounce/refund messages, the AA composer should validate up front (before calling `sendUnit`) whether the refund of a given non-base asset back to `trigger.address` can actually satisfy that asset's `transfer_condition`, `cosigned_by_definer`, and `spender_attested` requirements. If it cannot, that asset should be silently excluded from the bounce refund (with the funds left to the AA, as documented/expected behavior) rather than causing the entire trigger to be swallowed via the `bBouncing` re-entrancy guard. Additionally, `bounce()`'s second-failure path (`if (bBouncing) return finish(null);`) should still attempt to bounce back at least the pure `base` asset outputs (which have no transfer restrictions) instead of dropping the whole trigger with zero refund when only one of several assets in the trigger fails to validate.

### Proof of Concept
1. Attacker defines asset `X` with `cosigned_by_definer: true` (or `spender_attested: true` with an attestor list that will never attest the attacker's own address), and issues some units of `X` to their own address (self-issue or a first uncontested transfer to definer/self as allowed by `is_transferrable` validation rules).
2. Attacker sends a trigger unit to any existing AA, with outputs: enough `base` bytes to cover `bounce_fees.base`, plus some amount of asset `X` above `bounce_fees[X]` (or `bounce_fees` unset for `X`, defaulting to 0, so any positive amount).
3. The AA's oscript evaluation legitimately or illegitimately fails (or simply doesn't fully consume/route the `X` balance), causing `bounce(error)` to run in `aa_composer.js` (`aa_composer.js:910-945`).
4. `bounce()` builds a refund message for asset `X` back to `trigger.address` and calls `sendUnit(messages)`.
5. Inside `sendUnit`, `validatePaymentInputsAndOutputs` in `validation.js` rejects the payment of `X` because `cosigned_by_definer` (or `spender_attested`) is not satisfied (`validation.js:2112-2113`, `2643-2659`), causing `sendUnit`'s error path to invoke `bounce(err)` a second time.
6. The `if (bBouncing) return finish(null);` guard at `aa_composer.js:923-924` fires, producing `finish(null)` — no response unit — while `addResponse` (`aa_composer.js:1596-1638`) still inserts a permanent `aa_responses` row for this `trigger_unit`/`aa_address` pair with `response_unit = null`.
7. The attacker's (or any user's) bytes and asset `X` sent in step 2 remain credited to the AA's address in the `outputs` table, with no bounce/refund ever produced and no possibility of reprocessing that trigger — the funds are stuck.

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

**File:** aa_composer.js (L1346-1348)
```javascript
			function (err) {
				if (err)
					return bounce(err);
```

**File:** aa_composer.js (L1369-1377)
```javascript
				objUnit = {
					version: mci >= constants.v4UpgradeMci ? constants.version : (bWithKeys ? constants.version3 : constants.versionWithoutKeySizes), // we should actually use last_ball_mci
					alt: constants.alt,
					timestamp: objMcUnit.timestamp,
					messages: messages,
					authors: [{ address: address }],
					last_ball_unit: objMcUnit.last_ball_unit,
					last_ball: objMcUnit.last_ball,
				};
```

**File:** aa_composer.js (L1405-1410)
```javascript
						executeStateUpdateFormula(objUnit, function (err) {
							if (err)
								return bounce(err);
							validateAndSaveUnit(objUnit, function (err) {
								if (err)
									return bounce(err);
```

**File:** aa_composer.js (L1596-1638)
```javascript
	var bAddedResponse = false;
	function addResponse(objResponseUnit, cb) {
		var response_unit = objResponseUnit ? objResponseUnit.unit : null;
		var response = {};
		if (!bBouncing && Object.keys(responseVars).length > 0)
			response.responseVars = responseVars;
		if (error_message) {
			if (bBouncing)
				response.error = error_message;
			else
				response.info = error_message;
		}
		var objAAResponse = {
			mci: mci,
			timestamp: objMcUnit.timestamp,
			trigger_address: trigger.address,
			trigger_initial_address: trigger.initial_address,
			trigger_unit: trigger.unit,
			trigger_initial_unit: trigger.initial_unit,
			aa_address: address,
			bounced: bBouncing,
			response_unit: response_unit,
			objResponseUnit: objResponseUnit,
			response: response,
			balances: objValidationState.assocBalances[address],
		};
		if (objValidationState.logs)
			objAAResponse.logs = objValidationState.logs;
		arrResponses.push(objAAResponse);
		bAddedResponse = true;
		if (trigger_opts.bAir)
			return cb();
		conn.query(
			"INSERT INTO aa_responses (mci, trigger_address, aa_address, trigger_unit, bounced, response_unit, response) \n\
			VALUES (?, ?,?,?, ?,?,?)",
			[mci, trigger.address, address, trigger.unit, bBouncing ? 1 : 0, response_unit, JSON.stringify(response)],
			function (res) {
				if (!trigger_opts.bDryRun)
					storage.last_aa_response_id = res.insertId;
				cb();
			}
		);
	}
```

**File:** validation.js (L2112-2113)
```javascript
		if (objAsset.cosigned_by_definer && arrAuthorAddresses.indexOf(objAsset.definer_address) === -1)
			return callback("must be cosigned by definer");
```

**File:** validation.js (L2606-2629)
```javascript
		},
		function(err){
			console.log("inputs done "+payload.asset, arrInputAddresses, arrOutputAddresses);
			if (err)
				return callback(err);
			if (total_input > constants.MAX_CAP)
				return callback("total input too large: " + total_input);
			if (objAsset){
				if (total_input !== total_output)
					return callback("inputs and outputs do not balance: "+total_input+" !== "+total_output);
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

**File:** validation.js (L2643-2659)
```javascript
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
