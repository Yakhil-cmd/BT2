### Title
AA payout unit is atomic across all bundled payment messages, so a poisoned asset's `transfer_condition` can permanently block payout of all other assets/bytes bundled in the same response - ([File: aa_composer.js])

### Summary
`aa_composer.js`'s `sendUnit()` builds **one single response unit** containing all payment messages an AA wants to send in response to a trigger (base bytes plus any number of custom assets). The unit is validated as a whole via `validateAndSaveUnit()`; if validation fails for **any** message in it (e.g. because one asset's `transfer_condition` is not satisfied), the entire unit is discarded and `bounce()` is invoked, wiping out all state changes and all outgoing payments in that response — not just the offending asset payment.

### Finding Description
When an AA responds to a trigger, `handleTrigger()` calls `sendUnit(messages)` with the full list of payment messages the AA wants to emit (e.g. a base-byte transfer, plus any other assets held by the AA) [1](#0-0) . All of these payment messages are combined into a **single `objUnit`** with `messages: messages` [2](#0-1) .

For each non-base asset message, `sendUnit` loads asset info and completes the payment payload with `loadAssetWithListOfAttestedAuthors` / `completePaymentPayload` [3](#0-2) . The unit as a whole is then submitted through `validateAndSaveUnit(objUnit, ...)`, and **any** error from that call — including a failed asset `transfer_condition` — causes the whole response to `bounce(err)` [4](#0-3) .

`transfer_condition`/`issue_condition` are arbitrary, asset-issuer-defined boolean definitions (`Definition.evaluateAssetCondition`), checked during normal payment validation for every transfer of that asset, including transfers made by an AA [5](#0-4) . Nothing in the validation logic distinguishes "AA-issued transfer of a hostile third-party asset" from an ordinary transfer — the condition is evaluated exactly as the asset's definer wrote it, and an attacker (as asset issuer) can define one that legitimately never evaluates true for AA-controlled outputs (e.g. requiring authentication/attestation from an address the attacker never signs from, or referencing outputs/inputs conditions that the AA can never satisfy).

`bounce()` discards **all** messages of the trigger's response and undoes state changes / balance changes accumulated so far for that trigger (`revert()` rolls back to the `initial_balances` savepoint) [6](#0-5) ; it does not undo the earlier deposit of the malicious asset into the AA's balance. Consequently, if an AA's payout logic is written to send several different assets (or bytes plus an asset) together in one trigger response — a normal pattern for escrow/bounty-like AAs that release a reward together with returning collateral, or that batch multiple asset payouts in a single oscript `messages` array — an attacker can fund the AA with one asset carrying a permanently-failing `transfer_condition`. Every time the AA tries to pay out (this trigger or any future retrigger that reaches the same code path), the entire response bounces, and the legitimate, well-behaved assets/bytes that were supposed to be paid out alongside the poisoned one are never delivered, because they are bundled atomically in the same unit that is rejected.

This directly mirrors the reported bug class: mixing a malicious asset among legitimate ones in a payout causes the wholesale failure of the payout, freezing funds that would otherwise be perfectly claimable.

### Impact Explanation
Any AA whose response logic combines a payout of an attacker-controllable/attacker-funded custom asset together with base bytes or other well-behaved assets in the same trigger response can have that entire payout permanently blocked. Legitimate claimants can never receive bytes or other assets that were bundled with the poisoned asset, because `sendUnit` treats the whole set of messages as a single atomic unit and any validation failure (including a hostile `transfer_condition`) bounces everything. Funds already held by the AA (deposited before the attack, or arriving via a trigger that also includes the attacker's asset) become effectively frozen in the AA — a fund-freezing condition with no automatic recovery path, since every subsequent attempt to run the same payout logic hits the same unsatisfiable condition. This is a Medium/High-severity AA fund-freezing issue.

### Likelihood Explanation
Reaching this is straightforward for any unprivileged asset issuer: define a new asset (`issue_condition`/`transfer_condition` are validated only for well-formedness, not for "always satisfiable"), fund an AA that pays out multiple assets together, and trigger it. No special privileges or race conditions are needed. The likelihood is highest for AAs whose logic bundles payment of arbitrary/attacker-supplied assets together with the AA's own bytes/assets in the same response (a common and encouraged AA pattern), but the primitive itself (bundling messages into one atomic unit, with an asset condition able to be defined by anyone) is a base-layer characteristic, not an application bug — meaning any Oscript author who doesn't defensively isolate third-party asset payouts into their own trigger response is exposed.

### Recommendation
- When an AA sends a payment of a caller-/attacker-supplied asset together with other payments, isolate that asset payment into its own secondary trigger/response so a failure in the untrusted asset's condition cannot block payout of the AA's own bytes or other assets.
- Consider surfacing a documented best practice / oscript-level warning that bundling attacker-controllable-asset payments with other payments in the same `messages` array is unsafe, and provide a state-var-driven retry/skip mechanism so a single failing asset payment doesn't roll back the entire response.
- At the protocol level, evaluate whether `sendUnit`/`bounce` could optionally drop only the offending payment message (with an error response for that asset) instead of discarding the entire batch, when the failure is isolated to one asset's transfer condition and not to a structural/balance error.

### Proof of Concept
1. Attacker publishes an `asset` definition with `transfer_condition` set to a condition the attacker knows can never be satisfied when the AA is the sender (e.g., requiring a signature from an address only the attacker controls and will never provide, or `has address` filters that reference outputs the AA logic will never produce).
2. Attacker sends a trigger to a target AA whose oscript logic, upon receiving a payment, responds by paying out both base bytes (or a legitimate asset) and forwarding/returning the received custom asset in the *same* set of `messages` (a common bounty/escrow-style AA pattern releasing a reward plus returning collateral atomically).
3. `handleTrigger` → `sendUnit` builds one `objUnit` containing both the base-byte payment message and the malicious-asset payment message [2](#0-1) .
4. `validateAndSaveUnit` fails because the malicious asset's `transfer_condition` is not satisfied (validated per `validatePaymentInputsAndOutputs` → `Definition.evaluateAssetCondition`) [5](#0-4) .
5. `bounce(err)` is called [7](#0-6) , discarding the entire response, including the base-byte payout that had nothing to do with the poisoned asset.
6. Every subsequent trigger that would exercise the same payout path bounces identically, permanently preventing the legitimate recipient from ever receiving the bundled bytes/assets — the funds remain stuck in the AA.

### Citations

**File:** aa_composer.js (L1043-1054)
```javascript
	async function sendUnit(messages) {
		if (trigger_opts.bAir)
			return sendDummyUnit(messages);
		console.log('send unit with messages', util.inspect(messages, { depth: 6 }));
		var arrUsedOutputIds = [];
		var arrConsumedOutputs = [];
		var objUnit;

		const objLastBallUnit = await storage.readUnitProps(conn, objMcUnit.last_ball_unit);
		if (!objLastBallUnit)
			throw Error("last ball unit not found: " + objMcUnit.last_ball_unit);
		const last_ball_mci = objLastBallUnit.main_chain_index;
```

**File:** aa_composer.js (L1312-1344)
```javascript
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
```

**File:** aa_composer.js (L1362-1377)
```javascript
				if (!objBasePaymentMessage) {
					objBasePaymentMessage = { app: 'payment', payload: { outputs: [] } };
					messages.push(objBasePaymentMessage);
				}
				// add payload_location and wrong payload_hash
				objBasePaymentMessage.payload_location = 'inline';
				objBasePaymentMessage.payload_hash = '-'.repeat(44);
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

**File:** validation.js (L2643-2658)
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
```
