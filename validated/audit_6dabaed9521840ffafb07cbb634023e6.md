### Title
AA trigger senders can permanently lose their attached payment when an AA's duration/vesting-style formula evaluates the payout to zero - ([File: aa_composer.js])

### Summary
This is the same bug class as TRST‑M‑4: a value that consumes the caller's input funds is computed from user-controlled parameters (e.g. a duration/rate formula), and if that computed value rounds to zero, the framework silently "succeeds" instead of reverting/returning the funds. In ocore, this manifests in `sendUnit`'s message-preparation logic inside `handleTrigger` in `aa_composer.js`.

### Finding Description
When an Autonomous Agent (AA) responds to a trigger, `aa_composer.js` filters payment outputs whose computed `amount` is zero and then drops payment messages that end up with no outputs: [1](#0-0) 
If, after this filtering, no messages remain at all, the code does **not** bounce the trigger (which is the mechanism that returns the trigger's attached payment back to the sender minus the bounce fee); instead it calls `handleSuccessfulEmptyResponseUnit(null)`, treating the trigger as successfully processed: [2](#0-1) 
The same silent-filtering/silent-success pattern is repeated a second time after the payload is completed: [3](#0-2) 

This is functionally identical to the root cause described in TRST‑M‑4: an amount is derived from a user-controllable parameter (in Moz's case `duration`; in an ocore AA, any user-supplied trigger data feeding a vesting/rate/duration formula), and when that derived amount is zero, the framework consumes the input (the trigger's attached payment/asset, which is unconditionally credited to the AA's balance as soon as the trigger unit is included in the DAG) but produces no compensating output, and, critically, no error/bounce path is taken to refund the sender. Because oscript AAs commonly follow deposit/redeem/vesting patterns like the ones seen in `test/samples/futures_contract.oscript` (round-based conversion), `test/samples/51_attack_game.oscript` (`$amount = round(...)` payout), and `test/samples/payment_channels.oscript`, an AA author who does not explicitly guard with `bounce()` when a computed payout is zero exposes every trigger sender to the same class of fund loss that TRST‑M-4 describes.

Notably, ocore's own core-protocol code recognizes this exact bug class elsewhere and defends against it: for `headers_commission`/`witnessing` inputs, the validator explicitly rejects a computed commission of zero rather than silently proceeding: [4](#0-3) 
No equivalent safety net exists for the AA payment-message path — the framework simply drops the zero-output message and reports success, rather than requiring the AA to bounce or refusing to finalize the response.

### Impact Explanation
This falls under the accepted "AA fund loss" category. A trigger sender's payment (bytes or a custom asset) attached to a trigger unit is credited to the AA's balance the moment the unit stabilizes/executes, independent of whether the AA's response contains any output back to the sender. If the AA's payout/refund formula (a common pattern for vesting, staking-redeem, or subscription-style AAs) evaluates to zero due to a too-small input parameter (e.g., a too-short duration, a too-small amount before rounding, or a stale/borderline data-feed value), the trigger sender's funds are absorbed into the AA's balance with no recorded credit and no returned payment — a real, unrecoverable loss of funds for an ordinary AA trigger sender, mirroring the "user loses entire xMoz balance" outcome in the original report.

### Likelihood Explanation
This is only exploitable when an AA author's `oscript` fails to add a `bounce()` guard before or after computing a possibly-zero payout — exactly the same failure mode as the original unmitigated `redeem()`. Since ocore ships and documents `oscript` primitives (`round()`, division, duration-based formulas) that make zero results reachable from ordinary user input, and since the framework's default behavior on a fully-filtered zero-output response is silent success rather than a hard failure/bounce, this is a plausible and easy-to-trigger scenario for any commonly-written vesting/redeem/exchange-style AA, requiring only an unprivileged AA trigger sender supplying an edge-case parameter (e.g., minimal duration or amount).

### Recommendation
- In `aa_composer.js`, when all payment messages are filtered out due to zero-amount outputs (both the first-pass filter at lines 1277-1286 and the second-pass filter at lines 1349-1361), consider surfacing this state distinctly (e.g., logging/metrics) so wallet/AA-authoring tooling can flag AAs that regularly hit this path, and update AA-authoring documentation/`aa_validation.js` linting to require an explicit zero-amount check (`if (amount <= 0) bounce(...)`) before any payment message whose amount is derived from user-controlled data.
- Provide a built-in oscript safeguard (analogous to the zero-commission check in `validation.js`) so that a payment `if` producing a non-positive amount can, at the AA definition-validation level (`aa_validation.js`), be flagged/required to include a corresponding bounce guard for state-changing branches that also debit persistent `var[]` state.

### Proof of Concept
1. Deploy an AA whose response to a trigger conditionally computes a payout via a duration- or rate-based formula, e.g. (pattern seen in `test/samples/51_attack_game.oscript` lines 116-148 and `test/samples/futures_contract.oscript` lines 71-105):
```
messages: [{
  app: 'payment',
  payload: { asset: 'base', outputs: [{ address: "{trigger.address}", amount: "{ round($rate * trigger.output[[asset=base]] / $duration) }" }] }
}]
```
2. A trigger sender sends the AA a small `trigger.output[[asset=base]]` amount together with a `duration` value (or triggers the case at a borderline of `$rate`) that makes the rounded `amount` evaluate to `0`.
3. `aa_composer.js` filters this single zero-amount output (`aa_composer.js:1278`), leaving `messages.length === 0`.
4. The code calls `handleSuccessfulEmptyResponseUnit(null)` (`aa_composer.js:1282-1286`) instead of bouncing; the trigger's attached payment is retained by the AA balance permanently, and the sender receives nothing back.

### Citations

**File:** aa_composer.js (L1277-1286)
```javascript
			// filter out 0-outputs
			payload.outputs = payload.outputs.filter(function (output) { return (output.amount > 0 || output.amount === undefined); });
		}
		// remove messages with no outputs
		messages = messages.filter(function (message) { return (message.app !== 'payment' || message.payload.outputs.length > 0); });
		if (messages.length === 0) {
			error_message = 'no messages after removing 0-outputs';
			console.log(error_message);
			return handleSuccessfulEmptyResponseUnit(null);
		}
```

**File:** aa_composer.js (L1349-1361)
```javascript
				// remove messages with no outputs again (send-all outputs might get removed if nothing found for them)
				messages = messages.filter(function (message) { return (message.app !== 'payment' || message.payload.outputs.length > 0); });
				if (messages.length === 0) {
					error_message = 'no messages after removing 0-outputs (2nd pass)';
					console.log(error_message);
					return handleSuccessfulEmptyResponseUnit(null);
				}
				messages = messages.filter(function (message) { return (message.app !== 'payment' || !message.payload.asset || !assetInfos[message.payload.asset].fixed_denominations); });
				if (messages.length === 0) {
					error_message = 'no messages after removing fixed denominations';
					console.log(error_message);
					return handleSuccessfulEmptyResponseUnit(null);
				}
```

**File:** validation.js (L2593-2599)
```javascript
							ifOk: function(commission){
								if (commission === 0)
									return cb("zero "+type+" commission");
								total_input += commission;
								checkInputDoubleSpend(cb);
							}
						});
```
