Key finding: `validateAndSaveUnit(objUnit, ...)` at `aa_composer.js:1408` runs the composed AA response through full validation before saving, and if it fails, `bounce(err)` is invoked — but the `bounce()` function (`aa_composer.js:909-945`) itself unconditionally hardcodes the refund destination as `trigger.address` and offers no fallback address. Both the primary payment logic and the built-in bounce mechanism send exclusively to `trigger.address` with no way for the AA or trigger sender to redirect funds to an alternate address.

### Title
AA payments and bounce refunds are hardcoded to `trigger.address` with no alternate-recipient mechanism, permanently freezing funds if that address becomes ineligible to receive the asset - (File: aa_composer.js)

### Summary
Autonomous Agent (AA) responses (both normal payment messages built from oscript templates and the built-in `bounce()` fallback) always send funds back to `trigger.address` — the address that authored the triggering unit — with no parameter or mechanism allowing the recipient to be redirected to a different address.

### Finding Description
Throughout `aa_composer.js`, AA-authored payment outputs use `trigger.address` as the hardcoded destination, as seen in every AA response template (`test/samples/simple_aa.oscript:9`, `test/samples/just_a_bouncer.oscript:9`, `test/samples/bounce_half_of_balance.oscript:9`) and, critically, in the core `bounce()` function itself: [1](#0-0) 

The composed response unit is validated before being committed via `validateAndSaveUnit(objUnit, ...)`; if validation fails, the code falls back to `bounce(err)`: [2](#0-1) 

For assets defined with `spender_attested: true`, `validatePaymentInputsAndOutputs` requires that *all output addresses* (not just inputs) be on the attestor's attested list, or the entire unit is rejected: [3](#0-2) 

`aa_composer.js` never checks attestation status (or `is_transferrable`/`transfer_condition` eligibility) of `trigger.address` before composing payment or bounce messages — no `filterAttestedAddresses` or equivalent call exists anywhere in that file. Consequently, if the asset held by the AA on a user's behalf requires attestation (or has a transfer condition tied to eligibility) and `trigger.address` loses/lacks that attestation at execution time, every payment message that tries to send funds back to `trigger.address` fails full validation. The response then falls through to `bounce()`, which composes its refund to the very same ineligible `trigger.address`, so the bounce transaction fails validation as well, looping back into `bounce()` recursion guard (`bBouncing`) and ultimately calling `finish(null)` with no response unit produced at all.

### Impact Explanation
Because both normal payments and bounce refunds are hardcoded to `trigger.address`, a user whose address becomes ineligible for an attested/restricted asset (e.g., attestor revokes the address, or the asset's `transfer_condition` stops being satisfied for that address) permanently loses access to any balance the AA is holding on their behalf, and the AA can never validly transfer that value out to them — there is no way to specify a different destination address (analogous to Surge's `removeCollateral`/`withdraw` lacking a recipient parameter). This is a genuine freezing-of-AA-funds scenario reachable by an ordinary AA trigger sender, matching the required "AA fund loss or freezing" impact class.

### Likelihood Explanation
This requires an AA that holds/forwards a `spender_attested` (or otherwise address-restricted) asset on behalf of users and later needs to pay that asset back to `trigger.address` — a common and encouraged pattern in AA design (all sample AAs in the repo follow it). Any change in the trigger address's attestation/eligibility status between depositing into the AA and later withdrawal (which the AA logic cannot control since it isn't the attestor) triggers the freeze, so likelihood depends on real-world usage of attested/restricted assets with AAs, but the underlying protocol gap is deterministic and unconditional (no exception handling or configurable recipient exists in `aa_composer.js`).

### Recommendation
Allow AA definitions/oscript templates and the built-in `bounce()` mechanism to target a configurable output address (e.g., allow the AA response template to override the destination, or let `bounce()` accept an alternate recipient supplied via trigger data), and/or have `aa_composer.js` pre-check output address eligibility (via `storage.filterAttestedAddresses` / `Definition.evaluateAssetCondition`) before composing payment messages so failures can be surfaced explicitly (with the trigger's coins retained safely in AA state) rather than silently dropping to an equally-failing bounce.

### Proof of Concept
1. Issuer defines asset `A` with `spender_attested: true` and a set of attestors.
2. AA `W` is deployed with logic: `if (trigger.data.withdraw) send asset A back to trigger.address using stored balance var`. (See pattern in `test/samples/a_bank_without_percent.oscript:1-30`, `test/samples/order_book_exchange.oscript:1-25`.)
3. Address `U` is attested and deposits asset `A` into `W`, incrementing `balance_U_A` in AA state (`W`'s address itself must be attested to receive the deposit, which it is).
4. Attestor revokes/never grants attestation for `U` going forward (or `U`'s attestation naturally expires per attestor policy), e.g. via `asset_attestors` update.
5. `U` sends a trigger with `trigger.data.withdraw=true` requesting the previously deposited balance.
6. `handleTrigger` in `aa_composer.js` composes a `payment` message with `outputs: [{address: U, amount: X}]` for asset `A`.
7. `validateAndSaveUnit` (aa_composer.js:1408) fails validation because `U` is not in `arrAttestedAddresses` (validation.js:2632-2641 "some output addresses are not attested").
8. `bounce(err)` fires (aa_composer.js:1410), but `bounce()` composes its refund payment also targeting `U` (aa_composer.js:940), which fails validation identically.
9. `bBouncing` guard prevents infinite recursion and `finish(null)` is called with no response unit — `U`'s balance in `W`'s state remains untouched, permanently locked, with no mechanism in oscript or `aa_composer.js` to redirect the withdrawal to an alternate, eligible address.

### Citations

**File:** aa_composer.js (L930-944)
```javascript
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

**File:** aa_composer.js (L1405-1413)
```javascript
						executeStateUpdateFormula(objUnit, function (err) {
							if (err)
								return bounce(err);
							validateAndSaveUnit(objUnit, function (err) {
								if (err)
									return bounce(err);
								updateFinalAABalances(arrConsumedOutputs, objUnit, function () {
									if (arrOutputAddresses.length === 0)
										return finish(objUnit);
```

**File:** validation.js (L2630-2641)
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
```
