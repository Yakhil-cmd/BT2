This confirms the mechanism. In `bounce()` [1](#0-0) , when the AA's execution fails (e.g., bounces once), it constructs bounce messages that pay back `trigger.outputs[asset]` (minus fees) to `trigger.address` for *every* asset the trigger sent, including `spender_attested` assets, and then calls `sendUnit(messages)`. If that bounce attempt itself fails validation — which happens whenever `trigger.address` is not on the `spender_attested` asset's attestor-approved list (the ocore analog of a blacklisted/denylisted address) — `sendUnit` will call `bounce(err)` again, but since `bBouncing` is already `true`, it just calls `finish(null)` [2](#0-1) , producing **no response unit at all**. The asset that was already transferred to the AA's address in the (already-stable, already-confirmed) trigger unit remains credited to the AA forever, with no way to claw it back, because every attempt to return it to the sender is blocked by `spender_attested`/attestor validation in `validatePaymentInputsAndOutputs` (`"some output addresses are not attested"`) [3](#0-2) .

This is a legitimate resource of the report's bug class — a hardcoded/unconditional attempt to transfer to a party that can be denylisted, causing a fund-freeze condition. Below is the analog finding.

### Title
AA funds are permanently frozen when bounce-refund payment targets a `spender_attested` asset's un-attested trigger address - (File: `aa_composer.js`)

### Summary
When an Autonomous Agent (AA) execution fails and needs to bounce a trigger back to the sender, `bounce()` unconditionally builds a payment message returning any `spender_attested` (attestor/allow-list-restricted) asset the trigger sent, to `trigger.address`, and calls `sendUnit()` to send it. If `trigger.address` is not on that asset's currently active attestor allow-list, this refund payment fails `validatePaymentInputsAndOutputs`'s attestor check, causing `sendUnit` to call `bounce()` again. Because `bBouncing` is already `true` at that point, the code takes the `finish(null)` branch instead of retrying, so **no response unit is produced whatsoever** — the funds already credited to the AA (from the already-stable trigger unit) become permanently stuck with no recovery path.

### Finding Description
- `spender_attested` assets require that the addresses receiving outputs be attested by one of the asset's designated attestors, enforced in `validatePaymentInputsAndOutputs`: `"some output addresses are not attested"` [3](#0-2) . This attestor allow-list is functionally equivalent to a token blacklist/denylist (e.g. USDC) — an address can lose its attested status at any time (attestor revokes it, or simply never attested it), independent of what the AA or the ocore engine can control.
- When an AA bounces (rejects) a trigger — e.g., due to a formula/state error, insufficient balance, or any other business-logic failure — `bounce()` automatically constructs refund payment messages for *every* asset received in the trigger and sends them back to `trigger.address`, without checking whether that address is currently attested for `spender_attested` assets: [4](#0-3) .
- `sendUnit()` composes and validates the refund unit via `validateAndSaveUnit`; if that validation fails (e.g. attestor check), it calls `bounce(err)` again [5](#0-4) .
- `bounce()` guards against infinite recursion with the `bBouncing` flag: on the second call it just does `return finish(null)` [2](#0-1) , meaning the AA produces **no response unit** for this trigger at all.
- Since the original trigger unit (which paid the `spender_attested` asset to the AA address) is already valid, stable, and irreversible by the time the AA processes it, the AA's balance is permanently credited with that asset, but there is no subsequent path (this trigger already consumed, no response emitted) by which those funds can ever be extracted back to the sender or anyone else.

### Impact Explanation
This results in a genuine, unrecoverable **freezing of AA funds** — an explicitly listed valid impact category. Any `spender_attested` asset (a realistic feature for compliance-sensitive/stablecoin-like Obyte assets) sent to an AA that ever needs to bounce that trigger will get permanently trapped in the AA if the sender's address is (or becomes) un-attested, with no mechanism in `aa_composer.js` to route funds elsewhere or retry the refund via a different path.

### Likelihood Explanation
This is straightforward to trigger for any `spender_attested` asset issuer/attestor relationship that is not perfectly synchronized with the sending user's status, and can be deliberately engineered by a malicious sender: send a trigger with an amount/data combination that the AA is known to reject (e.g., malformed data, insufficient balance for the request) while using an address that is not attested. No special privileges are required — this is reachable by any ordinary trigger sender.

### Recommendation
In `bounce()` (`aa_composer.js`), before attempting to refund a `spender_attested` (or otherwise restricted, e.g. `cosigned_by_definer`/`transfer_condition`) asset to `trigger.address`, verify the address satisfies the asset's transfer/attestor requirements. If it does not, skip refunding that specific asset (leaving it credited to the AA's balance for a future retry/administrative recovery, or emitting a distinguishable failure state) rather than aborting the entire response with `finish(null)`, so that at minimum the base-asset bounce and any unaffected asset refunds still succeed instead of losing the whole response unit.

### Proof of Concept
1. Issue an asset `A` with `spender_attested: true` and an attestor list controlled by an external attestor (analogous to USDC's blacklist authority) [6](#0-5) .
2. Deploy an AA whose `messages` template can bounce under some condition (e.g. insufficient trigger data, or normal `bounce_fees`-based rejection).
3. From an address `X` that is *not* on asset `A`'s attestor list, send a trigger unit to the AA that includes an output of asset `A`, along with enough base bytes to cover `bounce_fees`, and data that intentionally causes the AA logic to reject/bounce.
4. `handleTrigger` runs the AA formulas, hits an error condition, and calls `bounce(error)` [1](#0-0) ; `bounce()` builds a payment message returning asset `A` to `trigger.address` (= `X`) and calls `sendUnit(messages)`.
5. `sendUnit` → `validateAndSaveUnit` fails with `"some output addresses are not attested"` from `validatePaymentInputsAndOutputs` [3](#0-2) , causing `bounce(err)` to run a second time.
6. `bBouncing` is already `true`, so `finish(null)` is invoked [2](#0-1)  — no response unit is emitted at all.
7. Result: the asset `A` funds sent in the original trigger unit remain credited to the AA's balance permanently, with no way for the AA (or anyone) to recover or forward them, since the triggering unit has already been consumed and no retry mechanism exists.

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

**File:** aa_composer.js (L1405-1410)
```javascript
						executeStateUpdateFormula(objUnit, function (err) {
							if (err)
								return bounce(err);
							validateAndSaveUnit(objUnit, function (err) {
								if (err)
									return bounce(err);
```

**File:** validation.js (L2115-2122)
```javascript
		if (objAsset.spender_attested){
			if (conf.bLight && objAsset.is_private) // in light clients, we don't have the attestation data but if the asset is public, we trust witnesses to have checked attestations
				return callback("being light, I can't check attestations for private assets"); // TODO: request history
			if (objAsset.arrAttestedAddresses.length === 0)
				return callback("none of the authors is attested");
			if (bIssue && objAsset.arrAttestedAddresses.indexOf(issuer_address) === -1)
				return callback("issuer is not attested");
		}
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
