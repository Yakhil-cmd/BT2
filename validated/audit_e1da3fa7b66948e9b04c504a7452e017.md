I have enough evidence to finalize the analog.

### Title
Single unattested recipient in a `spender_attested` asset payout DoS-freezes an entire AA payment batch to all other legitimate recipients - (File: validation.js, aa_composer.js)

### Summary
An asset can be defined with `spender_attested: true`, requiring **every** output address of a payment message in that asset to be attested before the payment validates. When an Autonomous Agent (AA) batches a `spender_attested` asset distribution to several recipients inside a single `payment` message (a common gas/fee-saving pattern), validation fails entirely if even a single recipient address is not attested. The failure is an all-or-nothing check over the whole `arrOutputAddresses` array, so one uncooperative or unattested recipient can permanently block the payout to every other, legitimate recipient bundled in the same AA response, mirroring the reported PoolTogether pattern where one blacklisted `recipient` blocks a shared reward-distribution transaction for everyone.

### Finding Description
`validatePaymentInputsAndOutputs()` checks attestation status for `spender_attested` assets by verifying that *all* addresses in `payload.outputs` are attested, failing the whole payment (and thus the whole unit) if any single one is not: [1](#0-0) 

This check runs against `arrOutputAddresses`, the deduplicated set of every recipient address that appears in the payment's `outputs` array, built earlier in the same function: [2](#0-1) 

An AA can naturally construct a `payment` message with an arbitrary list of output addresses, e.g. a reward/dividend distribution to a set of asset holders. During AA execution, `aa_composer.js`'s `sendUnit()` collects `addOutputAddresses(payload.outputs)` from the AA-generated messages and eventually calls `validateAndSaveUnit(objUnit, ...)`; if that validation fails, the composer unconditionally calls `bounce(err)`, discarding the entire response (including bounce-fee refunds and all the intended payouts) for the whole trigger: [3](#0-2) 

Because `bounce()` discards `objStateUpdate`, restores balances, and (for a primary trigger) either sends nothing back or only refunds the trigger's own bounce fee, none of the intended payments in the batched message reach any recipient — including the honest ones that were correctly attested: [4](#0-3) 

An address's attestation status is fully within that address owner's control in practice: an attacker only needs to never seek/complete attestation (the default state of any address) to remain permanently unattested — functionally equivalent to "entering a blacklist" in the original report, except here it requires no cooperation from any third party (like Circle for USDC) at all; simply not obtaining attestation is sufficient.

### Impact Explanation
Any AA (or user-composed transaction) that pays a `spender_attested` asset to multiple recipients in one atomic payment message can be permanently DoS'd by including (or being tricked into paying) a single unattested address in the recipient set. This causes:
- Loss/freezing of funds intended for all other, legitimate recipients bundled in the same distribution, since the entire unit fails validation and the AA bounces, discarding the payout attempt.
- If the AA logic is deterministic and retries the same batch (e.g., a recurring dividend/reward AA that iterates over the same list of holders), the DoS becomes persistent and permanently freezes distributions to the whole cohort until the AA's logic is redesigned to exclude the bad address, which typically requires an entirely new AA deployment since AA code is immutable.

This matches the "AA fund loss or freezing" impact class from a single malicious/uncooperative counterparty affecting other honest parties who have no way to remedy the situation themselves.

### Likelihood Explanation
Reaching this requires only: (1) an asset issuer to define a `spender_attested: true` asset (common for compliance/KYC-gated tokens) and (2) an AA (or transaction author) built to distribute that asset to a batch of addresses in a single `payment` message rather than issuing one message per recipient. Both are ordinary, expected usage patterns supported directly by ocore/oscript; no protocol-level bug or race condition is needed, only a single unattested address showing up among the intended batch recipients, which is trivial for an attacker to arrange for themselves.

### Recommendation
- Avoid batching `spender_attested` asset payouts to multiple independent recipients within a single payment message when partial failure isolation matters; validate/attest recipients individually, or split multi-recipient distributions into independent per-recipient messages/units so that one recipient's attestation failure cannot block the rest.
- Alternatively/additionally, consider changing `validatePaymentInputsAndOutputs` to only require attestation for actually-relevant "new" recipients (excluding those that also appear as input owners, similar to the existing `is_transferrable` self-payment carve-out) so a single bad address cannot invalidate an entire batched unit; or expose to AA authors a pre-check `getter`/`bounce()`-friendly way to filter out unattested addresses from a candidate distribution list before constructing the payment.

### Proof of Concept
1. Definer creates asset `A` with `spender_attested: true` and an attestor list, per `validateAssetDefinition` in `validation.js`.
2. Deploy an AA whose response logic builds a single `payment` message for asset `A` with `outputs` containing N holder addresses (e.g., a dividend-style AA that reads `var[...]` state to determine payout list).
3. Attacker (or any user) never requests attestation for their address, and either becomes a legitimate holder entitled to a distribution, or gets themselves included as a spurious output target if the AA logic is influenced by trigger data.
4. When the AA response is composed, `aa_composer.js`'s `sendUnit()` reaches `validateAndSaveUnit`, which calls into `validatePaymentInputsAndOutputs`; because `arrAttestedOutputAddresses.length !== arrOutputAddresses.length` (the attacker's address is unattested), the payment message — and therefore the entire response unit — fails validation with `"some output addresses are not attested"`.
5. `aa_composer.js` calls `bounce(err)`, discarding the whole distribution: no address in the batch (attested or not) receives their share, and if the AA is re-triggered with the same recipient list, the failure recurs indefinitely. [1](#0-0) [3](#0-2)

### Citations

**File:** validation.js (L2151-2194)
```javascript
	for (var i=0; i<payload.outputs.length; i++){
		var output = payload.outputs[i];
		if (!isNonemptyObject(output))
			return callback("output must be a non-empty object");
		if (hasFieldsExcept(output, ["address", "amount", "blinding", "output_hash"]))
			return callback("unknown fields in payment output");
		if (!isPositiveInteger(output.amount))
			return callback("amount must be positive integer, found "+JSON.stringify(output.amount));
		if (output.amount > constants.MAX_CAP)
			return callback("output too large: " + output.amount);
		if (objAsset && objAsset.fixed_denominations && output.amount % denomination !== 0)
			return callback("output amount must be divisible by denomination");
		if (objAsset && objAsset.is_private){
			if (("output_hash" in output) !== !!objAsset.fixed_denominations)
				return callback("output_hash must be present with fixed denominations only");
			if ("output_hash" in output && !isStringOfLength(output.output_hash, constants.HASH_LENGTH))
				return callback("invalid output hash");
			if (!objAsset.fixed_denominations && !(("blinding" in output) && ("address" in output)))
				return callback("no blinding or address");
			if ("blinding" in output && !isStringOfLength(output.blinding, 16))
				return callback("bad blinding");
			if (("blinding" in output) !== ("address" in output))
				return callback("address and blinding must come together");
			if ("address" in output && !isValidAddressWithCase(output.address))
				return callback("output address " + JSON.stringify(output.address) + " invalid");
			if (output.address)
				count_open_outputs++;
		}
		else{
			if ("blinding" in output)
				return callback("public output must not have blinding");
			if ("output_hash" in output)
				return callback("public output must not have output_hash");
			if (!isValidAddressWithCase(output.address))
				return callback("output address " + JSON.stringify(output.address) + " invalid");
			if (prev_address > output.address)
				return callback("output addresses not sorted");
			else if (prev_address === output.address && prev_amount > output.amount)
				return callback("output amounts for same address not sorted");
			prev_address = output.address;
			prev_amount = output.amount;
		}
		if (output.address && arrOutputAddresses.indexOf(output.address) === -1)
			arrOutputAddresses.push(output.address);
```

**File:** validation.js (L2630-2642)
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
```

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
