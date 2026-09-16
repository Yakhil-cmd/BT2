### Title
AA-held funds in a `spender_attested` asset can be permanently frozen if the recipient loses/never gets attestation - (File: aa_composer.js)

### Summary
The JOJO report describes a liquidation flow that pushes a mandatory refund transfer to a fixed recipient address; if that address is on USDC's blocklist, the transfer (and the whole liquidation) reverts, permanently preventing debt resolution. The analogous root cause in `ocore` is the Autonomous Agent (AA) payment-sending logic, which composes payments to arbitrary output addresses without verifying that those addresses satisfy asset-level authorization rules (e.g., `spender_attested`), relying instead on unit validation to reject the built unit and trigger a `bounce()`. Because `bounce()` only refunds the *triggering* unit's own outputs and does not return other assets that were already held in the AA's balance, an address that can never satisfy the attestation requirement (analogous to being "blocklisted") can permanently block the AA from paying out that asset to it, freezing the funds inside the AA.

### Finding Description
When an AA sends a `payment` message for a non-base asset, `sendUnit()` only loads the asset info for the AA's own address to decide whether to skip fixed-denomination assets or refuse private assets — it never checks whether the recipient output addresses satisfy the asset's authorization conditions such as `spender_attested`: [1](#0-0) 

The resulting unit is only checked for attestation compliance later, during full unit validation, in `validatePaymentInputsAndOutputs`, which rejects the payment if not all output addresses are attested for a `spender_attested` asset: [2](#0-1) 

If that validation fails, `validateAndSaveUnit` returns an error and the AA falls back to `bounce(err)`, which discards the constructed state update and response: [3](#0-2) 

Critically, `bounce()` only returns the *trigger's own outputs* (minus bounce fees) back to `trigger.address` — it does not, and cannot, return other asset balances that the AA is holding on behalf of a user from prior interactions: [4](#0-3) 

So if an AA's business logic (e.g., an escrow, vault, or lending-style AA) is coded to eventually pay out a `spender_attested` asset to a specific address (the original depositor/counterparty), and that address's attestor revokes or never grants attestation for it (the functional equivalent of USDC's admin-controlled blocklist, since attestor lists are managed by trusted third parties per `storage.filterAttestedAddresses`), every attempt to execute that payout will validate-fail and bounce, reverting the state change each time. The asset balance remains stuck inside the AA indefinitely with no pull-based recovery path, since the AA logic keeps attempting the same push-payment on every subsequent trigger.

### Impact Explanation
This blocks the AA from ever completing an intended payout to a specific address, exactly mirroring the "prevents full liquidation/settlement, causing frozen funds" impact of the original report. Funds legitimately owed to a user become permanently locked inside the AA (an AA fund-freezing scenario), and the AA operator/depositor has no alternative retrieval mechanism unless the oscript author anticipated this and coded a fallback recipient or pull-based withdrawal. This is a Medium-severity availability/fund-freezing issue reachable purely by an ordinary AA trigger sender interacting with an asset whose `spender_attested` flag is controlled by third-party attestors.

### Likelihood Explanation
Likelihood is moderate: it requires (1) an AA designed to pay a `spender_attested` (or otherwise conditionally-transferable, e.g. `transfer_condition`/`is_transferrable`) asset to a stored counterparty address, and (2) that counterparty later failing the condition (attestor revocation, or the condition formula evaluating false for reasons outside the AA's control). Given attestation/authorization state can change over time and is fully out of the AA's control, this is a realistic occurrence for AAs that hold third-party-issued restricted assets on behalf of users.

### Recommendation
AA developers should validate authorization conditions (attestation status, transfer conditions) of `payment` outputs before committing to send, and design fallback/pull-based withdrawal patterns instead of assuming a push payment to a fixed address will always succeed. At the protocol level, consider exposing to oscript authors a way to query `spender_attested`/`transfer_condition` status of an output address in advance (similar to `asset[...]` getters), so contracts can branch to an alternative recovery path (e.g., let the user pull funds via a separate address) rather than relying on `bounce()`, which is state-losing and cannot rescue non-trigger balances.

### Proof of Concept
1. Define asset `X` with `spender_attested: true` and attestor list `A`.
2. Deploy an AA that, upon trigger `withdraw`, sends `var['balance'][trigger.address]` of asset `X` back to `trigger.address` (a typical vault/escrow pattern), e.g. following the payment-composition path shown in `aa_composer.js` `sendUnit()`.
3. User `U` deposits asset `X` into the AA when still attested by `A`; balance recorded in AA state.
4. Attestor `A` revokes/never renews attestation for `U`.
5. `U` triggers `withdraw`; `sendUnit()` composes the payment without checking `U`'s attestation, `validatePaymentInputsAndOutputs` rejects the unit (`"some output addresses are not attested"`), and `bounce()` is invoked, reverting the state update — `U`'s balance of `X` is restored in state but can never actually be sent out because every future retry fails identically, permanently freezing it in the AA.

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

**File:** aa_composer.js (L1323-1344)
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
