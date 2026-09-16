### Title
Malicious asset `transfer_condition`/`is_transferrable` can permanently freeze funds held by an AA - ([File: validation.js])

### Summary
`ocore` lets any asset issuer attach an arbitrary `transfer_condition` (or set `is_transferrable: false`) to an asset, and this condition is re-evaluated on every subsequent transfer, including transfers made *out of* an Autonomous Agent (AA) address. Since an AA's payment logic in `aa_composer.js` treats a failed asset-payment validation as a reason to `bounce()` the whole trigger response, an attacker can design an asset whose `transfer_condition` is satisfiable when depositing into an AA but never satisfiable when the AA later tries to pay it back out. Any AA that accepts "any asset" as user deposits (vaults, DEXes, bridges) can have its balance of that asset permanently stuck, and every subsequent trigger that tries to forward it will bounce, wasting bytes for the caller. This mirrors the Sherlock report's root cause (`tokenIn`/`transfer_condition` controlled entirely by an unprivileged, malicious asset creator, with no whitelist), applied to ocore's AA/asset primitives instead of Solidity `IERC20`.

### Finding Description
Asset conditions (`issue_condition`, `transfer_condition`) are ordinary user-defined spending conditions, validated only for well-formedness at asset-definition time (`validation.js` `validateAssetDefinition`, `aa_validation.js`'s `case 'asset':`) and evaluated for every payment involving that asset via `Definition.evaluateAssetCondition`: [1](#0-0) 

There is no restriction preventing such a condition from depending on properties like the payer/output addresses (`this address`/`other address` filters in `definition.js`), so a malicious asset definer can craft a condition that:
- evaluates `true` when the payer is an ordinary user address sending the asset **into** an AA (deposit), and
- evaluates `false` whenever the payer is the AA's own address (i.e., any withdrawal payment message the AA composes to send the asset back out).

When an AA later tries to forward this asset in a response (`sendUnit`), the composed payment is checked by loading the asset info and calling `completePaymentPayload`; a validation failure of the underlying payment (including a failed `transfer_condition`) is turned into a hard `cb(err)` that bounces the entire trigger response: [2](#0-1) 

`bounce()` only ever restores state/balances or reflects back a small fee based on `bounce_fees`; it does not — and cannot — force a payment message that fails asset-condition validation to succeed: [3](#0-2) 

Because the asset was already accepted into the AA's balance in an earlier stable unit (the deposit succeeded, satisfying the condition at that time), the AA's balance of the tainted asset can never be forwarded again: every attempt to pay it out is validated against the same `transfer_condition`, which is designed to fail for that direction of transfer, per: [4](#0-3) [1](#0-0) 

This is structurally analogous to the Sherlock report's root cause: an unprivileged, attacker-controlled asset definer can encode logic that behaves fine on deposit but reverts (fails validation) on withdrawal from a specific counterparty (there, the `OracleLess` contract; here, an AA address), and the victim contract/AA has no mechanism to whitelist or reject such assets before crediting balances.

### Impact Explanation
Any AA design that accepts payments in arbitrary/attacker-chosen assets (common pattern for vaults, swaps, bridges, or "deposit any token" AAs) is exposed to permanent freezing of user or protocol funds in that asset: the deposited balance can never be forwarded back to the depositor or anywhere else, because the malicious `transfer_condition` is crafted to always fail when the AA is the payer. Every subsequent trigger that tries to pay it out also fails and bounces, burning bytes each time (griefing), matching the "wastes significant gas whenever they fill or cancel orders" impact from the original report. This qualifies as AA fund freezing.

### Likelihood Explanation
Likelihood is limited by the fact that this requires (a) a victim AA that is designed to accept arbitrary assets from users and later attempt to forward them elsewhere (rather than a hardcoded whitelist of "safe" assets), and (b) the attacker deploying a purpose-built malicious asset and inducing the AA to accept a deposit of it. This is a realistic pattern for generic vault/DEX-style AAs, similar to the original `OracleLess`-style contract accepting arbitrary `tokenIn`.

### Recommendation
- AAs that accept "any asset" deposits should verify at deposit time (or before crediting balance) that the asset has no `transfer_condition`/`issue_condition` and `is_transferrable == true`, using the `asset[...]` getter fields, and reject/bounce deposits of assets that carry conditions.
- Alternatively, document and enforce (at the ocore protocol/AA-authoring level) that AAs should never blindly trust the ability to re-transfer an arbitrarily-selected asset out, since transfer conditions are fully attacker-controlled and can be direction-dependent.
- Consider adding protocol-level guidance/documentation making explicit that `transfer_condition` evaluated against `this address`/`other address` can create one-way traps for any AA counterparty, so AA authors are warned to check the asset shape before accepting deposits in it.

### Proof of Concept
1. Attacker defines an asset `readable_condition` (fixed_denominations=false, is_transferrable=true) with a `transfer_condition` referencing `this address`/`other address` filters such that it is satisfied for outputs going *to* a specific AA address `A`, but never satisfied for payments whose payer/input address *is* `A` (e.g., condition requires "has" an output/input matching a specific non-AA address pattern, which the AA will never match when it is the sole author of the payment message).
2. Attacker triggers a generic "deposit any asset" vault AA `A` by sending some amount of `readable_condition` to it. The deposit payment satisfies the condition (attacker is payer), passes `validatePaymentInputsAndOutputs` (`validation.js` lines 2643-2658), and the AA credits the balance in its state/balance tracking.
3. Attacker (or any user) later triggers `A` to withdraw/forward the `readable_condition` balance back to a user address. `A` composes a payment message with itself as payer; `Definition.evaluateAssetCondition` evaluates the crafted condition against this new payment and returns `false`.
4. `completePaymentPayload`/payment validation in `sendUnit` fails, and `aa_composer.js` calls `bounce(err)` (aa_composer.js lines 1323-1348, 909-945). The withdrawal never succeeds; the asset balance remains permanently locked in AA `A`'s balance, and every future attempt to forward it likewise bounces, burning bytes for callers.

**Uncertainty note**: I was unable to fully trace whether ocore's `evaluateAssetCondition`/`Definition.js` filter semantics for `this address`/`other address` in a *transfer* (non-issue) condition specifically allow discriminating "payer is the AA" vs "payer is a normal user" with full generality (I confirmed `this address`/`other address` are valid in non-asset-defining-itself conditions per `definition.js` lines 31-119, but did not trace every edge case of `getFilterError`/`evaluate` for all filter types). A Devin session with the ability to run the ocore test suite and construct a concrete asset condition + AA definition would be needed to confirm the exact crafted condition compiles and behaves as described.

### Citations

**File:** validation.js (L2616-2629)
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

**File:** aa_composer.js (L1323-1348)
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
			},
			function (err) {
				if (err)
					return bounce(err);
```
