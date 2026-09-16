### Title
Malicious/restrictive asset conditions in a combined payment response can permanently bounce and freeze AA-held user funds - (File: aa_composer.js, validation.js)

### Summary
Autonomous Agents (AAs) frequently compose a single response unit containing several `payment` messages for different assets in one atomic transaction (e.g. returning a user's principal plus a separate reward/share asset). Because ocore validates and either accepts or rejects the whole response unit as one atomic object, a single toxic asset condition attached to just one of the payment messages causes the entire unit — including the unrelated, otherwise-valid principal payment — to be rejected and the AA to bounce, with no partial-success or "skip-this-transfer" fallback available to the AA author.

### Finding Description
When an AA finishes evaluating its formulas, it hands the composed `messages` array to `sendUnit()`, which builds one `objUnit` containing all payment messages and validates it as a whole via `validateAndSaveUnit`. If validation fails for any reason, the response is rejected wholesale via `bounce(err)`:

<cite repo="Jortegata/ocore--020" path="aa_composer.js" start="1403="/> [1](#0-0) 

`bounce()` discards the just-computed state update and, if the trigger has enough bytes to cover bounce fees, only refunds the trigger's own coins minus the bounce fee — it does not selectively drop the failing message and keep the rest: [2](#0-1) 

The per-message validation that can fail is `validatePayment`/`validatePaymentInputsAndOutputs` in `validation.js`, which enforces asset-level restrictions such as `spender_attested` and `transfer_condition`/`issue_condition` that are fully controlled by whoever defined the asset: [3](#0-2) [4](#0-3) 

Many real AA templates in this codebase compose a single set of messages that pays out multiple assets together in one response — for example, the "divest MM shares" case of the Uniswap-like market maker sends an asset payment and a base-byte payment in the same `messages` array: [5](#0-4) 

and generic bank/exchange templates accept an arbitrary asset chosen by the depositor and later pay it back out together with state accounting, without any way to verify in advance that the asset's transfer conditions will still be satisfiable: [6](#0-5) 

If the "reward"/secondary asset bundled into a payout is defined (by the AA operator, or by an unprivileged asset issuer whose asset gets adopted by a permissionless pool-style AA) with a `transfer_condition` that is impossible to satisfy for ordinary recipients, or `spender_attested: true` with attestors who will never attest the withdrawing address, then every attempt by the AA to combine that asset's payout with the user's principal payout will fail `validatePaymentInputsAndOutputs` and cause `bounce()` on the *entire* unit. Because oscript has no primitive to catch this failure and selectively omit only the toxic payment message, the AA has no way to still release the principal — the user's funds recorded in AA balance/state remain permanently unreachable through normal withdrawal flow, exactly mirroring the "malicious reward token disables withdrawals" bug class from the reference report.

### Impact Explanation
This causes permanent freezing of user funds inside an AA: any legitimate value (base bytes or another well-behaved asset) bundled in the same response as a toxic/restricted asset becomes unwithdrawable, because a single failed sub-payment always aborts the whole unit rather than only the offending transfer. This is a fund-freezing vulnerability reachable by an unprivileged asset issuer (or AA operator) who controls the conditions of one of the assets an AA pays out, with no built-in emergency/partial-withdraw mechanism in the protocol to work around it.

### Likelihood Explanation
Bundling multiple asset payments in a single AA response is a common, encouraged oscript pattern (seen directly in the shipped templates such as `uniswap_like_market_maker.oscript`). Any AA (including permissionless pool-like AAs pairing user deposits with an operator-chosen or user-chosen reward asset) that pays out more than one asset atomically is exposed if it does not defensively guarantee the secondary asset has benign, universally-satisfiable transfer/issue conditions and no `spender_attested` restriction — a guarantee the base protocol does nothing to enforce or allow the AA to probe/skip around.

### Recommendation
- Provide AA authors an oscript-level construct (analogous to a "best-effort"/optional payment message) that lets a failed sub-payment be dropped from the composed unit instead of forcing a full bounce of otherwise-valid messages, or
- Document and strongly warn AA template authors never to bundle a payout of an externally-controlled/asset-issuer-controlled token together with user principal in the same atomic response, and provide a documented "retry-only-safe-assets" pattern (e.g., split principal and reward payouts into separate secondary-trigger-driven response units so a toxic reward asset's failure only bounces its own leg, not the principal).
- Consider allowing an AA to pre-check, via a getter/formula, whether a target address is currently able to receive a given restricted asset (e.g. exposing `spender_attested` status or evaluating `transfer_condition` at oscript level) so the AA logic itself can branch and pay only assets that are known to be deliverable.

### Proof of Concept
1. Deploy (or reuse) an AA modeled on `uniswap_like_market_maker.oscript`'s "divest" case, which on a qualifying trigger sends two payment messages in the same response: `{asset: $asset, ...}` and `{asset: 'base', ...}` (see `test/samples/uniswap_like_market_maker.oscript` lines 67–93).
2. The `$asset` used is defined (by the AA operator or an asset issuer whose asset the AA adopts) with `spender_attested: true` and an attestor list that will never attest ordinary user addresses, or with a `transfer_condition` requiring a signature the depositor cannot produce (both fields are fully attacker/issuer controlled per `aa_validation.js` lines 289–335 and enforced in `validation.js` lines 2115–2122, 2630–2659).
3. A user deposits base bytes and receives share-asset credit in AA state as usual.
4. When the user triggers "divest," `sendUnit()` composes the unit containing both the base-byte payout and the restricted-asset payout; `validatePaymentInputsAndOutputs` rejects the restricted-asset message (`"transfer or issue condition not satisfied"` or `"some output addresses are not attested"`).
5. `validateAndSaveUnit` returns an error, `sendUnit`'s callback calls `bounce(err)` (`aa_composer.js` lines 1408–1411, 909–945), discarding the whole response — the user's base-byte principal is never paid out and remains stuck in the AA's balance, reproducing the "malicious reward token disables withdrawal" condition from the referenced report.

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

**File:** aa_composer.js (L1403-1411)
```javascript
						objUnit.unit = objectHash.getUnitHash(objUnit);
						console.log('unit', util.inspect(objUnit, { depth: 6 }))
						executeStateUpdateFormula(objUnit, function (err) {
							if (err)
								return bounce(err);
							validateAndSaveUnit(objUnit, function (err) {
								if (err)
									return bounce(err);
								updateFinalAABalances(arrConsumedOutputs, objUnit, function () {
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

**File:** validation.js (L2630-2659)
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

**File:** test/samples/uniswap_like_market_maker.oscript (L67-93)
```text
			{ // divest MM shares 
				// (user is already paying 10000 bytes bounce fee which is a divest fee)
				// the price slightly moves due to fees received and paid in bytes
				if: `{$mm_asset AND trigger.output[[asset=$mm_asset]]}`,
				init: `{
					$mm_asset_amount = trigger.output[[asset=$mm_asset]];
					$investor_share = $mm_asset_amount / var['mm_asset_outstanding'];
				}`,
				messages: [
					{
						app: 'payment',
						payload: {
							asset: "{$asset}",
							outputs: [
								{address: "{trigger.address}", amount: "{ round($investor_share * balance[$asset]) }"}
							]
						}
					},
					{
						app: 'payment',
						payload: {
							asset: "base",
							outputs: [
								{address: "{trigger.address}", amount: "{ round($investor_share * balance[base]) }"}
							]
						}
					},
```

**File:** test/samples/a_bank_without_percent.oscript (L1-30)
```text
{
	messages: {
		cases: [
			{ // withdraw funds
				if: `{
					$key = 'balance_'||trigger.address||'_'||trigger.data.asset;
					$base_key = 'balance_'||trigger.address||'_'||'base';
					$fee = 1000;
					$required_amount = trigger.data.amount + ((trigger.data.asset == 'base') ? $fee : 0);
					trigger.data.withdraw AND trigger.data.asset AND trigger.data.amount AND $required_amount <= var[$key] AND $fee <= var[$base_key]
				}`,
				messages: [
					{
						app: 'payment',
						payload: {
							asset: "{trigger.data.asset}",
							outputs: [
								{address: "{trigger.address}", amount: "{trigger.data.amount}"}
							]
						}
					},
					{
						app: 'state',
						state: `{
							var[$key] = var[$key] - trigger.data.amount;
							var[$base_key] = var[$base_key] - $fee;
						}`
					}
				]
			},
```
