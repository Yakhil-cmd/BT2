### Title
AA payments to a recipient blocked by an asset's `transfer_condition`/`spender_attested` check permanently bounce, freezing funds and reverting release-state changes - (File: aa_composer.js)

### Summary
Autonomous Agents (AAs) that release a stored asset balance to a fixed party (e.g. a payment channel, escrow, or vesting AA) build their payout message with `app: 'payment'` and rely on the underlying unit passing full validation, including any `transfer_condition`/`spender_attested` restriction defined on the asset. If the payee address later fails that condition (the practical analog of an ERC-20 “blocklist”), unit validation/save fails, the AA composer calls `bounce()`, and **all state changes for that trigger — including the “release/close” flag that was supposed to mark the payout as done — are rolled back**. Because the AA’s payout logic is driven purely by that same state, every subsequent trigger reproduces the identical failing payment and bounces again, permanently locking the asset inside the AA with no path to recovery, exactly mirroring the reNFT bug where a blocklisted recipient causes `_safeTransfer()` to revert and strands the NFT/payment.

### Finding Description
When an AA builds its response unit, non-base-asset payment outputs are completed via `storage.loadAssetWithListOfAttestedAuthors` and `completePaymentPayload`, and the resulting unit is passed to `validateAndSaveUnit`; if this fails, `bounce(err)` is invoked [1](#0-0) . `bounce()` explicitly restores `stateVars`/balances to their pre-trigger values (`originalStateVars`, `originalBalances`) and refunds bounce fees, i.e. it fully undoes any state update the AA had queued [2](#0-1) . The final unit is only committed after `executeStateUpdateFormula`, `validateAndSaveUnit`, and `updateFinalAABalances` all succeed [3](#0-2) .

At the protocol layer, a divisible/indivisible asset payment output is checked against `spender_attested` (all outputs must be attested addresses) and against `transfer_condition`/`issue_condition` via `Definition.evaluateAssetCondition`; either check can fail and reject the whole unit [4](#0-3) . These conditions are asset-issuer-controlled analogs of an ERC-20 blocklist: an attestor can stop attesting an address, or a `transfer_condition` (an arbitrary boolean expression evaluated over addresses/outputs, defined in `definition.js`) can begin excluding a specific address at any time after the AA has already committed to eventually paying that address.

A concrete pattern that hits this is the payment-channel style AA (`test/samples/payment_channels.oscript`), where the closing logic always pays `$addressA`/`$addressB` fixed at channel-open time and finalizes closure only together with the payment message in the same set of `messages` [5](#0-4) . If the asset being used in the channel enforces `spender_attested` or a `transfer_condition` and one of the two channel parties is later blocked by the attestor/condition, `sendUnit` will build the payment, `validateAndSaveUnit` will fail on the attestation/condition check, `bounce()` will be triggered, the `close_initiated_by`/`period`/balance state will be restored to “still open”, and no alternate un-conditioned withdrawal path exists — every future close attempt reproduces the same failure indefinitely.

### Impact Explanation
Any unprivileged asset issuer (attestor) or transfer-condition author can, after the fact, deny a specific address the ability to be paid by an AA that already holds funds earmarked for it. Because AA state changes are atomic with the response unit (bounce fully reverts them), this is not a temporary delay — the AA has no mechanism analogous to “claim later” or a non-reverting transfer; the funds are stuck in the AA’s balance permanently, and the counterparty’s NFT/asset-equivalent (the state that would let them exit the channel/escrow) never advances. This matches the report’s “Medium” findings (loss of counterparty funds/asset, no recovery without a protocol upgrade) rather than an unauthorized-spend bug.

### Likelihood Explanation
Requires the AA to pay out an asset that has `spender_attested` or `transfer_condition` restrictions (issuer-controlled), and the payee address to lose eligibility after the AA already committed to it (analogous to becoming blocklisted). This is plausible for any AA-based DeFi construct (payment channels, escrows, vesting contracts) built on top of a permissioned/attested asset, and requires no special privilege from the party triggering the failing payout — a normal `close`/settlement trigger from either channel party is enough to demonstrate the stuck state.

### Recommendation
- Avoid coupling irreversible state finalization (e.g., `close_initiated_by`, balance zeroing) with the payment message in a single all-or-nothing unit when the asset can carry issuer-defined transfer restrictions; instead separate "mark settled" from "send funds" so a failed transfer doesn't roll back the settlement record.
- Where feasible, allow AA authors to add a fallback payout address/branch (e.g., pay to `this_address`-controlled escrow output redeemable later, or allow either party to redirect payment to an alternate whitelisted address) so a condition/attestation failure does not permanently lock funds.
- Document to AA/oscript authors that using assets with `transfer_condition`/`spender_attested` for one-shot payout logic in AAs risks permanent fund lock if the condition changes between commitment and execution, given `bounce()`'s full state/balance rollback behavior [2](#0-1) .

### Proof of Concept
Conceptual reproduction (would require constructing an actual asset + AA test, which was not executed here):
1. Define an asset with `spender_attested: true` and an attestor address `X`.
2. Deploy an AA analogous to `payment_channels.oscript` that, on a `close`/`confirm` trigger, pays the channel counterparty from AA balance and simultaneously updates `var['close_initiated_by']`/balances to mark the channel closed [6](#0-5) .
3. Fund the AA with the asset and open/initiate closing the channel normally.
4. Have attestor `X` stop attesting the counterparty's address before the `confirm` trigger is posted.
5. Post the `confirm` trigger: `validatePaymentInputsAndOutputs` rejects the output because the address is no longer attested [7](#0-6) , causing `bounce()` to revert `close_initiated_by`/balance state [2](#0-1) ; the channel remains permanently open and the asset balance permanently stuck in the AA, since every future `confirm` trigger produces the identical failing output.

### Citations

**File:** aa_composer.js (L909-925)
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

**File:** aa_composer.js (L1405-1417)
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
									fixStateVars();
									addResponse(objUnit, function () {
										updateStorageSize(function (err) {
											if (err)
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

**File:** test/samples/payment_channels.oscript (L68-101)
```text
			{ // confirm closure
				if: `{ trigger.data.confirm AND var['close_initiated_by'] }`,
				init: `{
					if (!($bFromParties AND var['close_initiated_by'] != $party OR timestamp > var['close_start_ts'] + $close_timeout))
						bounce('too early');
					$finalBalanceA = var['balanceA'] - var['spentByA'] + var['spentByB'];
					$finalBalanceB = var['balanceB'] - var['spentByB'] + var['spentByA'];
				}`,
				messages: [
					{
						app: 'payment',
						payload: {
							asset: 'base',
							outputs: [
								// fees are paid by the larger party, its output is send-all
								// this party also collects the accumulated 10Kb bounce fees
								{ address: '{$addressA}', amount: "{ $finalBalanceA < $finalBalanceB ? $finalBalanceA : '' }" },
								{ address: '{$addressB}', amount: "{ $finalBalanceA >= $finalBalanceB ? $finalBalanceB : '' }" }
							]
						}
					},
					{
						app: 'state',
						state: `{
							var['period'] += 1;
							var['close_initiated_by'] = false;
							var['close_start_ts'] = false;
							var['balanceA'] = false;
							var['balanceB'] = false;
							var['spentByA'] = false;
							var['spentByB'] = false;
						}`
					}
				]
```
