I have enough evidence now to construct the analog. Key mechanism confirmed:

- `updateInitialAABalances` in `aa_composer.js` credits an AA's `aa_balances` for **any** asset sent to it in a trigger, with no whitelist or validation of the asset's properties. [1](#0-0) 
- When the AA later tries to pay out a held asset via a `payment` message, `sendUnit()` only special-cases `fixed_denominations` (silently dropped) and `is_private` (bounced), but does **not** check `is_transferrable` or `transfer_condition` before building the outgoing payment. [2](#0-1) 
- The actual enforcement of `is_transferrable` and `transfer_condition` happens only later, deep inside `validateAndSaveUnit` → `validatePaymentInputsAndOutputs`, which rejects the payment if the condition isn't satisfied for the resulting outputs. [3](#0-2) 
- If that validation fails, the whole AA response unit is discarded and `bounce(err)` is invoked, which reverts **all** balance/state changes for the entire trigger (not just the offending asset payment). [4](#0-3) [5](#0-4) 

### Title
Malicious asset with an unsatisfiable `transfer_condition`/`is_transferrable` freezes AA balances and blocks all-or-nothing payouts - (File: aa_composer.js)

### Summary
An unprivileged user can send an arbitrary custom asset (defined via a normal `asset` message, with any `transfer_condition` or `is_transferrable=false`) as part of a trigger's outputs to any Autonomous Agent (AA). The AA composer credits this asset to the AA's balance unconditionally, with no filtering of asset properties. If the AA's oscript logic is later triggered to pay out this balance together with other assets/bytes in a single response unit (a common oscript pattern for bounty/prize/escrow-style AAs that "send everything to the winner" in one atomic payment), the entire response unit fails validation and bounces, discarding the state update that would mark the payout complete.

### Finding Description
`updateInitialAABalances` adds every asset received in `trigger.outputs` to `aa_balances` without checking the asset's `is_transferrable`, `cosigned_by_definer`, or `transfer_condition` fields. [6](#0-5) 

Later, when the AA's oscript composes a payment message spending this balance, `sendUnit()` only pre-filters `fixed_denominations` (dropped silently) and `is_private` (explicit bounce), leaving `is_transferrable=false` and arbitrary `transfer_condition` formulas unchecked at composition time. [7](#0-6) 

The actual condition check happens only when the generated unit is validated via `validateAndSaveUnit` → `validatePaymentInputsAndOutputs`, where a non-transferrable asset payment to any address other than the definer, or a `transfer_condition` formula crafted by the attacker (definer of the malicious asset) to evaluate to false for any output address except the attacker's own, causes validation to fail. [8](#0-7) 

Because the AA composer builds one unit per trigger response containing all queued `payment` messages together (base bytes plus every asset), a validation failure anywhere in that unit causes `bounce(err)`, which restores original balances/state vars and aborts the whole response — none of the other (legitimate) asset transfers or state changes in that response go through either. [9](#0-8) [10](#0-9) 

If the oscript's payout logic is written such that a subsequent trigger recomputes the same output list (e.g., "pay winner all held assets" gated by a state var that is only updated once the send succeeds), every retry hits the same unsatisfiable condition and bounces identically, permanently blocking the AA from ever completing that payout — freezing not only the malicious asset but also any bytes/legitimate assets bundled in the same payment logic.

### Impact Explanation
An attacker can grief any AA that (a) accepts arbitrary assets from triggers without whitelisting, and (b) later batches a payout of its full balance (or a specific set of assets determined by trigger data) to a recipient in one unit. By sending a crafted asset with a `transfer_condition` that is unsatisfiable for the intended recipient (or `is_transferrable=false`), the attacker can cause every future payout attempt referencing that balance to bounce, permanently freezing bytes and other legitimate assets held by the AA for the affected recipient/state path. This is a fund-freezing/DoS impact on AA-held funds, analogous to the reported ERC20 "poison token" DoS against bounty payouts.

### Likelihood Explanation
Likelihood is moderate to high for AAs whose logic doesn't explicitly whitelist accepted asset addresses or filter `is_transferrable`/`transfer_condition` before including them in payout batches — a common oscript pattern for pools, bounties, escrows and games. Defining a custom asset and sending it to an AA are both unprivileged actions available to any user, and asset property manipulation (`transfer_condition`) is a fully user-controlled formula.

### Recommendation
- When an AA logic composes payout messages, or in the AA composer itself, validate that any non-`base` asset being paid out is `is_transferrable`, has no `cosigned_by_definer` requirement unmet, and has either no `transfer_condition` or one that can be generically satisfied for arbitrary recipients, before bundling it with other messages in the same response unit.
- Encourage/require oscript authors to isolate risky, attacker-controlled asset payouts into separate response units (secondary triggers) so a single malicious asset cannot block unrelated bytes/asset transfers in the same trigger.
- Consider extending `sendUnit()`'s asset pre-filtering (currently only `fixed_denominations` and `is_private`) to also drop or isolate assets with `is_transferrable=false` or a `transfer_condition`, mirroring the existing filtering pattern at [11](#0-10) .

### Proof of Concept
1. Attacker defines a malicious asset `M` with `is_transferrable: false, cosigned_by_definer: false, transfer_condition: ["and", cases such that the condition only ever holds for outputs to attacker's own address]`.
2. Attacker sends unit(s) with `M` as part of `trigger.outputs` to a victim AA that accepts arbitrary assets into its balance (per `updateInitialAABalances`).
3. Attacker (or any user) triggers the AA's payout logic, which composes a response unit containing a payment of `M` (plus bytes/other assets) to the intended recipient.
4. `validatePaymentInputsAndOutputs` rejects the `M` payment because `is_transferrable` is false and the condition/definer rules aren't met for that recipient. [12](#0-11) 
5. `sendUnit()`'s `validateAndSaveUnit` call fails, triggering `bounce(err)`, which reverts state/balance changes for the whole response, leaving the AA unable to ever complete that payout. [4](#0-3)

### Citations

**File:** aa_composer.js (L474-490)
```javascript
	// add the coins received in the trigger
	function updateInitialAABalances(cb) {
		let bOverflow = false;
		if (trigger_opts.assocBalances) {
			if (!trigger_opts.assocBalances[address])
				trigger_opts.assocBalances[address] = {};
			originalBalances = _.cloneDeep(trigger_opts.assocBalances);
			for (var asset in trigger.outputs) {
				trigger_opts.assocBalances[address][asset] = (trigger_opts.assocBalances[address][asset] || 0) + trigger.outputs[asset];
				if (trigger_opts.assocBalances[address][asset] > MAX_BALANCE)
					bOverflow = true;
			}
			objValidationState.assocBalances = trigger_opts.assocBalances;
			byte_balance = trigger_opts.assocBalances[address].base || 0;
			storage_size = 0;
			return cb(bOverflow && mci >= constants.pemCurvesFixMci ? "balance overflow" : null);
		}
```

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

**File:** aa_composer.js (L1405-1420)
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
												return revert(err);
											handleSecondaryTriggers(objUnit, arrOutputAddresses);
										});
```

**File:** validation.js (L2613-2659)
```javascript
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
