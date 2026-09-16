This ocore codebase doesn't have ERC20 tokens with pause/blacklist mechanisms, but it has a structurally identical bug class: **an AA response that bundles a core state change together with a payment of a condition-gated asset (spender-attested, oracle-gated `transfer_condition`) is atomically bounced in full if that asset payment fails, even though the failure has nothing to do with the AA's own logic.**

### Title
AA responses bundling core logic with condition-gated asset payments are entirely bounced (reverting all state changes) when the asset's `spender_attested`/`transfer_condition` check fails - (File: aa_composer.js, validation.js)

### Summary
When an Autonomous Agent (AA) composes a response unit containing multiple messages (e.g. a `state` update plus one or more `payment` messages), the whole unit is validated as a single atomic transaction via `validateAndSaveUnit`. If validation fails for **any** payment message — for instance because the asset being paid out is `spender_attested` and the recipient/trigger address is not (yet) attested, or because its `transfer_condition`/`issue_condition` (which can reference an oracle `data feed`) is not satisfied — the entire response is bounced and **all** state/balance changes performed by the AA in that response are rolled back, not just the failing payment.

### Finding Description
`sendUnit()` builds one combined `objUnit` from all of the AA's response messages and only then calls `validateAndSaveUnit`; if that call errors, `bounce(err)` is invoked: [1](#0-0) 

`bounce()` unconditionally undoes all state variable and balance changes accumulated during the trigger handling: [2](#0-1) 

The validator that can trigger this failure lives in `validatePaymentInputsAndOutputs`. For assets marked `spender_attested`, every output address must be attested by one of the asset's attestors, and any configured `transfer_condition`/`issue_condition` (which can itself depend on `in data feed`, i.e. an oracle) must independently evaluate to true: [3](#0-2) 

The `in data feed` condition evaluator shows that transfer/issue conditions can be made contingent on external oracle-posted values, which are outside the AA author's and the trigger sender's control: [4](#0-3) 

So, analogous to the reported `SecondaryRewarder` pattern (an immediate, unconditional `transfer()` to a possibly-blacklisted/paused ERC20 blocking unrelated nToken operations), here an AA that couples its main business logic (state updates, base-asset payments) with a payment of a "controlled" asset (spender-attested or oracle-gated) in the *same* response will have its entire operation bounced whenever that side payment's condition isn't currently satisfied — even though the core logic itself was perfectly valid.

### Impact Explanation
Any AA design that pairs core state transitions with a payment of a restricted/attested/oracle-gated asset in one response is fragile: a third party (attestor going offline, oracle not yet posting an updated value, recipient losing attestation) can cause legitimate, unrelated AA operations (e.g., mint/burn/state bookkeeping) to be undone via bounce, denying service to users interacting with the AA. Because `bounce()` reverts balances and state vars restored from `originalStateVars`/`originalBalances`, users lose the intended effect of their trigger (their bytes are typically returned minus `bounce_fees`), so it's primarily a griefing/liveness (freezing of AA funds/functionality) issue rather than a direct fund-theft bug, matching the "Medium" severity class of the source report (blocking of core operations due to an out-of-band, uncontrollable condition on a coupled payment).

### Likelihood Explanation
This requires an AA design that intentionally issues or forwards a `spender_attested` asset or one with an oracle-driven `transfer_condition`/`issue_condition` alongside its main logic in a single response — a realistic pattern for reward/loyalty-token style AAs (the same category the original Notional report concerns). Any attestor outage, timing gap before attestation, or an oracle not yet reflecting the current state is sufficient to trigger the bounce, making this moderately likely for such AA designs, though it does not affect base-asset-only AAs that avoid attaching conditioned assets to core-logic responses.

### Recommendation
- Decouple reward/incentive-style payments of condition-gated assets from core AA state changes: emit the core state update in one trigger/response and let the conditioned payment be claimable separately (e.g., record a claimable balance in state, similar to the "claimable[]" fix suggested in the original report) rather than composing them into a single atomically-bounceable unit.
- When an AA must pay out a `spender_attested` or condition-gated asset, guard the payment message with an `if` clause in oscript that checks the condition in advance (e.g., verifying attestation status via `is attested` state read) so a failed condition results in skipping just that message rather than bouncing the whole response, where the AA framework supports partial `if`-gated messages.
- Consider auditing existing/community AAs for this bundling pattern before granting them privileged roles that also perform critical bookkeeping.

### Proof of Concept
1. Issuer defines an asset `A` with `spender_attested: true` and `attestors: [X]` (or a `transfer_condition` referencing `in data feed` from oracle `O`) — see the fields checked in `validateAssetDefinition`/`validatePaymentInputsAndOutputs`: [5](#0-4) 
2. An AA's `messages` array combines (a) a `state` message performing core bookkeeping (e.g., incrementing a user's recorded balance) and (b) a `payment` message sending asset `A` to `trigger.address` as a "reward."
3. A trigger is posted by an ordinary user. If `trigger.address` is not currently in `X`'s attested list (or oracle `O` hasn't posted the expected data-feed value), `validatePaymentInputsAndOutputs` returns an error for the payment message.
4. `sendUnit`'s `validateAndSaveUnit` callback receives this error and calls `bounce(err)`, which restores `originalStateVars`/`originalBalances`, undoing the core bookkeeping state change from step 2(a) as well — even though it had nothing to do with the attestation/oracle failure. [2](#0-1)

### Citations

**File:** aa_composer.js (L909-922)
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

**File:** definition.js (L933-940)
```javascript
			case 'in data feed':
				// ['in data feed', [['BASE32'], 'data feed name', '=', 'expected value']]
				var arrAddresses = args[0];
				var feed_name = args[1];
				var relation = args[2];
				var value = args[3];
				var min_mci = args[4] || 0;
				dataFeeds.dataFeedExists(arrAddresses, feed_name, relation, value, min_mci, objValidationState.last_ball_mci, false, cb2);
```
