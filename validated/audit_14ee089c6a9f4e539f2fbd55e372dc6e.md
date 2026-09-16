### Title
Fund distribution to a permanently-bouncing recipient AA can lock funds in a distributor AA with no migration path - (File: aa_composer.js)

### Summary
The external report describes an Ethereum `FeeDistributor` contract where a single fee receiver that cannot accept ETH (revert or excessive gas) blocks the whole `withdraw()` call, causing ether to become permanently stuck with no way to migrate. The analogous ocore mechanism is Autonomous Agent (AA) response composition: `handleTrigger`/`sendUnit` in `aa_composer.js` builds one atomic response unit containing all payment outputs, and if any single output triggers a secondary AA (`handleSecondaryTriggers`) that itself bounces, the *entire* primary response is reverted via `revert()`, undoing all state changes and all other, otherwise-valid, outputs. Because AA bytecode is immutable and cannot be upgraded or migrated, an AA whose payout logic unconditionally sends part of its balance to a permanently-failing recipient AA can become unable to ever complete any distribution that includes that output, for the lifetime of the contract.

### Finding Description
When an AA response includes a payment message with an output to another AA's address, `sendUnit()` completes and saves the response unit, then calls `handleSecondaryTriggers(objUnit, arrOutputAddresses)` [1](#0-0) , which invokes `handleTrigger` recursively for every AA address found among the outputs [2](#0-1) .

If any secondary AA trigger bounces, the error propagates back through `cb`, and for a primary (non-secondary) trigger the code calls:
```
return revert({message: "one of secondary AAs bounced with error: ", callChain: {address, next: err}});
``` [3](#0-2) 

`revert()` rolls back the DB savepoint, clears the batch, deletes all accumulated state-variable changes, and discards every response collected so far (including successful ones from unrelated outputs), then calls `bounce()` on the *primary* trigger [4](#0-3) . This means a single poisoned/failing recipient in a multi-output distribution nullifies the entire operation — exactly the "one bad receiver blocks everyone" pattern from the `FeeDistributor` report.

Because oscript AA definitions are content-addressed and immutable (an AA's code/address is fixed once defined, and it cannot be redefined or "upgraded" in place — the codebase has no such migration primitive), if the payout logic in an AA deterministically depends on a fixed/hardcoded recipient AA address (for example, splitting incoming funds among several fixed sub-AAs) and that recipient AA can be made to permanently bounce every trigger (e.g., because its own state/logic always fails a condition, or a required getter/formula call always errors, or its bounce fee / balance requirements can never be satisfied given the forwarded amount), then:
- Every subsequent trigger to the parent distributor AA that produces this same payment shape will revert and bounce.
- The distributor AA's balance for the base asset (and/or any asset it holds) becomes practically unspendable through its normal state-machine, since the parent AA's only code path to release funds routes through the broken payout.
- There is no way to "redeploy" state or migrate the stuck balance to a new AA instance, because balances live at the immutable AA address and can only move via that AA's own (bricked) logic.

### Impact Explanation
This is a Medium/High-severity availability/fund-freezing issue: an attacker (or an unlucky configuration) can cause AA-held funds — belonging to all future depositors/participants of that AA, not just one party — to become permanently locked with no recovery mechanism, mirroring the "no ether can be withdrawn" impact in the original report. Depending on AA design, this can affect all users who trigger a given payout branch of the AA, not merely the attacker who created the poisoned condition, satisfying the "AA fund loss or freezing" acceptance criterion.

### Likelihood Explanation
Likelihood is Medium: exploitation requires an AA author (or an attacker who can influence AA parameters, e.g. via `base_aa`/`params` templating, or via state vars populated from earlier triggers) to arrange for a fixed downstream AA address used in a payment output to permanently fail its own trigger handling. This is most plausible in composed/factory AA patterns where one AA's `messages` unconditionally pay out to another AA address (chained AAs), and where the receiving AA's logic can be driven into an always-bouncing state (e.g., a required precondition that a malicious/adversarial actor can force to be permanently false, or a design bug in the receiving AA). It does not require any privileged/network-level position — any unprivileged trigger sender able to set up or trigger this condition through legitimate primary/secondary trigger flows can reach it.

### Recommendation
- When composing AA response messages that pay to other AA addresses, treat those sends as "best effort": isolate secondary-trigger failures so that a failing secondary AA does not force `revert()` of the entire primary response. For example, allow the primary AA definition author to explicitly acknowledge/handle secondary bounce failures (e.g., via a getter/condition that checks reachability, or a fallback branch) rather than making atomicity span across independently-controlled AA definitions.
- Document prominently (and perhaps enforce via `aa_validation.js`) that any oscript AA which forwards funds to another fixed AA address as part of its state machine risks self-bricking if the downstream AA ever bounces deterministically, and encourage defensive patterns (fixed, generous bounce_fees; sending "send-all" only as a last resort; avoiding unconditional forwarding to third-party AA addresses without a fallback/timeout state).
- Consider adding an operational/governance mechanism (e.g., an admin-defined `if`-branch or timeout-based fallback path in template AAs, or a general "circuit breaker" convention) so that if a downstream AA becomes permanently bouncing, the upstream AA has an alternate code path to release the funds to depositors instead of retrying the same broken payout forever.

### Proof of Concept
1. Deploy `AA_child`, whose response logic always bounces under some condition that becomes permanently true after a specific data point is recorded in its own state vars (e.g., `if (var['locked']) bounce('locked');` where `var['locked']` gets set to `true` by an early trigger and is never reset).
2. Deploy `AA_parent`, a distributor AA whose payout branch sends part of every incoming trigger's balance to `AA_child`'s fixed address as one of the outputs in its payment message, alongside a legitimate output to `trigger.address`:
   ```
   messages: [{
     app: 'payment',
     payload: {
       asset: 'base',
       outputs: [
         { address: '{trigger.address}', amount: "{...}" },
         { address: 'AA_CHILD_ADDRESS', amount: "{...}" }
       ]
     }
   }]
   ```
3. First trigger `AA_child` directly (or via `AA_parent`) so that `var['locked']` becomes `true`, making all of `AA_child`'s future triggers bounce.
4. Send a normal trigger to `AA_parent`. Its response unit is composed and saved, then `handleSecondaryTriggers` fires the secondary trigger into `AA_child`, which bounces [3](#0-2) .
5. `AA_parent`'s primary handler calls `revert()`, rolling back all of its own state changes and the previously-saved response unit, then bounces the primary trigger [4](#0-3) , meaning the legitimate output to `trigger.address` never actually reaches the trigger sender either.
6. Every future trigger against `AA_parent` that exercises this payout branch will repeat the same revert/bounce cycle indefinitely, since `AA_child` can never un-bounce and `AA_parent`'s definition (and thus its code path) cannot be changed. Funds held by `AA_parent` intended for this branch are permanently unreachable through the AA's normal logic.

*Note: I was not able to execute this scenario against a live/test ocore node within this investigation; the analysis is based on static reading of `aa_composer.js`'s `handleTrigger`/`sendUnit`/`handleSecondaryTriggers`/`revert` control flow. A live Devin session with test-suite execution (e.g., extending `test/aa_composer.test.js`) would be needed to empirically confirm the exact bounce/revert sequence and whether any existing safeguard (not found in this review) prevents permanent lock-up.*

### Citations

**File:** aa_composer.js (L1411-1421)
```javascript
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
									});
```

**File:** aa_composer.js (L1720-1742)
```javascript
			async.eachSeries(
				rows,
				function (row, cb) {
					var child_trigger = getTrigger(objUnit, row.address);
					child_trigger.initial_address = trigger.initial_address;
					child_trigger.initial_unit = trigger.initial_unit;
					if ("max_aa_responses" in trigger && mci >= constants.pemCurvesFixMci) // propagate the cap set on the primary trigger to secondary triggers
						child_trigger.max_aa_responses = trigger.max_aa_responses;
					var arrChildDefinition = JSON.parse(row.definition);

					var child_trigger_opts = { ...trigger_opts };
					child_trigger_opts.trigger = child_trigger;
					child_trigger_opts.params = {};
					child_trigger_opts.arrDefinition = arrChildDefinition;
					child_trigger_opts.address = row.address;
					child_trigger_opts.bSecondary = true;
					child_trigger_opts.onDone = function (objSecondaryUnit, bounce_message) {
						if (bounce_message)
							return cb(bounce_message);
						cb();
					};
					handleTrigger(child_trigger_opts);
				},
```

**File:** aa_composer.js (L1743-1750)
```javascript
				function (err) {
					if (err) {
						// revert
						if (bSecondary)
							return bounce(err);

						return revert({message: "one of secondary AAs bounced with error: ", callChain: {address, next: err}});
					}
```

**File:** aa_composer.js (L1759-1798)
```javascript
	function revert(err) {
		console.log('will revert: ' + err);
		if (bSecondary)
			return bounce(err);
		if (!trigger_opts.bAir)
			revertResponsesInCaches(arrResponses);
		
		// copy all logs
		var logs = [];
		arrResponses.forEach(objAAResponse => {
			if (objAAResponse.logs)
				logs = logs.concat(objAAResponse.logs);
		});
		if (logs.length > 0)
			objValidationState.logs = logs;
		
		arrResponses.splice(0, arrResponses.length); // start over
		if (trigger_opts.bAir)
			return bounce(err);
		Object.keys(stateVars).forEach(function (address) { delete stateVars[address]; });
		batch.clear();
		conn.query("ROLLBACK TO SAVEPOINT initial_balances", function () {
			console.log('done revert: ' + err);
			bounce(err);
		});
		/*
		conn.query("ROLLBACK", function () {
			conn.query("BEGIN", function () {
				// initial AA balances were rolled back, we have to add them again
				if (!fPrepare)
					fPrepare = function (cb) { cb(); };
				fPrepare(function () {
					updateInitialAABalances(function () {
						console.log('done revert: ' + err);
						bounce(err);
					});
				});
			});
		});*/
	}
```
