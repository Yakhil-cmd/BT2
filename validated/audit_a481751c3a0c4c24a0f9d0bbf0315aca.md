### Title
Malicious recipient AA can force-revert legitimate primary AA transactions - (File: aa_composer.js)

### Summary
`aa_composer.js`'s `handleTrigger` function pays outputs to any address specified by the AA's own logic (which can be influenced by unprivileged trigger data), and if any output address happens to be another AA, `handleSecondaryTriggers` fires a secondary trigger to it. If that secondary AA bounces, the *entire* primary trigger — including all other outputs and state changes unrelated to the bounced recipient — is rolled back via `revert()`. This mirrors the external report's bug class: an unrelated, externally-controlled contract's `require`/bounce condition can block an otherwise valid top-level operation instead of only affecting its own leg.

### Finding Description
In `handleSecondaryTriggers`, every output address of the primary AA response that is itself an AA is processed as a secondary trigger in series: [1](#0-0) 

If any of these secondary triggers bounces, the callback receives an error and, for a primary (non-secondary) trigger, the code calls `revert()`, which rolls back the whole unit — not just the bounced leg: [2](#0-1) 

`revert()` clears all accumulated responses, rolls back the DB savepoint, and reverts caches, undoing state changes and payments intended for every other (honest) recipient in the same trigger, before finally bouncing the primary trigger back to the sender: [3](#0-2) 

Any user can permissionlessly deploy an AA definition whose logic always bounces (e.g., an unconditional `bounce()` in its formulas) and then cause a victim distributor/paymaster/marketplace AA to send funds to that address — either directly as an AA trigger sender specifying the malicious address as a destination parameter, or by being selected as a counterparty/recipient in the victim AA's normal flow (e.g., an auction, swap, or payout AA that forwards funds to a user-supplied or matched address). Because the check happens only after the primary AA has already computed and would apply all its outputs and state updates, one adversarial recipient AA is enough to nullify the whole transaction for every legitimate party in it.

### Impact Explanation
This allows an attacker to grief and deny service to AA-based protocols that pay out to third-party or attacker-influenceable addresses (e.g., decentralized exchanges, auctions, staking/reward distributors, multi-recipient payout AAs). Legitimate outputs to honest recipients bundled into the same primary trigger response are silently undone whenever one recipient AA is malicious, blocking value transfer and state progression for the honest parties (AA fund freezing / denial of correct execution) at very low cost to the attacker (only their own trigger's bounce fee).

### Likelihood Explanation
Deploying a self-bouncing AA is trivial and free for any user (unprivileged AA author). Triggering the vulnerable path only requires interacting with any production AA that sends outputs to an address that can be influenced by, or belongs to, an adversarial party — a common pattern for exchange, auction, and distribution-style AAs — making this practically reachable from ordinary trigger-sending unit posters.

### Recommendation
Do not let a bounce from a secondary/recipient AA revert the entire primary trigger's already-computed outputs and state changes for unrelated parties. Consider isolating the failure to the specific secondary chain (e.g., treat a bounced secondary trigger as a no-op forward/refund for that output only, or require the primary AA's own logic to explicitly opt into atomicity with recipients) rather than unconditionally rolling back the whole unit whenever any downstream secondary AA bounces.

### Proof of Concept
1. Deploy AA `M` whose only logic is `bounce("always fails")`.
2. Identify or deploy a "victim" AA `V` that, as part of normal multi-output payouts (e.g., matching an order, distributing rewards, or forwarding change/fees to a caller-specified address), can be made to send a non-zero output to an address chosen or influenced by the trigger sender.
3. Send a trigger to `V` that causes it to compute payouts to both a legitimate address and to `M`.
4. Observe in `handleSecondaryTriggers` (`aa_composer.js:1702-1757`) that the secondary trigger to `M` bounces, and `revert()` (`aa_composer.js:1759-1783`) rolls back the entire unit — the legitimate recipient never receives its payout and `V`'s state changes are undone, even though `V`'s own logic was correct and only `M`'s output was problematic.

### Citations

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

**File:** aa_composer.js (L1743-1757)
```javascript
				function (err) {
					if (err) {
						// revert
						if (bSecondary)
							return bounce(err);

						return revert({message: "one of secondary AAs bounced with error: ", callChain: {address, next: err}});
					}
					saveStateVars();
					addUpdatedStateVarsIntoPrimaryResponse();
					onDone(objUnit, bBouncing ? error_message : false);
				}
			);
		});
	}
```

**File:** aa_composer.js (L1759-1783)
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
```
