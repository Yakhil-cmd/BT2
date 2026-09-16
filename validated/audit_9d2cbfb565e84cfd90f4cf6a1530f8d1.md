## Title
A single failing secondary AA trigger causes the entire primary AA call chain to revert, losing/freezing funds for unrelated recipients - (File: aa_composer.js)

### Summary
In `aa_composer.js`, when a primary AA's response unit pays multiple secondary AA addresses in the same message, `handleSecondaryTriggers` fires the secondary triggers with `async.eachSeries` and unconditionally reverts the *entire* call chain — including the primary AA's own successful state changes and payments to any other, unrelated recipients — if just **one** of the secondary AAs bounces.

### Finding Description
When an AA response includes payments to multiple AA addresses, `handleSecondaryTriggers` iterates over all of them sequentially: [1](#0-0) 

If any one secondary trigger in that series bounces, the `async.eachSeries` callback receives an error, and — as long as this is not itself a secondary call (`!bSecondary`) — the code calls `revert()` for the *whole chain*, not just for the single failing secondary AA: [2](#0-1) 

`revert()` then rolls back to the savepoint taken before *any* balance changes in the chain and bounces the primary trigger, discarding every state update and payment that had already succeeded for other, unrelated secondary AAs in the same chain: [3](#0-2) 

This mirrors exactly the bug class in the external report: a batch of independent operations (there, protocols paying premiums; here, secondary AA triggers stemming from one primary trigger) is processed in a loop where a single failing/under-funded/misbehaving element (`ps.protocolBalance[_protocol].sub(debt)` there, `bounce(...)` here) causes the entire batch to halt and roll back, even though the other elements in the batch were valid and would otherwise have succeeded independently.

A secondary AA can bounce for reasons entirely outside the primary AA's control, e.g.:
- It doesn't hold enough balance to cover its own `bounce_fees` for the amount it was sent, checked at [4](#0-3) .
- Its own business logic (formula) calls `bounce()` based on external state (oracle data feeds, other triggers that changed its state vars, etc.) that an attacker can manipulate ahead of time.
- The shared chain-wide response cap `MAX_RESPONSES_PER_PRIMARY_TRIGGER` is hit, checked at [5](#0-4) , since this counter is shared across the *entire* call chain stemming from one primary trigger, not per-AA.

Any of these conditions in *any one* secondary AA cascades a full rollback of the primary AA's state changes and payments intended for every other secondary AA in the same response, even though those other payments/state changes were individually valid and would have succeeded on their own.

### Impact Explanation
An attacker who can influence the bounce condition of one secondary AA in a call chain (e.g. by draining its balance below its bounce-fee requirement, or by triggering conditions in its own logic that make it bounce) can force the entire upstream AA's response to bounce. This:
- Destroys the primary AA's state updates that would otherwise have succeeded.
- Prevents delivery of funds/state to *all other, unrelated* secondary AAs in the same response, even though nothing was wrong with those transfers.
- Results in the trigger's funds being effectively wasted (only the bounce fee is consumed; the intended multi-recipient distribution never happens), and can be used repeatedly as a griefing/denial-of-service vector against any AA design that fans out payments to multiple downstream AAs in one transaction — this is a concrete AA fund-loss/freezing scenario.

### Likelihood Explanation
Any AA author who builds a multi-recipient/composable design (e.g., a router/aggregator AA sending to several downstream AAs in a single response) is exposed. Because bounce conditions of a downstream AA (balance, state, business rules) are frequently influenceable by anyone posting units/triggers to that AA beforehand, an attacker does not need special privileges — an ordinary AA trigger sender can arrange for one of the downstream AAs to be in a bounce-inducing state, then wait for (or induce) the router AA to fan out a payment that includes that downstream AA.

### Recommendation
Consider isolating the effects of a bounced secondary trigger to that specific branch rather than rolling back the whole call chain: e.g., let a secondary AA's bounce only revert its own balance change (refunding the AA that sent to it) and record the failure in the response chain, instead of forcing `revert()` on the entire ancestor chain in `handleSecondaryTriggers`. Alternatively, document this cascading-revert behavior prominently for AA authors and provide a template mechanism to catch/ignore individual secondary-trigger failures (similar to try/catch semantics) so that a single failing downstream AA cannot invalidate unrelated successful operations in the same response.

### Proof of Concept
1. Deploy `AA_router` whose response, for a single trigger, sends payments to `AA_A` and `AA_B` in the same unit.
2. Deploy `AA_B` such that its `bounce_fees` requirement is not met for the amount `AA_router` sends it, or whose formula calls `bounce()` under attacker-controlled conditions (e.g. based on a state var the attacker can set via a prior unit).
3. Post a trigger to `AA_router` that would legitimately succeed for `AA_A`.
4. Observe in `handleSecondaryTriggers` (aa_composer.js:1720-1756) that because `AA_B`'s secondary trigger bounces, `async.eachSeries`'s final callback receives an error and `revert()` (aa_composer.js:1759-1783) is invoked, rolling back to `SAVEPOINT initial_balances` — undoing `AA_router`'s state changes and the payment that `AA_A` would otherwise have successfully received, even though nothing was wrong with `AA_A`'s branch.

### Citations

**File:** aa_composer.js (L1720-1741)
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
```

**File:** aa_composer.js (L1743-1756)
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

**File:** aa_composer.js (L1846-1847)
```javascript
		if (arrResponses.length >= constants.MAX_RESPONSES_PER_PRIMARY_TRIGGER) // max number of responses per primary trigger, over all branches stemming from the primary trigger
			return bounce("max number of responses per trigger exceeded");
```

**File:** aa_composer.js (L1851-1859)
```javascript
		if (!bSecondary) {
			if ((trigger.outputs.base || 0) < bounce_fees.base) {
				return bounce('received bytes are not enough to cover bounce fees');
			}
			for (var asset in trigger.outputs) { // if not enough asset received to pay for bounce fees, ignore silently
				if (bounce_fees[asset] && trigger.outputs[asset] < bounce_fees[asset]) {
					return bounce('received ' + asset + ' is not enough to cover bounce fees');
				}
			}
```
