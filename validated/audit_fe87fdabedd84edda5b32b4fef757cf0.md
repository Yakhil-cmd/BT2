### Title
Bounce of any single secondary AA in a trigger's response chain unconditionally reverts and discards all sibling AA payments and state updates - (File: aa_composer.js)

### Summary
When a primary AA trigger causes payments to multiple secondary AAs (a "trigger graph"), `handleSecondaryTriggers()` in `aa_composer.js` processes each addressed secondary AA in series and, if *any one* of them bounces, unconditionally calls `revert()` for the whole primary trigger — discarding the responses, balances, and state-var updates of every other secondary AA that executed successfully, exactly analogous to TrueFiStrategy unconditionally calling a pausable external dependency and reverting an unrelated batch of operations.

### Finding Description
`handleSecondaryTriggers()` iterates over every AA address that received an output from the current unit/AA response and invokes `handleTrigger()` on each in series: [1](#0-0) 

If any child trigger bounces (`bounce_message` set), the `async.eachSeries` final callback treats this as a fatal error for the *entire* primary trigger (unless the current invocation is itself secondary, in which case it just propagates the bounce upward): [2](#0-1) 

`revert()` then unconditionally rolls back **all** accumulated `arrResponses` (i.e., every successful secondary-AA response generated so far in the same primary-trigger call chain), clears all state-var updates for every touched AA address, and rolls back the SQL savepoint and kv-store batch: [3](#0-2) 

There is no conditional check to isolate the failure to the specific secondary AA that failed (e.g., by skipping it and only bouncing its own payment back) — the code unconditionally treats one child failure as fatal for the whole graph, exactly like `TrueFiStrategy._deposit()` unconditionally calling `tfUSDC.join()` without checking `pauseStatus()` first.

This mirrors the reported bug class precisely: an author (whoever composes the triggering unit or an upstream AA that forwards a payment) has no way to prevent one down-stream AA — which may fail for reasons entirely outside the author's control (its own logic reverting, insufficient/oversize bounce fees, a stale internal condition, etc.) — from unwinding the entire multi-AA operation, including payments/logic destined for AAs that executed correctly.

### Impact Explanation
Any single unrelated AA in a payment/trigger graph that reliably bounces (whether due to its own bug, a deliberately hostile griefing AA planted by an attacker as one of the output addresses, or a legitimate but currently-failing condition) can be used to force the reversion of an entire batched multi-AA operation. This can:
- Cause loss of gas/bounce fees and DAG storage for the reverted attempt, repeatedly, for every retry.
- Deny service to unrelated AAs that would otherwise have received and correctly processed their payment/state update, because their success is retroactively discarded whenever a sibling in the same trigger chain fails.
- Be weaponized: an attacker who controls or can influence one leg of a multi-AA payment fan-out (e.g., is one of several strategy/DeFi/game AAs addressed by a router AA) can intentionally keep that leg failing to permanently block the router AA's ability to service all other counterparties in the same call.

This matches the required "AA fund loss or freezing" bar: legitimate AAs downstream of a shared router are functionally frozen out of receiving funds/updates as long as one sibling AA keeps bouncing, even though nothing is wrong with them individually.

### Likelihood Explanation
Likelihood is moderate-to-high: any AA developer who builds a "fan-out" or "router" AA that forwards trigger-derived payments to several other AAs (a common pattern for yield-routing, multi-strategy vaults, or marketplace/aggregator AAs) is exposed. No special privilege is needed to trigger it — any user who posts a unit that causes the router AA to address a currently-bouncing (or adversarially-controlled) secondary AA reproduces the failure, and the fix requires no protocol upgrade, only the AA author being aware of and working around this all-or-nothing semantics (which is undocumented as a caveat in the AA execution model).

### Recommendation
Consider providing AA authors a way to isolate secondary-trigger failures instead of making a single child bounce fatal to the whole chain, for example:
- Allow a primary/secondary AA to explicitly opt into "fire-and-forget" semantics for specific outgoing payments to other AAs, where a downstream bounce does not unwind the caller's own state/response.
- At minimum, document prominently that a payment routed to any other AA is effectively an atomic, blocking sub-call whose failure aborts the entire response tree, so that AA authors avoid unconditionally fanning out to AAs they do not fully control, and instead build in feature flags/circuit breakers analogous to the recommended `pauseStatus()` check in the original report.

### Proof of Concept
1. Deploy AA `Router` whose `messages` conditionally send a payment to `Sibling1` and to `Sibling2` (two independent secondary AAs) based on `trigger.data`, similar to the fan-out pattern in `handleSecondaryTriggers()`.
2. Deploy `Sibling2` such that a `bounce(...)` is unconditionally triggered for a given trigger shape (e.g., missing a required data field), simulating an externally "paused"/broken dependency.
3. Post a unit that triggers `Router`, causing it to fan out payments to both `Sibling1` and `Sibling2` in the same primary trigger.
4. Observe that even though `Sibling1` executes successfully and updates its own state/response, `handleSecondaryTriggers()`'s `async.eachSeries` callback sees the `Sibling2` bounce and calls `revert()` [2](#0-1) , which discards `Sibling1`'s successful response and state changes as well [3](#0-2) , so `Sibling1` never receives its funds/update despite executing correctly.
5. Repeat with any trigger that reaches `Router` while `Sibling2` remains broken/adversarial: `Sibling1` is permanently starved of service as a side effect of `Sibling2`'s unrelated failure.

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
