Based on my investigation, I found a valid analog in the AA (Autonomous Agent) trigger-processing engine.

### Title
Malicious secondary AA can revert an entire primary AA trigger, causing loss/freezing of funds intended for other unrelated recipients - ([File: aa_composer.js])

### Summary
`handleTrigger`'s `handleSecondaryTriggers` function processes multiple secondary AAs (any AA address that receives an output from the primary AA's response unit) sequentially in `async.eachSeries`. If any single secondary AA in that batch bounces (returns an error), the entire primary trigger is reverted via `revert()`, undoing all state changes and payments made to every other recipient in the same response unit, not just the failing one.

### Finding Description
When a primary AA sends payment outputs to multiple addresses in one response unit, and one or more of those addresses are themselves AAs, `handleSecondaryTriggers` iterates over all of them with `async.eachSeries`: [1](#0-0) 

If any of the secondary AA triggers bounces, the entire eachSeries fails and, for a primary trigger, the code calls `revert()` which rolls back all state variables, balances, and the batch/DB transaction for the *whole* AA response chain, not just the failing branch: [2](#0-1) 

`revert()` clears all accumulated `arrResponses`, deletes all `stateVars`, clears the `batch`, and issues a `ROLLBACK TO SAVEPOINT`, which undoes every payment/state change made to the *other* (non-malicious) recipients in the same trigger unit: [3](#0-2) 

This is directly analogous to the reported Y2K `Carousel.mintRollovers()` bug: a single hostile recipient (there, a contract with a reverting fallback; here, an attacker-deployed AA whose definition is engineered to always bounce, e.g. by referencing an always-false/error condition or intentionally malformed messages) can unilaterally block or reverse legitimate state changes/payments meant for unrelated, well-behaved recipients that happen to be batched together in the same processing loop. Any unprivileged user can define such a "poison" AA (AA definitions can be posted by anyone), and any unprivileged trigger sender who causes a primary AA to pay out to a set of addresses that includes the attacker's poison AA (e.g., an AA that iterates over a dynamic/user-suppliable list of payees, a registry, or a router/distributor pattern) will have the whole trigger's effects wiped out.

### Impact Explanation
This breaks the "AA fund loss or freezing" and "node disagreement" concerns from a fairness perspective within an atomic transaction: legitimate users who were supposed to receive funds or state updates from a primary AA response lose them entirely because one attacker-controlled address chosen by the attacker (not the victim) is included in the same output batch. Any AA design that fan-outs to caller-influenced or registry-based AA addresses (e.g., vault/distributor/router patterns, or aggregating multiple pending payouts in a single response unit) is vulnerable to complete denial of service / fund-freezing by a single malicious secondary AA, at the cost of only the trigger fee to define the poison AA and to get it included as an output target.

### Likelihood Explanation
Medium-High: exploitation requires that a primary AA's output logic can be influenced (directly or indirectly, e.g. via a registry state var or a batched set of pending recipients) to include an attacker-supplied address. This is a common pattern for AAs that pay out to multiple users in one response (analogous to "rollover"/batch payout designs), so it is readily reachable by any unprivileged user who can (a) define an AA that deterministically bounces, and (b) get it added as a payout target of a victim AA (e.g. by registering as a participant, or being a legitimate but adversarial actor among many payees).

### Recommendation
Isolate secondary-trigger failures per-branch instead of reverting the whole primary trigger. When a secondary AA bounces, that AA's own effects should already be self-contained (since a bounce only reverses that specific secondary AA's state/balance changes as designed via `bounce()`), and the primary trigger's `handleSecondaryTriggers` loop should continue processing/committing the other unaffected recipients rather than calling `revert()` to unwind the entire primary response. If atomicity across all secondary calls is required for defined AA semantics, document this clearly and encourage AA authors writing multi-recipient payout logic to isolate each recipient into its own independent trigger/response rather than batching untrusted addresses into a single all-or-nothing unit.

### Proof of Concept
1. Attacker defines AA `Poison` whose only message logic is `bounce("always fail")` (or equivalently a state formula that always throws/returns invalid data), deployed via a `definition` message - [4](#0-3) .
2. Attacker gets `Poison`'s address added as one of many payees of a victim AA `Distributor` that pays out to a set of addresses in a single response unit (e.g., by registering itself as a claimant/queue entry, similar to a "rollover queue").
3. A legitimate user (or the attacker) triggers `Distributor`. Its response unit contains payment outputs to several addresses, including `Poison`.
4. `handleSecondaryTriggers` is invoked with all these addresses that are AAs; `async.eachSeries` calls `handleTrigger` recursively for each, including `Poison` - [1](#0-0) .
5. `Poison`'s trigger execution bounces, `cb(err)` is invoked, and because this is a primary trigger's iteration (`bSecondary` is false at this outer level), `revert()` is called, wiping out `Distributor`'s entire response including payments/state updates to all other, legitimate payees - [5](#0-4) .
6. Every trigger of `Distributor` that includes `Poison` as a payee will permanently fail, freezing/losing the funds and state updates intended for the other legitimate recipients in that batch.

### Citations

**File:** aa_composer.js (L1301-1310)
```javascript
				if (message.app !== 'payment') {
					try {
						if (message.app === 'definition')
							message.payload.address = objectHash.getChash160(message.payload.definition);
						completeMessage(message);
					}
					catch (e) { // may error if there are empty objects or arrays inside
						return cb("some hashes failed: " + e.toString());
					}
					return cb();
```

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

**File:** aa_composer.js (L1743-1783)
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
