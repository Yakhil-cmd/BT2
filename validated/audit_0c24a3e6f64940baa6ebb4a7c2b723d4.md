### Title
Single failing secondary AA trigger reverts an entire chain of AA responses, permanently freezing funds routed through unrelated branches - (File: `aa_composer.js`)

### Summary
In `aa_composer.js`, when a primary AA's response unit sends outputs to one or more other AAs, those AAs are invoked as "secondary triggers" inside `handleSecondaryTriggers()`. All secondary triggers spawned from a single primary trigger execute inside one DB transaction/one `batch`. If **any single** secondary AA in that chain bounces with an error, the whole chain — including state changes and payments made by every other, unrelated AA in the same trigger DAG — is unwound via `revert()`, and the primary trigger itself just bounces the incoming payment. This mirrors the reported `Voter.distribute` bug class: a loop over several independent sub-operations where the failure of a single item aborts the entire batch, wasting the work already done for the successful items and potentially freezing funds that depend on that path succeeding.

### Finding Description
`handleSecondaryTriggers()` collects every AA address that received an output from the current response unit and processes them with `async.eachSeries`: [1](#0-0) 

If any of these secondary AAs calls back with a `bounce_message` (i.e., that individual secondary AA's logic bounced for whatever reason — insufficient balance, an unmet `if` condition, a missing state var, etc., exactly analogous to the "`proposal must be updated`" style pre-condition failure in the reported Voter bug), `async.eachSeries`'s final callback receives that error and immediately calls `revert()` for the whole chain rather than continuing with or isolating the failing branch: [2](#0-1) 

`revert()` unconditionally throws away all balance/state changes accumulated by every AA in the DAG up to that point (not just the failing one), rolls back to a savepoint, and falls back to just bouncing the primary trigger's payment: [3](#0-2) 

Because a trigger unit is user-supplied and its outputs (which decide which AAs become secondary triggers) are fully attacker/user controlled, any address — an ordinary unprivileged trigger sender — can construct a payment/trigger to a primary AA whose configured response logic fans out to several independent secondary AAs. If just one of those secondary AAs has any state-dependent failure mode (the same class of "sometimes fails" precondition the original report describes for gauges), invoking the primary AA will deterministically bounce and undo work for **all** branches, every time, with no way for the caller to skip or isolate the failing branch — there is no equivalent of `distribute(_start,_finish)` or `distribute(gauges[])` to work around a single bad participant.

### Impact Explanation
This can produce persistent freezing of funds/state for AAs that fan out to multiple downstream AAs: as long as one downstream AA in the DAG keeps failing (e.g., due to an oracle/state-feed dependency not being met, a bug in that AA, or simply running out of balance for its own bounce fee), the whole primary AA becomes unusable — every trigger to it bounces, so funds intended for the healthy branches of the DAG are perpetually returned/never delivered, and useful computation/state updates performed by the healthy branches are wasted on every attempt. This matches the "AA fund freezing" impact category.

### Likelihood Explanation
Any unprivileged user who can post a valid unit is able to trigger AAs with arbitrary payment amounts and, once the target AA's own logic decides to pay several secondary AAs, exercise this all-or-nothing behavior. No special privilege, race, or timing is needed — only a AA whose design (a common pattern, similar to distributing rewards to several "gauge"-like AAs) forwards payments to multiple sub-AAs where one of them can independently fail.

### Recommendation
Consider giving AA authors a documented, supported way to make secondary-trigger fan-out fault-tolerant, e.g.:
- Allow an AA's `messages` to mark specific `payment` outputs to other AAs as independent/non-atomic, so a bounce in one secondary trigger does not force `revert()` of the entire chain, or
- Expose the specific address/error of the failing secondary AA back to the primary AA (already partly done via `errorObj`) *before* committing to `revert()`, so future AA logic can react rather than unconditionally losing all sibling branches' state.

At minimum, this should be explicitly documented as expected atomic-chain semantics so AA authors avoid architectures (like a rewards-distribution AA that forwards to many independent recipient AAs in one trigger) that are vulnerable to a single unreliable participant freezing the whole flow.

### Proof of Concept
1. Deploy `Primary AA` whose response sends outputs to `SecondaryA` and `SecondaryB` (both become secondary triggers of the same primary trigger, per `getTrigger`/`handleSecondaryTriggers`): [4](#0-3) 
2. Deploy `SecondaryB` such that its own logic bounces under a condition entirely controlled by an unrelated third party (e.g., depends on a data feed value or a state var not yet set — analogous to `proposalUpdated` in the reported bug).
3. Trigger `Primary AA` while `SecondaryB`'s condition is unmet. `SecondaryA`'s payment/state changes are computed and would have succeeded, but because `SecondaryB` bounces, `async.eachSeries`'s error handler calls `revert()`, discarding `SecondaryA`'s results and bouncing the whole trigger: [3](#0-2) 
4. Every subsequent trigger to `Primary AA` behaves identically until `SecondaryB`'s external precondition is fixed, effectively freezing funds/functionality that depend on `SecondaryA`'s branch.

### Citations

**File:** aa_composer.js (L1702-1741)
```javascript
	function handleSecondaryTriggers(objUnit, arrOutputAddresses) {
		conn.query("SELECT address, definition, mci, main_chain_index FROM aa_addresses LEFT JOIN units USING(unit) WHERE address IN(?) AND mci<=? ORDER BY address", [arrOutputAddresses, mci], function (rows) {
			if (rows.length > 0 && constants.bTestnet && mci < testnetAAsDefinedByAAsAreActiveImmediatelyUpgradeMci)
				rows = rows.filter(function (row) {
					if (row.main_chain_index && row.main_chain_index < mci) // previous definition is already stable
						return true;
					var len = storage.getUnconfirmedAADefinitionsPostedByAAs([row.address]).length;
					if (len > 0)
						console.log("not calling secondary trigger from unit " + objUnit.unit + " to AA " + row.address);
					return (len === 0);
				});
			if (rows.length === 0) {
				saveStateVars();
				addUpdatedStateVarsIntoPrimaryResponse();
				return onDone(objUnit, bBouncing ? error_message : false);
			}
			if (bBouncing)
				throw Error("secondary triggers while bouncing");
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
