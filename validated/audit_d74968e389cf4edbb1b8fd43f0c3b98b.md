## Analog Found

### Title
Downstream secondary-AA failure reverts and freezes the entire primary AA response - ([File: aa_composer.js])

### Summary
The Obyte AA execution engine cascades payments into "secondary triggers" whenever an AA sends funds to another address that is itself an Autonomous Agent. If any AA anywhere in that dependency chain bounces, `aa_composer.js` unconditionally discards the *entire* primary trigger's already-computed state changes, response units and payments (including transfers destined to unrelated, well-behaved recipients) and turns the whole execution into a bounce. This mirrors the dTRINITY `DStakeToken`/`DStakeRouterDLend` bug, where a downstream/secondary operation on an unrelated leg of the flow (refunding surplus into the Aave-wrapped vault) can revert for reasons outside the withdrawer's control, and that unrelated failure aborts the entire user-facing operation.

### Finding Description
In `aa_composer.js`, `handleSecondaryTriggers` is invoked after the primary AA has already built and (attempted to) save its response unit, for every output address that happens to be a deployed AA: [1](#0-0) 

If any of those chained secondary AA calls returns an error, the primary (non-secondary) branch calls `revert()`, which rolls back **all** state variables, forgets **all** response units generated so far by the primary AA and any earlier secondary AAs in the chain, and then bounces the entire trigger: [2](#0-1) [3](#0-2) 

This is functionally identical in shape to the reported bug: a legitimate primary operation (the DStake withdraw, or here, the primary AA's business logic that already computed correct payments/state for the actual triggering user) is made contingent on the success of an unrelated downstream leg (the Aave-vault surplus redeposit, or here, an unrelated secondary AA elsewhere in the payment graph) that can fail for reasons entirely outside the primary caller's/AA's control (paused/frozen external protocol vs. a downstream AA that bounces due to its own bounce-fee checks, `MAX_RESPONSES_PER_PRIMARY_TRIGGER`/`max_aa_responses` limits, missing data feed, insufficient asset balance requiring issuer-only checks, etc. — see `handleTrigger`'s bounce conditions): [4](#0-3) 

Any AA design that forwards part of its output to a fixed/known secondary AA (fee vault, treasury, reward pool, oracle payout AA, etc.) is exposed: once that secondary AA is in a state where it bounces (whether due to its own bug, being paused by its own logic, exceeding response caps, or an attacker deliberately manipulating shared state/data feeds that the secondary AA's condition depends on), **every** trigger to the primary AA — even those unrelated to the failing leg — is entirely reverted and bounced, refunding only `bounce_fees` and discarding the primary AA's legitimate computed response.

### Impact Explanation
This is an AA fund-freezing/DOS condition: legitimate users triggering a healthy primary AA get their entire intended operation and refund logic nullified purely because a downstream AA (over which the triggering user has no control) reverts. Because `revertResponsesInCaches`/`ROLLBACK TO SAVEPOINT initial_balances` unwind the *whole* chain, not just the failing branch, a single misbehaving or intentionally-poisoned secondary AA can systemically freeze an otherwise-correct primary AA for all its users, matching the "AA fund loss or freezing" impact category.

### Likelihood Explanation
Reachable by any unprivileged AA trigger sender: they only need to send a normal trigger unit to a primary AA whose design (by the AA author, not the attacker) forwards funds to a secondary AA. The attacker does not need to compromise the primary AA — they only need the secondary AA (which they may control, or whose state/data-feed dependencies they can influence) to be in, or be driven into, a bouncing state. Since AA definitions and their conditional logic (`bounce_fees`, `max_aa_responses`, data-feed based `if` conditions, balance checks) are fully attacker-composable in oscript, crafting a secondary AA that reliably bounces under attacker-chosen conditions is straightforward.

### Recommendation
Do not let a failure in a secondary/chained AA trigger unconditionally revert the primary AA's already-valid state changes and response unit. Consider isolating each AA's response atomically at the level of that AA only (already-produced, valid response units for AAs earlier in the chain should be allowed to stand), or require primary AAs to explicitly opt into "all-or-nothing" semantics rather than making it the unconditional default in `revert()`/`handleSecondaryTriggers`.

### Proof of Concept
1. Deploy AA `S` (secondary) whose logic bounces whenever a chosen condition (e.g., a data feed value, or `balance[...]` check, or exceeding its own `max_aa_responses`) is met — attacker fully controls `S`'s definition.
2. Deploy or point to any primary AA `P` (e.g., a DEX, staking vault, DAO) whose `messages` unconditionally forward a portion of every response's output to `S` (a common pattern: fee/treasury/reward-pool AA).
3. Trigger the condition that makes `S` bounce (e.g., post a data feed value, or repeatedly trigger `S` until it hits `max_aa_responses`/`MAX_RESPONSES_PER_PRIMARY_TRIGGER`).
4. Any subsequent, otherwise legitimate, trigger sent to `P` by any user causes `handleSecondaryTriggers` to invoke `S`, which bounces; `revert()` then discards `P`'s entire valid response and state changes, converting a normal successful operation into a bounce for every user — reproducing the DOS pattern from the source report at `aa_composer.js:1743-1783`.

### Citations

**File:** aa_composer.js (L1702-1720)
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
```

**File:** aa_composer.js (L1743-1749)
```javascript
				function (err) {
					if (err) {
						// revert
						if (bSecondary)
							return bounce(err);

						return revert({message: "one of secondary AAs bounced with error: ", callChain: {address, next: err}});
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

**File:** aa_composer.js (L1846-1862)
```javascript
		if (arrResponses.length >= constants.MAX_RESPONSES_PER_PRIMARY_TRIGGER) // max number of responses per primary trigger, over all branches stemming from the primary trigger
			return bounce("max number of responses per trigger exceeded");
		if ("max_aa_responses" in trigger && arrResponses.length >= trigger.max_aa_responses)
			return bounce(`max_aa_responses ${trigger.max_aa_responses} exceeded`);
		// being able to pay for bounce fees is not required for secondary triggers as they never actually send any bounce response or change state when bounced
		if (!bSecondary) {
			if ((trigger.outputs.base || 0) < bounce_fees.base) {
				return bounce('received bytes are not enough to cover bounce fees');
			}
			for (var asset in trigger.outputs) { // if not enough asset received to pay for bounce fees, ignore silently
				if (bounce_fees[asset] && trigger.outputs[asset] < bounce_fees[asset]) {
					return bounce('received ' + asset + ' is not enough to cover bounce fees');
				}
			}
			// skip this check for dry-run which uses genesis unit as trigger unit
			if (trigger.unit !== constants.GENESIS_UNIT && !trigger_opts.bAir && storage.assocStableUnits[trigger.unit].count_aa_responses && mci >= constants.pemCurvesFixMci)
				return bounce('a second primary trigger from the same unit is not allowed');
```
