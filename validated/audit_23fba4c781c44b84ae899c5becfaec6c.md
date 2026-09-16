## Title
Single failing secondary AA trigger reverts and blocks token delivery to all other, unrelated secondary AAs triggered by the same unit - (File: `aa_composer.js`)

### Summary
When a trigger unit's `payment` messages pay multiple different AA addresses (e.g., a hub/distributor AA that forwards balances or fees to several other AAs in one response), `aa_composer.js`'s `handleSecondaryTriggers()` invokes each recipient AA sequentially with `async.eachSeries`. If any single one of these secondary AAs bounces, the entire chain — including secondary AAs that were processed successfully before it and those that would have succeeded but never even get a chance to run after it — is rolled back via `revert()`. This mirrors the reported `StakingRewardsManager.topUp()` bug class: a batched operation over several independent recipients is made atomic on a single shared failure condition, so one recipient's failure denies unrelated, legitimate recipients their tokens.

### Finding Description
`handleSecondaryTriggers()` collects every AA address that received an output from the parent unit and processes them one at a time: [1](#0-0) 

The iteration order is fixed by the SQL `ORDER BY address` and `async.eachSeries` stops at the first callback error: [2](#0-1) 

If any secondary AA's `onDone` callback reports a bounce message, the series is aborted and, for the primary (non-secondary) branch, `revert()` is called instead of continuing to process the remaining secondary AAs: [3](#0-2) 

`revert()` then unwinds *all* effects accumulated so far for the entire trigger chain — not just the failing AA's effects: [4](#0-3) 

Because `stateVars` are cleared, the write `batch` is cleared, and the DB is rolled back `TO SAVEPOINT initial_balances`, any secondary AA that already successfully executed earlier in the `async.eachSeries` loop (address-sorted order) has its state changes and outbound payments discarded, and any secondary AA appearing later in the sorted list never executes at all. The parent AA is then made to `bounce()`, so its whole response — including the portion meant for the well-behaved recipient AAs — is undone.

This is structurally the same flaw as `StakingRewardsManager::topUp()`: multiple independent "reward" recipients are processed in one batch/loop, and a `require`/bounce triggered by just one recipient (e.g., an attacker-deployed AA at one of the output addresses that intentionally always bounces, or simply an AA whose acceptance condition isn't met) denies token delivery to the rest of the batch — including recipients unrelated to and uninvolved in the failure.

### Impact Explanation
Any account can permissionlessly deploy an AA (address definition) that always bounces on receipt of funds. If that address is included as one of several outputs in another AA's response payment message (a common "distributor"/"router" AA pattern, e.g., splitting fees or rewards among several sub-AAs), the attacker's AA can force `revert()` on the whole trigger, causing:
- Loss of the payment/state changes intended for other, legitimate secondary AAs that would otherwise have succeeded (fund freezing/denial for those AAs).
- The distributing AA's own state changes and previously-registered effects for that trigger are wiped, forcing the parent's response to bounce, even though the parent AA's own logic executed correctly.

This is a fund-freezing/denial-of-service condition reachable by any unprivileged AA author who can get their AA address included as a payment recipient of another AA's outputs.

### Likelihood Explanation
The attacker only needs to define an AA (a normal, permissionless operation) whose logic always fails/bounces, and induce (or wait for) another AA to include that address among the outputs of one of its payment messages (this is a routine multi-recipient payout pattern, e.g. splitting proceeds among several sub-AAs/pools). No special privileges, timing races, or governance access are required, making this practically triggerable whenever a composite/distributor AA design sends to more than one AA address in the same trigger chain.

### Recommendation
Isolate the execution and balance effects of each secondary AA so a bounce in one does not unwind the successful state/payment effects of sibling secondary AAs triggered by the same parent unit. Options:
1. Use per-secondary-AA savepoints instead of one shared "initial_balances" savepoint for the whole chain, so only the failing secondary AA's own effects (and its own descendants) are rolled back, not siblings processed earlier or intended to run later.
2. Continue processing remaining secondary AAs in `async.eachSeries` after a bounce (accumulate errors) rather than short-circuiting, so unrelated recipients still get their outputs and state changes.
3. Document/clarify if today's fully atomic revert-the-whole-chain behavior is deliberate; if so, restrict/flag distributor-AA patterns that fan out payments to many other AA addresses in one message, since such patterns are inherently griefable under the current all-or-nothing semantics.

### Proof of Concept
1. Deploy AA `M` (malicious) whose only message logic always calls `bounce('always fail')` regardless of trigger data.
2. Deploy AA `D` (distributor) whose response to some trigger condition sends a `payment` message with outputs to AA `M` and to AA `G` (good, legitimate) in the same unit, e.g.:
```
messages: [
  { app: 'payment', payload: { asset: 'base', outputs: [
      { address: M_address, amount: 10000 },
      { address: G_address, amount: 20000 }
  ]}}
]
```
3. Trigger `D`. `D`'s response unit is created and both `M` and `G` are added to `arrOutputAddresses`, causing `handleSecondaryTriggers()` to invoke each in `address`-sorted order via `async.eachSeries` ( [1](#0-0) ).
4. If `M`'s address sorts before `G`'s, `M` bounces immediately, the `eachSeries` callback receives an error, `G` is never invoked at all, and `revert()` rolls back `D`'s state and balance changes entirely ( [5](#0-4) ) — `G` never receives its 20000 bytes despite being a fully legitimate, unrelated recipient.
5. If `M`'s address sorts after `G`'s, `G` executes and accepts its 20000 bytes successfully first, but when `M` subsequently bounces, `revert()` still unwinds `G`'s already-applied state/balance changes via `ROLLBACK TO SAVEPOINT initial_balances` and `batch.clear()`, wiping out `G`'s legitimately-received funds and state updates.

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
