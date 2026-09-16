### Title
Primary AA trigger can be permanently DoSed via a malicious secondary-AA "callback" that always bounces - (File: `aa_composer.js`)

### Summary
When an AA (Autonomous Agent) sends a payment to another address as part of processing a trigger, and that recipient address happens to be an AA itself, `aa_composer.js` automatically fires a **secondary trigger** to that recipient AA as part of the very same primary response. If the secondary AA's logic bounces (reverts), the entire primary trigger — including all of its state changes and outputs — is rolled back and bounced too. This is structurally the same bug class as the reported `repayLoan` issue: a counterparty-controlled "callback" (the secondary AA) that can be programmed to always fail, blocking the initiator's operation indefinitely.

### Finding Description
In `handleSecondaryTriggers()`, after a primary (or intermediate) AA sends outputs to addresses, any recipient address that is itself an AA is invoked as a **secondary trigger** synchronously, inside the same DB transaction: [1](#0-0) 

If that secondary AA bounces, the error is propagated back and the *entire* primary chain is reverted via `revert()`, not just the secondary branch: [2](#0-1) 

`revert()` rolls back all balance/state changes to the savepoint taken at the start of primary processing and then re-bounces the primary trigger itself: [3](#0-2) 

This means any AA-based protocol that pays funds "forward" to a party-controlled address (e.g. a lending, escrow, or marketplace AA that sends the counterparty's share/refund/repayment to an address chosen or controlled by that counterparty) is exposed: if the counterparty deploys that address as an AA whose logic unconditionally bounces (e.g. `bounce('nope')` in every code path), then:
1. Every trigger unit that tries to complete the payout will always end up reverted (bounced) as a whole.
2. Because bouncing rolls back *all* state changes of the primary AA (not just the failed payment), any state transition that was supposed to accompany the payment (e.g., marking a loan as repaid, releasing collateral, updating balances) never takes effect.
3. The initiator (e.g., a borrower repaying a loan, or a buyer claiming a refund) can never succeed in completing the intended action, permanently.

This directly mirrors the `Cooler.repayLoan` bug: the lender-controlled "callback" (there, an external contract call; here, a secondary AA trigger) can be toggled to always fail, denying the legitimate counterparty the ability to complete an operation whose success requires paying out to the attacker's address within the same atomic unit.

### Impact Explanation
Any oscript-based protocol built on ocore's AA framework (lending, escrow, marketplace, subscription, etc.) that includes an attacker/counterparty-influenceable payout address as part of a state-changing message can be permanently griefed: the victim's funds held by the honest AA (e.g., posted collateral) become frozen because the state transition that would release/settle them can never be finalized — the whole response always bounces. This satisfies the "AA fund loss or freezing" impact category, since collateral or escrowed balances become permanently unreachable once the state-changing branch requires paying the adversarial secondary AA.

### Likelihood Explanation
Exploitation only requires the attacker to control (or be able to designate) the address that the target AA's payout message routes funds to, and to deploy a trivial AA at that address whose only logic is `bounce(...)` unconditionally. This is straightforward and requires no special privileges beyond being a normal AA trigger sender/counterparty in a two-party protocol (e.g., the "peer" in an escrow, or "lender" in a lending AA) — squarely within the reachable set of an unprivileged AA author/trigger sender.

### Recommendation
- AA framework/application-level guidance should be updated to warn AA authors against combining state-committing logic (e.g., "mark loan repaid") in the same message set as a payment whose recipient is attacker-influenceable, since a bounce of a resulting secondary trigger unconditionally reverts all accompanying state changes.
- Where possible, protocols built on AAs should decouple fund transfer to a counterparty-controlled/AA address from the state transition that unlocks the sender's own funds (pull-payment style), or should not treat the secondary AA's bounce as fatal to the primary AA's own state changes.
- Consider whether `aa_composer.js`'s secondary-trigger semantics could offer an opt-in mode where a failing secondary trigger is treated as "silently swallowed with unspent funds returned to the primary AA's own balance" instead of reverting the entire primary response, for payment branches explicitly marked as non-critical/best-effort.

### Proof of Concept
1. Deploy AA `Escrow` (or a lending-style AA) whose `messages.cases` include a branch that, upon receiving a "settle"/"repay" trigger from the borrower/buyer, sends a payout in the same response to `$counterparty_address` and also updates `var['settled'] = 1` / releases collateral, following the pattern used in `test/aa_composer.test.js` "chain of AAs" test where a primary AA pays a secondary AA address as part of its message set: [4](#0-3) 
2. `$counterparty_address` is itself an AA (`Griefer`) whose only logic is to bounce unconditionally on every trigger, similar in spirit to `just_a_bouncer.oscript`'s AA but replacing the payment message with an unconditional `bounce(...)`.
3. Whenever the borrower/buyer posts the "settle"/"repay" trigger to `Escrow`, `handleSecondaryTriggers()` invokes `Griefer` as a secondary trigger, `Griefer` bounces, and per lines 1743-1749 the entire `Escrow` primary response — including the `var['settled'] = 1` state change — is reverted via `revert()`/`bounce()`. The borrower's collateral inside `Escrow` remains locked forever, since the only path to release it always routes through the attacker-controlled `Griefer` AA.

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

**File:** test/aa_composer.test.js (L156-214)
```javascript
test.cb.serial('chain of AAs', t => {
	var trigger_address = "I2ADHGP4HL6J37NQAD73J7E5SKFIXJOT";
	var trigger = { outputs: { base: 40000 }, data: { x: 333 }, address: trigger_address };

	var secondary_aa = ['autonomous agent', {
		bounce_fees: { base: 10000 },
		messages: [
			{
				app: 'payment',
				payload: {
					asset: 'base',
					outputs: [
						{address: "{trigger.initial_address}", amount: "{trigger.output[[asset=base]] - 2000}"}
					]
				}
			},
			{
				app: 'state',
				state: `{
					var['who'] = trigger.address || timestamp;
					var['initial'] = trigger.initial_address || timestamp;
					var['initial_unit'] = trigger.initial_unit;
					var['large_num2'] = var[trigger.address]['large_num'] + 1;
					var['long_num2'] = var[trigger.address]['long_num'] + 1;
					var['number_of_responses'] = number_of_responses;
					var['previous_aa_responses_trigger_address'] = previous_aa_responses[0].trigger_address;
					var['previous_aa_responses_unit'] = previous_aa_responses[0].unit_obj.unit;
				}`
			}
		]
	}];
	var secondary_address = objectHash.getChash160(secondary_aa);
	addAA(secondary_aa);

	var primary_aa = ['autonomous agent', {
		bounce_fees: { base: 10000 },
		messages: [
			{
				app: 'payment',
				payload: {
					asset: 'base',
					outputs: [
						{address: secondary_address, amount: "{trigger.output[[asset=base]] - 1000}"}
					]
				}
			},
			{
				app: 'state',
				state: `{
					var['who'] = trigger.address || timestamp;
					var['initial'] = trigger.initial_address || timestamp;
					var['large_num'] = 1e15;
					var['long_num'] = 0.000678901234567;
				}`
			}
		]
	}];
	var primary_address = objectHash.getChash160(primary_aa);
	addAA(primary_aa);
```
