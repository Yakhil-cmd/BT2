### Title
Malicious secondary-AA recipient can permanently block and freeze funds owed to unrelated parties in a shared AA response - (File: aa_composer.js)

### Summary
The reported ERC20 bug lets an attacker who controls the *payment method* (a malicious `_currency` contract) unconditionally revert every `transfer` call, so a trusted contract can never finalize a payout to any party involved in the transaction. The same bug class exists in ocore's Autonomous Agent (AA) engine: when a primary AA response sends bytes/assets to multiple addresses in the same trigger handling, and one of those addresses is a secondary AA, that secondary AA's logic runs synchronously as part of the same trigger. If the attacker-controlled secondary AA is made to always bounce, the entire primary trigger — including payments intended for completely unrelated, honest parties — is rolled back and re-bounced, every single time the trigger is processed.

### Finding Description
When a primary AA sends an output to another AA address, `handleSecondaryTriggers` fires a nested `handleTrigger` call for that secondary AA as part of processing the very same unit: [1](#0-0) 

If that secondary AA's execution results in a bounce (`cb(bounce_message)`), the error propagates up through `async.eachSeries`, and for a *primary* trigger (not itself secondary) the code calls `revert()` instead of just failing locally: [2](#0-1) 

`revert()` unwinds everything that happened for the whole trigger — not just the secondary AA's part: [3](#0-2) 

It reverts all in-memory response caches (`revertResponsesInCaches`), clears all pending state variable updates (`stateVars`), clears the batch, and issues `ROLLBACK TO SAVEPOINT initial_balances` on the DB connection, discarding the entire chain of payments and state changes produced by the primary AA and any earlier secondary AAs that already ran successfully in this same trigger. It then calls `bounce(err)`, so the primary AA's overall response becomes a bounce, exactly as if the top-level AA itself had failed.

This means an attacker only needs to be *one* of several payees in an AA's payout logic (e.g., an escrow/marketplace AA that pays a seller, buyer refund, and a fee/commission address in one response) to be able to force the whole transaction to fail on every attempt, denying the payout to the *other, honest* payees as well. The `test.cb.serial('calling a remote function that fails', ...)` test demonstrates the underlying mechanism — an attacker-controlled remote AA calling `bounce(...)` inside its own logic causes the calling AA's entire trigger to bounce: [4](#0-3) 

And the "chain of AAs" test confirms that outputs to secondary AAs are processed inline as part of the same trigger/response chain, so their failure is not isolated from the primary AA's own logic: [5](#0-4) 

An attacker can guarantee a bounce cheaply and reliably by simply deploying/using an AA address that either has no logic that satisfies its own bounce-fee/complexity checks, or that deliberately calls `bounce(...)`. Since the trigger MCI, complexity, and definition of the attacker's AA are fully under the attacker's control (it's just another oscript AA they define themselves, exactly analogous to the malicious ERC20 contract), this attack is trivial and repeatable at essentially zero incremental cost, and it can be re-triggered indefinitely because the payout logic that references the attacker's address as a recipient never changes.

### Impact Explanation
Any AA design that pays out to a set of addresses in a single response (marketplace payouts, escrow finalization, DEX settlement, revenue splits, multi-recipient distributions) is vulnerable if any one of the destination addresses can be chosen or influenced by an untrusted party and that address turns out to be (or is later redefined/pre-computed as) an AA. A single malicious/misbehaving recipient AA can force the entire primary trigger to bounce every time, which:
- Permanently prevents the AA from ever completing that class of trigger (denial of service on legitimate counterparties' funds, analogous to "an offer that can't be finalized").
- Freezes/traps the value sent with the triggering unit inside the AA (since bounce consumes/returns only `bounce_fees`, and repeated attempts always fail the same way), effectively locking funds meant for honest recipients.
- Can be weaponized by a griefing counterparty (e.g., in an escrow or split-payment AA) exactly as Bob does with the malicious ERC20 in the original report — the "other side" of the transaction is denied resolution indefinitely.

This matches the required impact bar of AA fund loss/freezing and a legitimate transaction being permanently unable to be confirmed/finalized.

### Likelihood Explanation
Likelihood is high for any AA whose logic pays multiple parties in one response where at least one recipient address is attacker-influenced (e.g., specified as a parameter by a permissionless caller, similar to how `_currency`/counterparty addresses are attacker-supplied in the ERC20 report). Constructing a bouncing AA is trivial — the attacker fully controls its oscript definition, complexity, and can just call `bounce()` unconditionally or omit sufficient bounce fees. No special privileges (validator, hub, witness) are required; it only requires posting ordinary units as an unprivileged AA trigger sender/asset issuer/private-payment counterparty, matching the reachable surface for this scan.

### Recommendation
- Short term: Isolate the effect of secondary-trigger failures so that a bounce in one downstream AA does not automatically revert the payments/state changes already committed to *other, unrelated* recipients in the same primary response. At minimum, document and strongly warn AA authors against sending outputs to attacker-influenced/unknown addresses within the same response as guaranteed payments to other parties, and consider adding an oscript-level mechanism (e.g., a "best effort"/`try`-like message flag) that lets a payment to a specific address fail without reverting the whole trigger.
- Long term: Consider decoupling secondary-trigger execution from the primary trigger's atomicity guarantee — e.g., queue payments to other AAs as independent triggers that are processed and can fail independently, rather than executing them synchronously within the same all-or-nothing transaction as the primary AA's remaining messages and state updates.

### Proof of Concept
1. Define `MaliciousAA` with a definition that guarantees a bounce whenever triggered, e.g.:
```
{
  messages: [
    { app: 'state', state: "{ bounce('always fail'); }" }
  ]
}
```
2. Define `EscrowAA` (the victim), whose response to a trigger pays out to multiple addresses in one unit, e.g. `trigger.data.seller` and `trigger.data.buyer`, where `seller`/`buyer` are attacker-influenced parameters (analogous to the offer's `_currency`/counterparty in the report).
3. An attacker triggers `EscrowAA` (or convinces a legitimate user to) with `trigger.data.seller` set to `MaliciousAA`'s address.
4. `EscrowAA`'s response includes a payment output to `MaliciousAA`, which becomes a secondary trigger per `handleSecondaryTriggers` (aa_composer.js:1702-1742).
5. `MaliciousAA` always bounces, so `handleSecondaryTriggers`'s `async.eachSeries` callback receives an error and calls `revert()` (aa_composer.js:1743-1749), which rolls back **all** of `EscrowAA`'s payments/state for this trigger — including the payout intended for the honest `buyer` — and turns the whole thing into a bounce (aa_composer.js:1759-1783).
6. Every future attempt to finalize this escrow trigger fails identically, permanently denying the honest buyer's payout while the triggering funds remain stuck in `EscrowAA`.

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

**File:** test/aa_composer.test.js (L156-221)
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
	
	aa_composer.dryRunPrimaryAATrigger(trigger, primary_address, primary_aa, (arrResponses) => {
		t.deepEqual(arrResponses.length, 2);
		t.deepEqual(arrResponses[0].aa_address, primary_address);
		t.deepEqual(arrResponses[0].bounced, false);
		t.deepEqual(arrResponses[0].response.error, undefined);
		t.deepEqual(arrResponses[0].objResponseUnit.messages.find(function (message) { return (message.app === 'payment'); }).payload.outputs.find(function (output) { return (output.address === secondary_address); }).amount, 39000);
```

**File:** test/aa_composer.test.js (L1629-1647)
```javascript
	var remote_aa = ['autonomous agent', {
		getters: `{
			$f = ($x) => {
				if ($x==5)
					bounce("==5");
			};
		}`,
		messages: [
			{
				app: 'payment',
				payload: {
					asset: 'base',
					outputs: [
						{address: "{trigger.initial_address}", amount: 1000}
					]
				}
			}
		]
	}];
```
