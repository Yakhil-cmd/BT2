### Title
Malicious secondary-trigger AA can grief chains of AAs, causing legitimate protocol responses to be discarded and trigger-sender funds to be wasted - (File: `aa_composer.js`)

### Summary
`handleTrigger()` in `aa_composer.js` posts a payment message to any address returned in a response, and if that address is an AA, it is automatically invoked as a "secondary trigger" via `handleSecondaryTriggers()`. If the secondary AA bounces for any reason (including an intentionally, adaptively reverting malicious AA), the *entire* primary response chain is discarded via `revert()`, which does a full `ROLLBACK TO SAVEPOINT initial_balances` and clears the write batch. This is structurally the same root cause as the reported PromiseRouter bug: an unconditional external call whose failure/revert is propagated up and destroys work/fees that other parties already paid for, with the callee address chosen at a point the attacker can control or predict.

### Finding Description
When a primary AA computes a response, any payment output addressed to another AA is treated as a secondary trigger and immediately executed synchronously within the same DB transaction: [1](#0-0) 

If any secondary AA in the chain bounces, the error is propagated to the top-level `async.eachSeries` callback, and (for a primary, non-secondary caller) `revert()` is invoked instead of simply accepting the bounce of that one hop: [2](#0-1) 

`revert()` unconditionally rolls back *all* balance/state changes made by the whole chain of AAs (not just the offending secondary AA), clears the pending batch write, and only then re-enters `bounce()` for the primary trigger: [3](#0-2) 

This mirrors the PromiseRouter bug class exactly: a downstream "callback" recipient (the secondary AA address) is called unconditionally with no isolation/try-catch equivalent, and if it reverts, everything the calling code already did (potentially several AAs' worth of payments and state changes) is thrown away in one atomic revert, denying value to everyone upstream in the chain — even though those upstream AAs behaved correctly.

Any AA author can deploy an "AA" that always bounces, or bounces adaptively (e.g., only when it observes it is receiving funds above a threshold, or only during specific MCI windows, using `bounce()` in oscript) to selectively grief. Protocols that compose with user-supplied or third-party AA addresses (e.g., DEX/aggregator/relayer-style AAs that forward funds to a caller-specified destination AA, similar to Uniswap-like market maker patterns seen in the test suite) are exposed: a malicious actor supplies (or is) the destination AA, and forces `revert()` on every trigger that routes through them.

### Impact Explanation
This qualifies as AA fund loss/freezing and node-visible denial of service for a specific interaction pattern:
- The trigger sender's payment is consumed in gas/complexity terms (the whole multi-hop chain is computed, DB work performed) yet the entire state update is rolled back; the sender only gets back `trigger.outputs - bounce_fees` via `bounce()`, losing the excess funds/complexity they paid expecting a successful swap/service — exactly the "attacker causes caller to lose value without any recourse" pattern from the report.
- Any legitimate AA that forwards to a secondary AA (as designed feature of the platform, e.g., swaps, routers) can have 100% of its otherwise-valid trigger executions destroyed by a single malicious downstream AA, which is a reliable, repeatable DoS against that AA's whole business logic, not just a single call.
- Because AA code and state are public and deterministic, the "griefer" AA can inspect the mempool/trigger content before its own invocation completes (its bounce decision can depend on `trigger`, `balance`, or state vars) similarly to the front-running scenario described in the report.

This does not directly enable unauthorized spending or double-spend, but it does cause concrete AA fund loss/freezing for the calling chain and a repeatable denial-of-service against legitimate composed AAs, matching the accepted impact categories.

### Likelihood Explanation
Any AA author (an unprivileged actor per the allowed reachability list) can deploy such a griefing AA at zero cost beyond normal AA deployment; no special privilege, race condition, or complex setup is required beyond being a legitimate destination address in a protocol's payment output. Protocols that route to caller/attacker-influenceable destination AAs are the necessary precondition, which is a common, encouraged pattern in ocore (chained/secondary AAs, as demonstrated by the test suite's "chain of AAs" cases). Likelihood is therefore Medium: it requires a victim protocol to forward funds to an AA address that is attacker-controlled or attacker-selectable, but this is a normal and encouraged composition pattern in the AA ecosystem.

### Recommendation
- Do not let a single misbehaving secondary AA's bounce cascade into a full `revert()` of the entire chain by default. Instead, treat a bounced secondary AA the same way `bounce()` treats trigger underfunding: absorb the loss locally (e.g., keep the funds sent to the secondary AA's own bounce_fees consumption) without invalidating the state changes already committed by sibling/ancestor AAs in the chain, when this is safe to do.
- Alternatively/additionally, give upstream AA authors an explicit opt-in "fire-and-forget" semantics for chained payments to arbitrary/attacker-controllable AA addresses (i.e., allow the primary AA's own state changes to be finalized regardless of what the secondary AA does), so an untrusted destination cannot force an atomic rollback of the entire multi-hop transaction.
- At minimum, document clearly (as Connext ultimately did for PromiseRouter) that AA authors composing with attacker-influenceable secondary-trigger addresses must not treat a successful chain completion as guaranteed, and should design bounce_fees/economics assuming griefing secondary AAs exist.

### Proof of Concept
1. Deploy AA `G` ("griefer") whose response always calls `bounce("grief")` (or conditionally, based on observed `balance`/`trigger` data) for the messages it evaluates.
2. Deploy or use an existing composed AA `P` (e.g., patterned after the "chain of AAs" test) whose response message sends payment output to an address it does not fully control/trust (directly, or a caller-supplied destination as in router/aggregator-style AAs).
3. Trigger `P` such that its output routes to `G`.
4. `handleSecondaryTriggers()` (aa_composer.js:1702) invokes `G` as a secondary trigger; `G` bounces.
5. `revert()` (aa_composer.js:1759) is called, rolling back all of `P`'s (and any other upstream AAs') state/balance changes via `ROLLBACK TO SAVEPOINT initial_balances`, discarding the entire chain's work; the original trigger sender only receives back `trigger.outputs - bounce_fees`.

This can be verified conceptually against the existing test `'chain of AAs'` [4](#0-3)  by replacing `secondary_aa`'s messages with an unconditional `bounce()` call and observing that `arrResponses` no longer contains the primary AA's successful state changes, matching the `revert()` code path at aa_composer.js:1743-1783.

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

**File:** test/aa_composer.test.js (L156-252)
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
		t.deepEqual(arrResponses[0].updatedStateVars[primary_address], {
			who: { value: trigger_address + arrResponses[0].objResponseUnit.timestamp },
			initial: { value: trigger_address + arrResponses[0].objResponseUnit.timestamp },
			large_num: { value: 1e15 },
			long_num: { value: 0.000678901234567 },
		});
		t.deepEqual(arrResponses[0].updatedStateVars[secondary_address], {
			who: { value: primary_address + arrResponses[1].objResponseUnit.timestamp },
			initial: { value: trigger_address + arrResponses[1].objResponseUnit.timestamp },
			initial_unit: { value: arrResponses[0].trigger_unit },
			number_of_responses: { value: 1 },
			previous_aa_responses_trigger_address: { value: trigger_address },
			previous_aa_responses_unit: { value: arrResponses[0].response_unit },
			large_num2: { value: 1e15 }, // the same due to loss of precision
			long_num2: { value: 1.00067890123457 }, // rounded to 15 significant digits (but uses cached vars)
		});
		
		t.deepEqual(arrResponses[1].aa_address, secondary_address);
		t.deepEqual(arrResponses[1].bounced, false);
		t.deepEqual(arrResponses[1].response.error, undefined);
		t.deepEqual(arrResponses[1].objResponseUnit.messages.find(function (message) { return (message.app === 'payment'); }).payload.outputs.find(function (output) { return (output.address === trigger_address); }).amount, 37000);
		t.deepEqual(arrResponses[1].updatedStateVars, undefined);
		
		t.deepEqual(storage.assocUnstableUnits, old_cache.assocUnstableUnits);
		t.deepEqual(storage.assocStableUnits, old_cache.assocStableUnits);
		t.deepEqual(storage.assocUnstableMessages, old_cache.assocUnstableMessages);
		t.deepEqual(storage.assocBestChildren, old_cache.assocBestChildren);
		t.deepEqual(storage.assocStableUnitsByMci, old_cache.assocStableUnitsByMci);
		t.end();
	});
});
```
