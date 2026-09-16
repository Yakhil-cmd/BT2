## Analysis

The reported bug class — an unprivileged recipient consuming attacker-controlled code execution to grief a batch of outgoing payments (all-or-nothing failure hurting the *other*, honest recipients in the same transaction) — has a direct analog in ocore's Autonomous Agent (AA) engine.

Obyte payments are UTXO outputs, so a plain non-AA address never executes code on receipt (no `receive()`/fallback equivalent), which rules out the literal ETH transfer-griefing pattern. However, when an AA sends a payment to an address that is itself another AA, ocore executes a **secondary trigger** synchronously as part of composing the primary AA's response unit [1](#0-0) . If that secondary AA's execution errors out (bounces), the failure is propagated back through `async.eachSeries` and the **entire primary response — including all other outputs to unrelated, honest recipients in the same message — is reverted**, not just the failed leg:

```
function (err) {
    if (err) {
        // revert
        if (bSecondary)
            return bounce(err);
        return revert({message: "one of secondary AAs bounced with error: ", callChain: {address, next: err}});
    }
    ...
}
``` [2](#0-1) 

`revert()` rolls back all units/state produced by the trigger to the initial savepoint and then calls `bounce()`, which discards the whole batch and returns only the bounce fee to the trigger's original sender: [3](#0-2) [4](#0-3) 

### Title
Malicious AA recipient can permanently DoS/freeze multi-recipient AA payment batches by always bouncing - (File: `aa_composer.js`)

### Summary
An AA that pays out to several addresses in a single response message (e.g. a distribution, staking, airdrop, or auction-settlement AA) is vulnerable to griefing if any of the payout addresses is (or can become) another AA that deterministically bounces. Because ocore composes the whole payment unit atomically and reverts everything if any secondary trigger bounces, one poisoned recipient address can block payouts to all other legitimate recipients in that trigger, indefinitely.

### Finding Description
When `sendUnit()` finishes composing a payment unit, it calls `handleSecondaryTriggers()` for every output address that happens to be a registered AA [5](#0-4) . Each such address is executed as a full secondary AA trigger via `handleTrigger()` inside an `async.eachSeries` loop [6](#0-5) . If any secondary AA in that series returns a bounce, the series callback receives an error and, since the caller is a primary (non-secondary) trigger, the code calls `revert()` [2](#0-1) , which rolls back *all* units and state changes produced so far by the primary trigger (including outputs already validated for the other, unrelated recipients) and finally bounces the primary trigger, refunding only the bounce fee to the trigger's original sender [3](#0-2) .

An attacker who can get their own address included as one of the output addresses of a distribution/payout AA (e.g., by depositing from that address in a crowdfunding/staking-style AA that later pays out pro-rata to all depositors in one batched message) can pre-register that address as an AA whose definition unconditionally bounces (or reliably fails, e.g. by referencing an undefined state var or intentionally calling `bounce()`). From then on, any attempt by the distribution AA to include that poisoned address in an output batch causes the entire response — and therefore the payouts owed to every other honest participant in that same trigger — to be reverted and re-bounced.

### Impact Explanation
This causes fund freezing/DoS for legitimate users: any batched payout that includes the malicious address as a recipient will never successfully post, so honest recipients bundled into the same payment message never receive their funds from that trigger, and the AA's balance remains locked pending a redesign or exclusion of the poisoned address. Because bounce() only returns the bounce fee to the *trigger sender* (not the intended payees), repeated attempts will keep failing identically as long as the AA's payout logic keeps grouping the poisoned address with others in one message, which satisfies the "AA fund loss or freezing" impact criterion.

### Likelihood Explanation
Exploitability depends on the specific AA design: it requires (1) an AA that accepts arbitrary user addresses as future payout recipients (common in staking/vote-reward/airdrop-style AAs) and (2) batches multiple recipients' outputs into one payment message rather than issuing one trigger/output per recipient. Both patterns are natural and commonly used to reduce fees/complexity, and defining a bouncing AA at a chosen address is trivial and cheap for an attacker (deploy once, deposit once to get whitelisted as a recipient). No special privilege is needed beyond being a normal, unprivileged unit poster / AA author.

### Recommendation
- Distribution-style AAs should not group untrusted, externally influenced addresses into the same payment message/output batch; instead, issue one payment output (and hence one potential secondary trigger) per recipient in separate messages/triggers so a single poisoned recipient cannot block payouts to others.
- Alternatively, the AA can maintain a pull-based withdrawal pattern (recipient sends a trigger to withdraw their own share) instead of push-based batch payouts, eliminating the secondary-trigger dependency entirely.
- At the protocol level, consider making a bounce from a secondary AA not force reversion of the entire primary unit's already-computed non-payment side effects/outputs to other addresses, or provide a "best-effort" payment mode where individual bounced legs are dropped rather than reverting the whole batch.

### Proof of Concept
1. Deploy AA `M` whose definition unconditionally bounces, e.g.:
```
{
  messages: [
    { app: 'state', state: "{ bounce('always fail'); }" }
  ]
}
```
2. Deploy/observe a distribution AA `D` that pays out to a list of addresses (e.g., depositors) in a single `payment` message with multiple `outputs`, as illustrated by the batched-output pattern used in `test/samples/send_all.oscript` and `test/aa_composer.test.js` chain-of-AA tests [7](#0-6) .
3. Get address `M` included as one of `D`'s recipients (e.g., register/deposit from `M`'s address before it is redefined as an AA, or have `D` accept arbitrary recipient addresses).
4. Trigger `D`'s payout logic. `sendUnit()` composes the batch payment including an output to `M`; `handleSecondaryTriggers()` invokes `M`'s trigger, which bounces [6](#0-5) ; the `async.eachSeries` error path calls `revert()` [2](#0-1) , discarding the entire payout unit, including outputs meant for all other honest recipients in that batch. [5](#0-4)

### Citations

**File:** aa_composer.js (L909-945)
```javascript
	var bBouncing = false;
	function bounce(error) {
		console.log('bouncing with error', error, new Error().stack);
		objStateUpdate = null;
		error_message = error_message ? (error_message + ', then ' + error) : error;
		if (trigger_opts.bAir) {
			assignObject(stateVars, originalStateVars); // restore state vars
			assignObject(trigger_opts.assocBalances, originalBalances); // restore balances
			if (!bSecondary) {
				for (let a in trigger.outputs)
					if (bounce_fees[a])
						trigger_opts.assocBalances[address][a] = (trigger_opts.assocBalances[address][a] || 0) + bounce_fees[a];
			}
		}
		if (bBouncing)
			return finish(null);
		bBouncing = true;
		if (bSecondary)
			return finish(null);
		if ((trigger.outputs.base || 0) < bounce_fees.base)
			return finish(null);
		var messages = [];
		// iteration order is standardized since ECMAScript 2020
		for (var asset in trigger.outputs) {
			var amount = trigger.outputs[asset];
			var fee = bounce_fees[asset] || 0;
			if (fee > amount)
				return finish(null);
			if (fee === amount)
				continue;
			var bounced_amount = amount - fee;
			messages.push({app: 'payment', payload: {asset: asset, outputs: [{address: trigger.address, amount: bounced_amount}]}});
		}
		if (messages.length === 0)
			return finish(null);
		sendUnit(messages);
	}
```

**File:** aa_composer.js (L1411-1419)
```javascript
								updateFinalAABalances(arrConsumedOutputs, objUnit, function () {
									if (arrOutputAddresses.length === 0)
										return finish(objUnit);
									fixStateVars();
									addResponse(objUnit, function () {
										updateStorageSize(function (err) {
											if (err)
												return revert(err);
											handleSecondaryTriggers(objUnit, arrOutputAddresses);
```

**File:** aa_composer.js (L1702-1742)
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
				},
```

**File:** aa_composer.js (L1743-1750)
```javascript
				function (err) {
					if (err) {
						// revert
						if (bSecondary)
							return bounce(err);

						return revert({message: "one of secondary AAs bounced with error: ", callChain: {address, next: err}});
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

**File:** test/samples/send_all.oscript (L1-30)
```text
{
	messages: {
		cases: [
			{
				if: `{trigger.output[[asset=base]] >= 1e6}`,
				messages: [{
					app: 'payment',
					payload: {
						asset: 'base',
						outputs: [
							{ address: '{trigger.address}' }
						]
					}
				}]
			},
			{
				messages: [{
					app: 'payment',
					payload: {
						asset: 'base',
						outputs: [
							{ address: 'X55IWSNMHNDUIYKICDW3EOYAWHRUKANP', amount: `{round(trigger.output[[asset=base]]/2)}` },
							{ address: '{trigger.address}' }, // no amount here meaning that this output receives all the remaining coins
						]
					}
				}]
			},
		]
	}
}
```
