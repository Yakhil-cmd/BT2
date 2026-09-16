## Analysis

This maps to a genuine analog in `ocore`'s Autonomous Agent (AA) execution engine, in the file `aa_composer.js`.

### Title
Malicious secondary-AA recipient can force revert of an entire primary AA response, destroying legitimate payouts bundled in the same batch - (File: `aa_composer.js`)

### Summary
When a primary AA sends payment outputs to multiple addresses in a single response (a common pattern for batch payouts — the exact analog of Carousel's queued multi-user minting), any output address that is itself a registered AA is automatically triggered as a "secondary trigger" via `handleSecondaryTriggers`. If that secondary AA bounces for any reason (including an attacker-controlled AA that is coded to unconditionally `bounce`), the error propagates and causes the *entire* primary trigger's execution to be reverted — wiping out every other output/state change bundled in that same response, not just the payment to the malicious address.

### Finding Description
`handleSecondaryTriggers` iterates over all AA output addresses of a response with `async.eachSeries` and recursively calls `handleTrigger` for each one: [1](#0-0) 

If a secondary AA bounces, its `onDone` callback passes the bounce message as an error into the `async.eachSeries` completion handler: [2](#0-1) 

For the primary (non-secondary) trigger, any such error from a secondary AA causes the whole primary response to be discarded via `revert(...)`, rather than just skipping/failing that one output: [3](#0-2) 

`revert()` then clears **all** state-variable changes and **all** accumulated responses for the entire trigger chain, and forces the primary trigger to fall back to a mere bounce/refund to the original trigger sender: [4](#0-3) 

The code even documents that a bouncing secondary trigger doesn't need its own bounce-fee coverage because "they never actually send any bounce response or change state when bounced" — confirming that the *cost* of a secondary bounce is entirely borne by the primary trigger/response, not by the malicious secondary AA itself: [5](#0-4) 

This is structurally identical to the reported Carousel bug class: a single uncooperative/malicious entry in a batch of recipients (there: an ERC1155 receiver that reverts; here: an AA that always bounces) causes the entire multi-recipient operation to fail, at the expense of all the other legitimate recipients bundled in the same call/response.

### Impact Explanation
Any AA design that pays out to multiple addresses in one response — e.g. a lottery, vault, DEX, or a batch-withdrawal-processing AA that iterates over several pending requests and pays them all in the same trigger response (the direct oscript analog of `mintDepositInQueue`) — is vulnerable if one of the payout addresses can be influenced to be (or is) a registered AA that always bounces. An attacker only needs to:
1. Deploy a trivial AA whose only logic is `bounce("grief")`.
2. Get that address included as one of the outputs of a victim AA's batch response (e.g., by registering as a withdrawal recipient, or by being chosen as a payout target in a permissionless queue/list that the victim AA processes).

Once triggered, the victim AA's entire response — including payments intended for all other, legitimate users in the same batch, and any state updates (accounting, queue removal, balance updates) — is reverted. Depending on the victim AA's logic, this can lead to:
- Denial of service: the batch payout can never complete as long as the malicious AA remains in the recipient set.
- Fund loss/freezing: legitimate users whose withdrawal/payout was bundled with the malicious AA's entry lose their expected payment for that trigger, and the corresponding state (e.g. "already paid" flags) is rolled back, potentially causing double-processing issues or permanent stuck funds if the queue entry itself was consumed prior to the payment attempt in application logic that doesn't get rolled back consistently.

This satisfies "AA fund loss or freezing" from the validation criteria and is reachable by any AA trigger sender / AA author — no privileged role required.

### Likelihood Explanation
Likelihood is high for any AA that implements shared/batch payout logic to multiple potentially-attacker-influenced addresses (lotteries, vaults, escrow/queue-based payout systems, DEX order matching that pays multiple counterparties in one trigger). Deploying a "griefing AA" that always bounces is trivial and costs only the address-definition fee; then getting it included as a payout recipient depends on the specific victim AA's design (e.g., an open deposit/withdrawal queue, a referral payout list, or any place that lets one user's address end up in a batch alongside others).

### Recommendation
- Victim AA authors should avoid architectures where a single trigger response pays out to many independently-controlled addresses that could be arbitrary AAs, or should isolate high-risk/attacker-influenced payouts into separate triggers/responses rather than bundling them with other users' funds.
- At the protocol level, consider making a secondary AA's bounce failure only fail/skip that specific output message chain rather than cascading a full `revert()` of the primary AA's entire response and state changes, so that one malicious secondary AA cannot nullify unrelated legitimate outputs bundled in the same batch. This would require careful accounting so the funds destined for the bounced secondary AA are still recoverable (e.g. returned to the primary AA's balance) without discarding everything else.

### Proof of Concept
1. Deploy `MaliciousAA`:
```
['autonomous agent', {
  bounce_fees: { base: 10000 },
  messages: [{ app: 'payment', payload: { asset: 'base', outputs: [{ address: "{trigger.address}", amount: "{trigger.output[[asset=base]] - 20000}" }] } }],
  init: "{ bounce('always griefing'); }"
}]
```
2. Deploy `VaultAA` that, on a batch-withdrawal trigger, sends outputs to a list of pending withdrawal addresses `A`, `B`, `MaliciousAA` (or lets any user register as a withdrawal recipient, including `MaliciousAA`'s address), and updates state to mark those requests as paid — this mirrors `mintDepositInQueue`'s loop.
3. Trigger `VaultAA` so its response includes payments to `A`, `B`, and `MaliciousAA`.
4. Observe: `handleSecondaryTriggers` fires a secondary trigger to `MaliciousAA`, which bounces; per `aa_composer.js:1743-1750` this is treated as `revert(...)` for the primary trigger; per `aa_composer.js:1759-1783` all state changes and all responses (including the intended payments to `A` and `B`) are discarded, and the whole trigger unit collapses into a bounce/refund to the original sender — `A` and `B` receive nothing despite being legitimate, uninvolved recipients. [6](#0-5) [7](#0-6)

### Citations

**File:** aa_composer.js (L1702-1757)
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

**File:** aa_composer.js (L1759-1798)
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
		/*
		conn.query("ROLLBACK", function () {
			conn.query("BEGIN", function () {
				// initial AA balances were rolled back, we have to add them again
				if (!fPrepare)
					fPrepare = function (cb) { cb(); };
				fPrepare(function () {
					updateInitialAABalances(function () {
						console.log('done revert: ' + err);
						bounce(err);
					});
				});
			});
		});*/
	}
```

**File:** aa_composer.js (L1850-1850)
```javascript
		// being able to pay for bounce fees is not required for secondary triggers as they never actually send any bounce response or change state when bounced
```
