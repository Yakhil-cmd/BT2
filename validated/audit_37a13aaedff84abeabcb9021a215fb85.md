### Title
Malicious secondary-trigger AA can force full revert of a primary AA's payout batch, blocking/losing funds for all other recipients in the same trigger - (File: aa_composer.js)

### Summary
When a primary AA sends payment outputs to multiple addresses in a single trigger response, every output address that is itself an AA is invoked as a "secondary trigger" via `handleSecondaryTriggers` [1](#0-0) . If any one of these secondary AAs bounces, `async.eachSeries`'s error callback calls `revert(...)`, which rolls the entire primary trigger back to `SAVEPOINT initial_balances`, discarding all state changes and payouts made to every other (honest) recipient processed as part of the same primary trigger [2](#0-1) [3](#0-2) .

### Finding Description
This is directly analogous to the Y2K `Carousel.sol` bug: a queue/batch of independent beneficiaries is processed together, and a single malicious "receiver" (there, an ERC1155 recipient whose `onERC1155Received` hook always reverts; here, an AA address controlled by the attacker that deliberately bounces on receipt) can force the whole batch operation to fail atomically, wiping out state/fund changes intended for unrelated, innocent parties.

In ocore, whenever an AA sends bytes/assets to output addresses as part of its response, any output address that resolves to a defined AA is automatically re-triggered as a "secondary trigger" (`handleSecondaryTriggers`, `arrOutputAddresses`) [4](#0-3) . The secondary triggers are executed in series with `async.eachSeries`, and the very first bounce from any of them aborts the loop with an error [5](#0-4) . That error propagates to:
```
return revert({message: "one of secondary AAs bounced with error: ", callChain: {address, next: err}});
``` [6](#0-5) 

`revert()` clears all in-progress `arrResponses`, deletes all pending `stateVars`, and issues `ROLLBACK TO SAVEPOINT initial_balances`, unwinding every state change and payout produced by the primary trigger's execution up to that point — including outputs that were already correctly delivered/queued for other, unrelated recipients in the same response — and then bounces the entire primary trigger [3](#0-2) .

Because any user can define and post an AA (an "adversary can post a trigger" or, here, simply define a receiving AA that is reachable as an output address of another shared AA — e.g., a shared distributor/vault/market AA that pays multiple recipients based on user-supplied or state-driven addresses), an attacker can:
1. Deploy a trivial AA whose logic unconditionally `bounce()`s any trigger it receives.
2. Arrange (or wait) for a shared/batch-paying AA to include that malicious AA's address among the outputs of a single response (this is common for any AA design that fans out payments to many addresses in one trigger, analogous to a "deposit/rollover queue" that processes several users' funds together).
3. As soon as that malicious AA receives its payment as a secondary trigger, it bounces, forcing `revert()` on the whole primary trigger — which then discards the payouts/state updates intended for every other, honest recipient processed in that same batch.

This mirrors the reported root cause precisely: an unconditionally-reverting "receiver" injected into a shared processing path can DoS the entire batch and, combined with any "first-processed, all-affected" fan-out logic, cause loss/freezing of funds for other participants whose legitimate transfers get rolled back.

### Impact Explanation
Any AA that fans out payments/state changes to multiple addresses within a single trigger response (a common and encouraged oscript pattern — dividend distributors, vaults, exchanges paying out to several parties, "51%-attack"-style games, market makers, etc.) is vulnerable: if any output address happens to be (or can be made to be) an always-bouncing AA, the entire primary trigger — and all of its intended effects for unrelated honest addresses — is reverted. This can result in AA fund loss/freezing (payouts that should have gone through are discarded/blocked) and repeated denial of service against any AA design that batches multiple beneficiaries per trigger, matching the "Medium/High" bar of concrete AA fund loss or freezing.

### Likelihood Explanation
Exploitability requires only that the attacker be able to define an ordinary AA (permissionless) and get it included as one of several output addresses handled within a single primary trigger of a shared/batch-processing AA — a normal and encouraged pattern in oscript for multi-recipient payouts. No privileged access, node compromise, or network-level behavior is needed; a single crafted secondary AA and a single trigger unit posted to the victim AA are sufficient.

### Recommendation
Do not let the failure of one secondary (fan-out) AA trigger abort/rollback the entire primary trigger's already-computed state changes and payouts for unrelated recipients. Options:
- Isolate each secondary trigger's execution/rollback scope so that a bounce in one secondary AA rolls back only that secondary AA's own effects (and possibly the funds sent to it, returned to the primary AA or held/refundable), rather than reverting the whole primary trigger via `SAVEPOINT initial_balances`.
- Alternatively, require primary AAs to explicitly acknowledge/opt into "fail-together" semantics only where atomicity across the whole batch is actually desired, and otherwise process each output address's secondary trigger independently, capturing bounce results per-recipient rather than propagating a single `err` through `async.eachSeries` that reverts everything in `handleSecondaryTriggers`/`revert()` [2](#0-1) .

### Proof of Concept
1. Define AA `Malicious`: `{ messages: { cases: [{ if: "{true}", messages: [{ app: 'state', state: "{ bounce('always fail'); }" }] }] } }` — an AA that bounces on every trigger.
2. Define/identify a "batch payout" AA `Distributor` whose response, for a single primary trigger, sends payment outputs to multiple addresses (e.g., several depositors/beneficiaries) in one message, including a way to route or discover `Malicious`'s address as one of the outputs (directly, e.g. as one of the paid addresses, or by getting oneself added to the distribution set beforehand).
3. Post a unit that triggers `Distributor` such that its response includes an output to `Malicious`.
4. `handleSecondaryTriggers` invokes `Malicious` as a secondary trigger; it bounces immediately [7](#0-6) .
5. `async.eachSeries`'s error handler calls `revert(...)`, rolling back `SAVEPOINT initial_balances` and discarding all of `Distributor`'s intended payouts/state changes for every other (honest) recipient in that trigger [8](#0-7) .

### Citations

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

**File:** aa_composer.js (L1702-1717)
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
