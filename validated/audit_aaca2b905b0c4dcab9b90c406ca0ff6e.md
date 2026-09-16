### Title
Single malfunctioning or malicious secondary AA permanently DOS's any primary AA that must pay it - (File: `aa_composer.js`)

### Summary
`handleSecondaryTriggers()` in `aa_composer.js` invokes every AA that receives an output from a response unit as a mandatory "secondary trigger," using `async.eachSeries`. If **any** secondary AA in that batch bounces, the entire chain — including the primary AA's own state changes and response — is reverted. There is no mechanism to skip, quarantine, or "bypass" a failing recipient AA, so a primary AA that is designed to always route funds to a fixed set of sub-AAs (an oscript analog of the DynamoFinance vault's adapter list) can be permanently denied service by a single misbehaving or malicious recipient AA.

### Finding Description
When a primary AA's response unit sends outputs to other AA addresses, `sendUnit()` collects those addresses (`arrOutputAddresses`) and calls `handleSecondaryTriggers()`. [1](#0-0) 

`handleSecondaryTriggers()` looks up all AAs among the output addresses and triggers each of them in series via `handleTrigger()`: [2](#0-1) 

If any of these secondary AA invocations bounces, the `async.eachSeries` completion callback calls `revert()` for the whole primary-trigger execution chain: [3](#0-2) 

`revert()` rolls back all state variable changes, forgets all response units already generated in this call chain, and rolls the DB back to the initial savepoint, then bounces the primary trigger: [4](#0-3) 

This atomic all-or-nothing semantics is analogous to `FundsAllocator.vy`'s loop over `_pool_balances`/adapters: just as a single reverting adapter call blocks the whole rebalance, a single deterministically-bouncing secondary AA blocks the whole primary AA's execution, with no bypass path in `aa_composer.js`. If a primary AA's template unconditionally sends part of its payout to a set of sub-AA addresses (e.g., a distributor/vault-like AA that always pays several fixed "adapter" AAs, mirroring the vault's adapter list pattern), and one of those sub-AAs is malfunctioning (bug causing it to always bounce) or deliberately malicious (its owner intentionally makes it always fail, e.g. via a `bounce()`/`require()` formula call whose condition can never be satisfied), then **every** trigger to the primary AA will revert forever. Users who send funds to the primary AA to invoke its main functionality will have their triggers bounced indefinitely, and the primary AA's state (and thus all its normal operations) is permanently unusable while that recipient AA is in the payout path.

### Impact Explanation
This causes permanent freezing/denial of service of any primary AA whose logic requires (unconditionally, as part of its `messages` template) paying out to a fixed set of other AA addresses. Legitimate users' funds sent to trigger the AA are perpetually bounced (minus bounce fees), and any distributor/aggregator-style AA design that fans out payments to several sub-AAs (the oscript analog of the vault's pluggable adapters) can be bricked by a single bad actor or a single buggy AA in that set — matching the "AA fund loss or freezing" and "node disagreement/network unable to confirm new units for this AA's purpose" impact categories.

### Likelihood Explanation
Any unprivileged AA author can deploy a secondary AA and get it referenced as a mandatory payout recipient of another AA (directly, if they control both AAs' addresses being used in a distribution scheme, or indirectly, if a distributor/vault-style AA allows governance/config to add new recipient AA addresses over time, similar to the vault's adapter list). The only requirement is that the secondary AA's bounce condition be deterministic (always true), which is trivial to construct with `bounce_fees` and an always-failing `require`/formula condition. No special privilege beyond normal AA deployment and posting a triggering unit is needed.

### Recommendation
Introduce a mechanism in `aa_composer.js`'s `handleSecondaryTriggers()`/`revert()` path to isolate failures of individual secondary AAs from the rest of the chain instead of unconditionally reverting the whole primary-trigger execution — for example, allow the primary AA's messages/template to explicitly mark certain outgoing payments as "best-effort," or expose to the primary AA that a specific secondary trigger bounced so that its own logic (or a follow-up governance-controlled mechanism) can react without losing all other completed work in the same trigger chain.

### Proof of Concept
1. Deploy `secondary_aa` whose template includes a `bounce_fees` and a message with a `require` (or any deterministic bounce condition) that always fails, e.g. `require($x == 1 && $x == 2, "always bounce")`.
2. Deploy `primary_aa` whose `messages` template unconditionally includes a payment output to `secondary_address` (analogous to a vault always paying its adapters) alongside its normal state-update logic, similar to the "chain of AAs" pattern shown in the test: [5](#0-4) 
3. Any user sends a triggering payment to `primary_aa`.
4. `sendUnit()` builds the response unit, then calls `handleSecondaryTriggers()`, which invokes `secondary_aa`; it deterministically bounces.
5. `handleSecondaryTriggers` propagates the bounce error to `revert()`, which rolls back all of `primary_aa`'s state changes and response unit and bounces the whole trigger back to the sender.
6. Every subsequent trigger to `primary_aa` repeats steps 3–5 indefinitely — `primary_aa` is permanently denied service as long as `secondary_address` remains in its mandatory payout path.

### Citations

**File:** aa_composer.js (L1411-1420)
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
										});
```

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

**File:** test/aa_composer.test.js (L190-214)
```javascript
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
