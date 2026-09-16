### Title
A single malicious secondary AA can bounce the entire response chain and DOS payments to all other output recipients of a primary trigger - (File: aa_composer.js)

### Summary
When a primary AA response sends payments to multiple addresses that happen to be other AAs, each of those addresses is invoked as a "secondary trigger" via `handleSecondaryTriggers`. These secondary triggers are executed sequentially with `async.eachSeries`, and if **any single one** of them bounces, the entire primary trigger's response — including payments and state changes already successfully made to the other, innocent secondary AAs — is rolled back via `revert()`. This is directly analogous to M-6: a single fee/output recipient can unilaterally cause the whole multi-party payment operation to fail, denying all other legitimate recipients their expected funds/state changes, exactly as a malicious fee recipient could revert an EVM `mint()` call to DOS the rest of the fee splits.

### Finding Description
`handleTrigger` in `aa_composer.js` processes a unit that triggers an AA. After the primary AA composes its response unit and determines the list of output addresses (`arrOutputAddresses`), it calls `handleSecondaryTriggers`, which looks up which of those addresses are themselves AAs and invokes `handleTrigger` recursively for each one, in series: [1](#0-0) 

If any one of these secondary AA invocations bounces (calls back with a `bounce_message`), the `async.eachSeries` callback receives an error and, since this is not itself a secondary invocation (`!bSecondary`), the code calls `revert()` instead of just continuing or isolating the failure: [2](#0-1) 

`revert()` unconditionally rolls back **all** balance/state changes made during the entire primary trigger's execution — including payments that had already been successfully delivered to the *other*, well-behaved secondary AAs earlier in the `eachSeries` chain — via `ROLLBACK TO SAVEPOINT initial_balances`, and then re-bounces the primary trigger: [3](#0-2) 

Since a secondary trigger's bounce condition is fully controllable by the address owner (they can define an AA whose `bounce_fees`/state logic is engineered to always fail, or that always throws an evaluation error), any address that is one of several payment outputs of a primary AA response can act as a "malicious fee recipient": simply being an AA that always bounces is enough to nullify the whole distribution, exactly mirroring the Sherlock M-6 pattern where any of several fee-receiving parties could revert to DOS the rest.

Compare with the test fixture `chain of AAs`, which demonstrates the normal (non-adversarial) flow where a primary AA forwards funds to a secondary AA which forwards further — the same mechanism that an attacker can weaponize by making one node in the chain always bounce: [4](#0-3) 

### Impact Explanation
Any oscript author designing a primary AA that distributes bytes/assets to multiple downstream AA addresses (marketplace payouts, referral splits, DAO/vault forwarding, multi-recipient reward AAs, etc.) is exposed to a griefing/DOS vector: if even one downstream address is (or later becomes/is redefined as) an AA that always bounces, then:
- The entire primary AA response is rolled back (`revert()` → `ROLLBACK TO SAVEPOINT initial_balances`), so no state changes or payments occur to any of the other legitimate recipients in that trigger's chain.
- The triggering unit itself only receives back the leftover bytes minus the bounce fee (handled by `bounce()`), and the fee/assets intended for distribution are effectively wasted for that unit's execution.
- This can be repeated for every subsequent unit sent to the primary AA, permanently denying the distribution functionality of that AA as long as the malicious downstream AA exists and keeps bouncing, without the malicious party needing any special privilege — they only need to be named as one of the output addresses (e.g., by legitimately registering as a "referrer" or "payee" address whose AA is then swapped to always bounce, or by being chosen for such a role because the primary AA computes it from data feeds/state that the attacker can influence).

This satisfies "AA fund loss or freezing" and denial of the core distribution functionality of an affected AA.

### Likelihood Explanation
Any AA design that fans out payments to more than one address where at least one address is expected to be (or can become) an AA is affected — this is a common oscript pattern (chained AAs, referral/fee-splitting AAs, DAO treasuries). The attacker only needs to control (or get named as) one of the output addresses and define/redefine it as an AA that reliably bounces (e.g., trivially insufficient bounce fee handling or a state formula that always throws). No special privileges, front-running, or race conditions are required — a single crafted AA definition is sufficient, making this straightforward to trigger repeatedly against any vulnerable primary AA.

### Recommendation
Avoid making the primary trigger's entire state/response chain roll back solely because one secondary/downstream AA bounces. Options:
- Isolate secondary-trigger failures per-branch instead of failing the whole `eachSeries` chain: allow other successfully-processed secondary triggers/payments to remain committed, and only mark the failing branch as bounced (already partially represented by `bSecondary` handling in `bounce()`, but the aggregate `revert()` in the primary trigger currently discards everything).
- Alternatively, document/enforce (at the AA-authoring level, e.g., via validation warnings) that AAs which fan out payments to potentially-attacker-controlled or externally-influenced addresses should use a pull-style claim mechanism (a per-recipient claim state var) rather than pushing payments directly to addresses that may resolve to hostile AAs, mirroring the recommended fix in the referenced report.

### Proof of Concept
1. Deploy `PrimaryAA` whose response sends payments to two addresses in the same trigger-derived response unit: `GoodAA` and `EvilAA`.
2. Deploy `EvilAA` such that its response logic always causes a bounce (e.g., an `if` condition that never allows any payment message to survive filtering, or a state formula that throws), while `GoodAA` behaves normally and would otherwise successfully process its inbound payment and produce a legitimate response.
3. Post a trigger unit to `PrimaryAA`. `handleSecondaryTriggers` invokes `GoodAA`'s trigger first (succeeds) then `EvilAA`'s trigger (bounces) via `async.eachSeries` per [5](#0-4) .
4. Because `EvilAA` bounced and this is the primary trigger (`!bSecondary`), `revert({message: "one of secondary AAs bounced with error: ...})` is called per [6](#0-5) , which rolls back to `SAVEPOINT initial_balances`, undoing `GoodAA`'s already-successful state/payment changes, per [7](#0-6) .
5. Result: `GoodAA` never receives its intended funds/state update despite having behaved correctly, and `PrimaryAA`'s trigger unit only produces a bounce response (minus bounce fee) — demonstrating a DOS of the whole distribution caused solely by `EvilAA`.

### Citations

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
