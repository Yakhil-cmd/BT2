The strongest reachable analog in this codebase is in `aa_composer.js`'s secondary-trigger cascade, not the network/payment layer. It reproduces the same bug class as the report (one uncooperative recipient blocking a whole batch of transfers) but through Autonomous Agent (AA) trigger chaining rather than an unbounded-gas `receive()`.

### Title
Malicious secondary-trigger AA can force reversal of an entire primary AA response, DoS-ing payouts to all other recipients - (File: aa_composer.js)

### Summary
When a primary AA sends payment outputs to multiple addresses in one response, any output address that is itself an AA becomes a "secondary trigger" that is invoked synchronously as part of finishing the same primary trigger. `handleSecondaryTriggers` processes these secondary triggers with `async.eachSeries`; if **any single** secondary AA bounces, the primary trigger's entire response — including all payments intended for the *other*, well-behaved output addresses — is rolled back via `revert()` and replaced with a bounce. [1](#0-0) 

### Finding Description
`handleSecondaryTriggers(objUnit, arrOutputAddresses)` looks up which output addresses are AA addresses and, for each one, recursively calls `handleTrigger` with `bSecondary=true`: [2](#0-1) 

The completion callback treats a bounce from *any* secondary AA as a fatal error for the whole `async.eachSeries` batch:

```js
child_trigger_opts.onDone = function (objSecondaryUnit, bounce_message) {
    if (bounce_message)
        return cb(bounce_message);
    cb();
};
``` [3](#0-2) 

And the final callback of that `eachSeries`, on error, reverts the *primary* trigger entirely (unless it is itself secondary, in which case it bounces upward):

```js
function (err) {
    if (err) {
        if (bSecondary)
            return bounce(err);
        return revert({message: "one of secondary AAs bounced with error: ", callChain: {address, next: err}});
    }
    ...
}
``` [4](#0-3) 

`revert()` rolls the whole unit of work back to the savepoint taken before the primary trigger began (undoing the already-saved response unit and all balance changes for every output address in the batch), and then calls `bounce()`: [5](#0-4) 

Any user can deploy an AA whose definition unconditionally executes the `bounce` oscript operation, which is a first-class supported operation and legitimately allowed to run in a non-statements-only context: [6](#0-5) 

This is structurally identical to the Sherlock finding: a batch operation (there, the vUSD withdrawal batch to a list of recipient addresses; here, a primary AA's payment fan-out to a list of recipient addresses) is fully reverted because of the failure of a single, attacker-chosen participant in that batch, denying service and funds to every other legitimate participant of the same batch.

### Impact Explanation
Any AA design pattern that pays out to multiple addresses derived from user input in a single response (batch distributions, DEX/exchange payouts, faucets, "send to arbitrary address" wrappers, matching engines that forward proceeds to counterparties, etc.) can be denied entirely by an attacker who:
1. Deploys a trivial AA whose only logic is `bounce(...)`.
2. Gets that AA address included as one of the output addresses of the targeted primary AA's response (e.g., by being a legitimate counterparty/user of the victim AA, or by being named as a payee in one execution among many).

Once that AA address is present in `arrOutputAddresses`, every future primary trigger of the victim AA that routes an output there will have its **entire** response — including outputs and business-logic side effects intended for all other unrelated addresses in the same response — reverted and bounced. This is a denial-of-service on the victim AA's core payout logic and can freeze/misdirect funds meant for unrelated third parties, matching the "AA fund loss or freezing" / "network unable to process" criteria.

### Likelihood Explanation
Deploying an AA that always bounces requires no special privilege — AA definitions are posted by ordinary, unprivileged users via a normal unit, and the `bounce` operation is intentionally exposed to AA authors. Any protocol whose AA design fans out payments to several addresses in one trigger response (a common and encouraged pattern, as shown by the existing "chain of AAs" tests) is exposed. The attacker only needs to become one of the recipient addresses of a shared/batched payout to weaponize this.

### Recommendation
Do not let the failure (bounce) of one secondary-trigger AA revert the state changes/payments intended for sibling output addresses in the same primary response. Options:
- Process each output address's secondary trigger independently, isolating each one's state effects/rollback to only that branch instead of rolling back the whole primary trigger via a global `revert()`.
- Alternatively, require the primary AA author to explicitly opt into "all-or-nothing" semantics, and by default treat a bounced secondary trigger as a bounce affecting only that leg (e.g., returning the leg's funds to the primary AA or its trigger, while still committing all other successful legs and the ledger state for them).

### Proof of Concept
1. Deploy `attacker_aa = ['autonomous agent', { messages: [ { app: 'state', state: '{ bounce("dos"); }' } ] }]`. Any trigger sent to `attacker_aa` unconditionally bounces.
2. Deploy `victim_aa`, an AA whose response, for a given trigger, sends outputs to two addresses in the *same* response — one legitimate user address and `attacker_aa`'s address (e.g., a payout/distribution AA where the attacker registers as one of N payees, similar to `test/aa_composer.test.js`'s "chain of AAs" pattern at lines 156-252 which demonstrates exactly this trigger→secondary-trigger cascade mechanism). [7](#0-6) 
3. Trigger `victim_aa`. `handleSecondaryTriggers` invokes secondary triggers for both output addresses; the one to `attacker_aa` bounces, causing `cb(bounce_message)` in the `eachSeries` loop.
4. The `eachSeries` final callback (since the caller of `handleSecondaryTriggers` is the primary, non-secondary trigger) calls `revert()`, which rolls back to `SAVEPOINT initial_balances` and bounces the entire primary trigger — undoing the payout that was already validated and saved for the legitimate address, even though that leg had no failure of its own. [8](#0-7)

### Citations

**File:** aa_composer.js (L1702-1783)
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

**File:** formula/validation.js (L1278-1284)
```javascript
			case 'bounce':
				// can be used in non-statements-only formulas and non-AAs too
				if (bGetters && !bInFunction)
					return cb("bounce not allowed at top level in getters");
				var expr = arr[1];
				evaluate(expr, cb);
				break;
```

**File:** test/aa_composer.test.js (L156-187)
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
```
