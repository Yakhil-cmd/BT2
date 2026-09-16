## Finding

### Title
AA state variables are permanently updated even when a computed reward/payment output evaluates to zero, silently dropping the payment - ([File: aa_composer.js])

### Summary
`ocore`'s Autonomous Agent (AA) engine evaluates all `messages` of a triggered AA (including `state` messages that write to `var[...]`) in a single pass, then only afterwards strips zero-amount outputs from `payment` messages. If an AA author writes a message list similar to the vulnerable Solidity pattern (a `payment` message paying out a reward computed at trigger time, plus a separate `state` message that unconditionally updates persistent bookkeeping such as a "last claimed" timestamp or "debt" variable), a trigger that causes the reward amount to evaluate to `0` will still update the state variable, while the actual reward payment silently disappears.

### Finding Description
When an AA is triggered, `handleTrigger()` calls `evaluateAA()` which evaluates the full oscript template, executing all message formulas — including `state` app formulas that write to `stateVars`/`var[...]` — as side effects during formula evaluation [1](#0-0) .

Only after this evaluation does the code post-process the resulting `messages` array: it filters out negative/undefined checks, then explicitly strips zero-amount outputs from `payment` messages: [2](#0-1) 

Critically, this filtering only aborts the whole response (with "no state changes") if it results in an **empty** `messages` array: [3](#0-2) 

If any other, non-payment message (e.g. an independent `state` message) survives, execution proceeds normally: `executeStateUpdateFormula`/state vars already computed during `evaluateAA` are persisted via `fixStateVars()`/`saveStateVars()`, and the unit is built and posted even though the reward `payment` message with its single zero-amount output was already dropped. This is confirmed by the existing test `only 0 output`, which shows that ocore treats "all messages become empty" as the only case that skips state changes: [4](#0-3) . When a payment message is only *one* of several messages (as in `state`+`payment` reward patterns seen throughout the codebase's own AA samples, e.g. withdraw/stake logic that both pays out and updates `var[$key]`) [5](#0-4) , a zero-value payment silently vanishes while the accompanying state update (e.g. debt/balance/"amount_left" bookkeeping) is still committed.

This is the exact analog of the reported Limbo.sol bug: the reward/payment computation is conditioned on a nonzero amount, but the debt/state update happens unconditionally and is not rolled back when the payment output is dropped.

### Impact Explanation
Any AA whose oscript logic pays a reward in one `payment` message and separately records bookkeeping in a `state` message (a very common and idiomatic ocore pattern, as shown in the codebase's own official examples) is exposed: a user (unprivileged trigger sender) can end up having their internal accounting advanced (mark reward as paid, decrement/zero a claimable balance, advance an interest/epoch counter, etc.) without actually receiving the funds, permanently losing access to that reward. This is a fund-loss/freezing bug reachable by any AA-trigger sender interacting with an affected AA, matching the "AA fund loss or freezing" impact category.

### Likelihood Explanation
This requires no special privilege — any address can send a trigger to an AA causing a reward-calculation formula to evaluate to `0` (e.g., staking/depositing/triggering with `amount = 0`, or naturally reaching a state where the computed reward rounds down to zero). Because the vulnerable pattern (separate `payment` + `state` messages) is a standard, encouraged way to write AAs (as evidenced by the project's own oscript samples), the likelihood of real-world AAs containing this pattern is high, and the trigger condition (a zero/rounded-to-zero payout) is easy to reach.

### Recommendation
Ensure that dropping a zero-amount `payment` message (or any output within it) is treated as consistently as dropping all messages: either (a) re-run/gate the `state` message evaluation based on the final, post-filtering set of `payment` outputs rather than evaluating state side effects before filtering, or (b) require AA authors to explicitly guard `state` updates with the same zero-amount condition used for the `payment` outputs, and document/lint against unconditional state updates that assume an accompanying payment amount is nonzero. At minimum, expose a formula-level guarantee (e.g., an `if` filter on the state message itself, or evaluation ordering that recomputes/aborts state changes when the correlated payment output was removed for being zero) so that debt/accounting variables cannot advance independently of the payment they are meant to track.

### Proof of Concept
1. Deploy an AA whose `messages` are:
   - `payment` message paying `trigger.data.amount` (or a formula that can evaluate to `0`, e.g. computed reward) to `trigger.address`.
   - A separate `state` message that unconditionally does `var['debt_' || trigger.address] = 0;` (marking the reward as claimed) or increments `var['last_claimed_ts']`.
2. Send a trigger unit where the reward-amount formula evaluates to `0` (e.g. `trigger.data.amount = 0`, mirroring `stake(amount=0)`).
3. Observe (per `aa_composer.js:1274-1286`) that the `payment` message's sole output is stripped for being `<= 0`, but because the `state` message remains non-empty, `messages.length !== 0`, so the AA response proceeds: the `state` update commits (debt cleared / timestamp advanced) while no `payment` message is sent to the user.
4. The test `only 0 output` in `test/aa.test.js` demonstrates the filtering behavior described; extending it to include a co-existing `state` message (instead of a lone `payment` message) reproduces the fund-loss scenario since the "no messages after removing 0-outputs" early-exit is not triggered when other message types are present.

### Citations

**File:** aa_composer.js (L1274-1286)
```javascript
			// negative or fractional
			if (!payload.outputs.every(function (output) { return (isNonnegativeInteger(output.amount) || output.amount === undefined); }))
				return bounce("negative or fractional amounts");
			// filter out 0-outputs
			payload.outputs = payload.outputs.filter(function (output) { return (output.amount > 0 || output.amount === undefined); });
		}
		// remove messages with no outputs
		messages = messages.filter(function (message) { return (message.app !== 'payment' || message.payload.outputs.length > 0); });
		if (messages.length === 0) {
			error_message = 'no messages after removing 0-outputs';
			console.log(error_message);
			return handleSuccessfulEmptyResponseUnit(null);
		}
```

**File:** aa_composer.js (L1865-1868)
```javascript
		evaluateAA(arrDefinition, function (err) {
			if (err)
				return bounce(err);
			var messages = template.messages;
```

**File:** test/aa.test.js (L1024-1075)
```javascript
test.cb.serial('only 0 output', t => {
	var db = require("../db");
	var batch = kvstore.batch();
	var stateVars = {};
	var objMcUnit = {
		unit: 'DTDDiGV4wBlVUdEpwwQMxZK2ZsHQGBQ6x4vM463/uy8=',
		last_ball_unit: 'oXGOcA9TQx8Tl5Syjp1d5+mB4xicsRk3kbcE82YQAS0=',
		last_ball: 'oXGOcA9TQx8Tl5Syjp1d5+mB4xicsRk3kbcE82YQAS0=',
		witness_list_unit: 'oj8yEksX9Ubq7lLc+p6F2uyHUuynugeVq4+ikT67X6E=',
		timestamp: 1.5e9+100,
	};
	storage.assocStableUnits[objMcUnit.unit] = {};
	var trigger = { address: 'TU3Q44S6H2WXTGQO6BZAGWFKKJCF7Q3W', outputs: { base: 40000 }, data: { x: 333 }, unit: objMcUnit.unit};
	var arrResponseUnits = [];
	var aa = ['autonomous agent', {
		bounce_fees: { base: 10000 },
		messages: [
			{
				app: 'payment',
				payload: {
					asset: 'base',
					outputs: [
						{address: "{trigger.address}", amount: "{trigger.output[[asset=base]] * 0}"}
					]
				}
			}
		]
	}];
	var address = objectHash.getChash160(aa);
	db.takeConnectionFromPool(conn => {
		conn.query('BEGIN');
		conn.query("INSERT INTO aa_addresses (address, definition, unit, mci) VALUES(?, ?, ?, ?)", [address, JSON.stringify(aa), objMcUnit.last_ball_unit, 500]);
		conn.query("INSERT INTO outputs (unit, message_index, output_index, address, amount) VALUES(?, 0, 5, ?, ?)", [objMcUnit.unit, address, trigger.outputs.base]);
		conn.query("DELETE FROM aa_responses WHERE trigger_unit=? AND aa_address=?", [trigger.unit, address]);

		var objUnit;
		writer.saveJoint = function (objJoint, objValidationState, preCommitCallback, onDone) {
			console.log("mock saving unit", JSON.stringify(objJoint, null, '\t'));
			objUnit = objJoint.unit;
			onDone();
		}
		
		aa_composer.handleTrigger(conn, batch, trigger, {}, stateVars, aa, address, 600, objMcUnit, false, arrResponseUnits, (objResponseUnit, bounce_message) => {
			conn.query('ROLLBACK', () => {
				conn.release();
			});
			t.deepEqual(bounce_message, 'no messages after removing 0-outputs, then no state changes');
			t.deepEqual(objUnit.messages.find(function (message) { return (message.app === 'payment'); }).payload.outputs.find(function (output) { return (output.address === trigger.address); }).amount, 30000);
			t.end();
		});
	});
});
```

**File:** test/samples/a_bank_without_percent.oscript (L1-30)
```text
{
	messages: {
		cases: [
			{ // withdraw funds
				if: `{
					$key = 'balance_'||trigger.address||'_'||trigger.data.asset;
					$base_key = 'balance_'||trigger.address||'_'||'base';
					$fee = 1000;
					$required_amount = trigger.data.amount + ((trigger.data.asset == 'base') ? $fee : 0);
					trigger.data.withdraw AND trigger.data.asset AND trigger.data.amount AND $required_amount <= var[$key] AND $fee <= var[$base_key]
				}`,
				messages: [
					{
						app: 'payment',
						payload: {
							asset: "{trigger.data.asset}",
							outputs: [
								{address: "{trigger.address}", amount: "{trigger.data.amount}"}
							]
						}
					},
					{
						app: 'state',
						state: `{
							var[$key] = var[$key] - trigger.data.amount;
							var[$base_key] = var[$base_key] - $fee;
						}`
					}
				]
			},
```
