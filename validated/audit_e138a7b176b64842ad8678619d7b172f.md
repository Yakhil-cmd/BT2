### Title
AA can lose asset holdings without receiving the paired payout when a proportional share rounds to zero — ([File: aa_composer.js])

### Summary
The AA engine silently drops individual payment outputs that evaluate to `0` and removes the enclosing `payment` message if it ends up with no outputs, but it does **not** abort the whole trigger response when a `state` (or other non-payment) message in the same set still remains. This mirrors the reported ProtectionPool bug: a formula-computed transfer amount can round down to zero, and the caller still has their side of the trade "settled" (state variables updated / their deposited asset consumed) even though they receive nothing back.

### Finding Description
In `sendUnit`, before a response unit is assembled, the engine validates and cleans up computed payment outputs: [1](#0-0) 

Each `payment` message has its `0`-amount outputs stripped, and if a `payment` message ends up with zero outputs it is removed entirely. Only if **all** messages in the whole response are removed does the engine treat the trigger as producing no effect (`'no messages after removing 0-outputs'` → `handleSuccessfulEmptyResponseUnit`, verified by the "only 0 output" test): [2](#0-1) 

However, when an AA definition mixes a `payment` message computing a *proportional* payout (e.g. via `round(share * balance[...])`) with a separate `state` message that unconditionally updates accounting variables (e.g. decrementing an "outstanding shares" variable by the full amount the trigger sent in), only the payment message is dropped if its output rounds to zero — the `state` message is not a `payment` message, so it's unaffected by the zero-output filter and is still executed. This exact pattern exists in the shipped sample AA: [3](#0-2) 

Here, `$investor_share = $mm_asset_amount / var['mm_asset_outstanding']` can be small enough that `round($investor_share * balance[$asset])` and `round($investor_share * balance[base])` both evaluate to `0`. Both `payment` messages get filtered out by the engine, but the trailing `state` message (`var['mm_asset_outstanding'] -= trigger.output[[asset=$mm_asset]];`) is unaffected and still runs, permanently reducing `mm_asset_outstanding` by the sender's full share amount while the sender receives neither the underlying asset nor bytes back.

The underlying asset/shares the sender transferred to the AA as part of the trigger are non-refundable in this path: because the response is *not* empty (the state message remains), this is not treated as "no messages", so no bounce/refund occurs — the sender's payment to the AA is simply absorbed.

### Impact Explanation
An AA trigger sender who deposits a small enough amount of a share/LP-style asset can have that asset silently absorbed by the AA (and effectively transferred in value to other shareholders, since the "outstanding" accounting used to compute future payouts shrinks) without receiving any of the paired asset back. This is a direct, unrecoverable fund loss for the trigger sender, matching the Medium-severity impact of the original finding (user loses shares without receiving the underlying).

### Likelihood Explanation
Any unprivileged AA trigger sender can trigger this by sending a small enough amount of the relevant asset (dust relative to `balance[asset]`/`var['mm_asset_outstanding']`) — no special privileges, race conditions, or malicious infrastructure are required. This is purely a function of common oscript formula patterns (`round(share * balance)` used for proportional payouts) combined with core engine behavior for zero-output filtering.

### Recommendation
The engine could help AA authors avoid this class of bug in one of two ways:
1. When a `payment` message ends up with all outputs dropped due to rounding to zero, treat the entire trigger response as failed/bounced (not just remove that message), so state updates tied to the same trigger cannot proceed without the corresponding payment.
2. Alternatively, document/require that AA authors guard state updates with the same zero-check as the payment amount (e.g. `if ($amount == 0) bounce('nothing to pay out');`) before decrementing accounting variables, and provide a lint/validation warning in `aa_validation.js` for AA definitions that decrement balances in a `state` message without a corresponding zero-amount guard on the sibling payment output.

### Proof of Concept
1. Deploy an AA using the pattern in `test/samples/uniswap_like_market_maker.oscript` (or any AA definition following: `payment message with rounded proportional amount` + `state message that unconditionally decrements accounting var by the raw trigger amount`).
2. As a normal user, send `trigger.output[[asset=$mm_asset]]` sized so that `round($investor_share * balance[$asset])` and `round($investor_share * balance[base])` both compute to `0` (this is easy when `var['mm_asset_outstanding']` is large relative to the sent amount).
3. Observe: both `payment` messages are filtered out at `aa_composer.js` lines 1274-1288, but the `state` message decrementing `var['mm_asset_outstanding']` by the full `trigger.output[[asset=$mm_asset]]` still executes, per the response filtering logic — the sender's `mm_asset` is consumed with zero payout, and the AA does not bounce/refund since the response is non-empty.

### Citations

**File:** aa_composer.js (L1274-1288)
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
		if (mci >= constants.pemCurvesFixMci)
			messages = mergeMessagesAndOutputs(messages);
```

**File:** test/aa.test.js (L1024-1074)
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
```

**File:** test/samples/uniswap_like_market_maker.oscript (L67-100)
```text
			{ // divest MM shares 
				// (user is already paying 10000 bytes bounce fee which is a divest fee)
				// the price slightly moves due to fees received and paid in bytes
				if: `{$mm_asset AND trigger.output[[asset=$mm_asset]]}`,
				init: `{
					$mm_asset_amount = trigger.output[[asset=$mm_asset]];
					$investor_share = $mm_asset_amount / var['mm_asset_outstanding'];
				}`,
				messages: [
					{
						app: 'payment',
						payload: {
							asset: "{$asset}",
							outputs: [
								{address: "{trigger.address}", amount: "{ round($investor_share * balance[$asset]) }"}
							]
						}
					},
					{
						app: 'payment',
						payload: {
							asset: "base",
							outputs: [
								{address: "{trigger.address}", amount: "{ round($investor_share * balance[base]) }"}
							]
						}
					},
					{
						app: 'state',
						state: `{
							var['mm_asset_outstanding'] -= trigger.output[[asset=$mm_asset]];
						}`
					},
				]
```
