### Title
Silent loss of rounded-to-zero divestment payouts in AA due to unconditional state decrement combined with 0-output message filtering - (File: aa_composer.js, test/samples/uniswap_like_market_maker.oscript)

### Summary
Autonomous Agents (AAs) written in oscript can compute a payment output amount that rounds to zero (via `round()`/integer division), and `ocore`'s trigger-handling core silently drops any payment message whose computed output is `0`, while other messages in the same response (e.g. `state` messages that unconditionally decrement pooled/outstanding balances) still execute. This reproduces the exact root cause of Sherlock M-35: a reimbursement/redemption amount that rounds to zero is silently dropped instead of triggering an abort/refund, while the accompanying bookkeeping proceeds as if the payment had happened, permanently losing the depositor's funds inside the AA.

### Finding Description
When an AA response is composed, `sendUnit()` first filters every payment message's outputs, dropping any output whose amount evaluated to `0`: [1](#0-0) 

If this filtering empties **all** messages, the whole response is aborted via `handleSuccessfulEmptyResponseUnit`/an automatic bounce, so a trigger consisting of a single payment message whose amount rounds to `0` is safely bounced and the sender is refunded (minus bounce fee), as demonstrated by the `'only 0 output'` unit test: [2](#0-1) 

However, if the case contains **multiple** messages — e.g. a payment message that rounds to `0` alongside a `state` message that unconditionally mutates AA state — only the empty-output payment message is removed from the array (line 1281 filters per-message, not per-case), while the other messages proceed unaffected. This is exactly the pattern used in the bundled reference "Uniswap-like market maker" AA template's "divest MM shares" case, which pays out two proportional shares (asset + bytes) and then unconditionally decrements the pool's outstanding share counter regardless of whether either payout actually happened: [3](#0-2) 

`$investor_share = $mm_asset_amount / var['mm_asset_outstanding']` can be arbitrarily small (a small investor divesting relative to a large outstanding pool), causing `round($investor_share * balance[base])` (or the asset-side payout) to evaluate to `0`. Because the accompanying `outputs.filter(output => output.amount > 0 ...)` logic in `aa_composer.js` silently drops just that one payment output/message while the sibling payment (if non-zero) and the `state` message still execute, `var['mm_asset_outstanding'] -= trigger.output[[asset=$mm_asset]]` unconditionally subtracts the investor's full share tokens even though one leg of their redemption was dropped. The investor's MM shares (which are consumed as the trigger input into the AA, already credited to the AA's balance by `updateInitialAABalances`) are irretrievably spent, and no code path checks "was this leg's payout actually non-zero" before committing the state update — mirroring the exact conditioned-on-nonzero-diff flaw described in M-35.

### Impact Explanation
An investor divesting a fractional/small stake from a market-maker-style AA (or any AA following this common redemption pattern: compute rounded proportional payout + unconditionally decrement pooled counters) can have one or both legs of their redemption silently rounded to zero and dropped, while their contributed shares are permanently consumed by the AA. This is a direct, unrecoverable loss of user funds trapped inside the AA (AA fund loss), reachable by any unprivileged AA trigger sender who structures a small enough divestment trigger — including an attacker deliberately back-running/timing their own small trigger, or triggering this against another party's position indirectly via pool-state manipulation, to extract value at others' expense.

### Likelihood Explanation
The probability of hitting an exact-zero rounding result is low for arbitrary redemptions, but it is trivially and deterministically triggerable by an attacker who chooses `$mm_asset_amount` to make `$investor_share * balance[...]` fall just under `0.5`. Since the trigger amount and pool state are both attacker/observable inputs, this can be engineered on demand rather than relying on chance, similar to how the original Tapioca report treats it as a probability that can nonetheless be forced. This affects any oscript AA (built from or resembling the officially bundled reference templates) that follows the compute-rounded-payment + unconditional-state-update pattern.

### Recommendation
- In `aa_composer.js`, when filtering `0`-amount outputs out of a payment message (lines 1274–1281), the AA's evaluation layer should give oscript authors first-class access to a "was this leg actually paid" signal (e.g. exposing whether an output was dropped) so the accompanying `state` update can be conditioned on it, or
- Update the bundled reference AA templates (e.g. `uniswap_like_market_maker.oscript`, `ico_with_milestones.oscript`, `fundraising_proxy.oscript`) to explicitly guard against zero-rounded payouts before mutating any outstanding/pool counters (e.g. `if ($amount == 0) bounce('nothing to pay')`), consistent with the Tapioca fix of treating the zero-amount branch as a first-class case rather than silently proceeding.

### Proof of Concept
1. Deploy an AA using the "divest MM shares" case from `test/samples/uniswap_like_market_maker.oscript` (lines 67–100).
2. Build up `var['mm_asset_outstanding']` to a large value via normal investments.
3. Send a trigger with `trigger.output[[asset=$mm_asset]]` small enough that `$investor_share = $mm_asset_amount / var['mm_asset_outstanding']` makes `round($investor_share * balance[base])` (or the asset-side payout) evaluate to `0`, while the other leg's `round(...)` is non-zero (so the case doesn't fully self-bounce per `aa_composer.js` lines 1281–1286).
4. Observe: `aa_composer.js`'s output filter (lines 1274–1281) silently drops the empty-output payment message; the `state` message still executes, decrementing `var['mm_asset_outstanding']` by the investor's full contributed `$mm_asset_amount`.
5. The investor's consumed MM shares are gone from the pool's outstanding accounting, but they never received the corresponding payout leg — the funds remain trapped in the AA, unrecoverable by the investor.

### Citations

**File:** aa_composer.js (L1274-1281)
```javascript
			// negative or fractional
			if (!payload.outputs.every(function (output) { return (isNonnegativeInteger(output.amount) || output.amount === undefined); }))
				return bounce("negative or fractional amounts");
			// filter out 0-outputs
			payload.outputs = payload.outputs.filter(function (output) { return (output.amount > 0 || output.amount === undefined); });
		}
		// remove messages with no outputs
		messages = messages.filter(function (message) { return (message.app !== 'payment' || message.payload.outputs.length > 0); });
```

**File:** test/aa.test.js (L1024-1073)
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
