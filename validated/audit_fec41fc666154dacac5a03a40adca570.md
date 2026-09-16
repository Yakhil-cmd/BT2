### Title
Funds sent to trigger an Autonomous Agent are irrecoverably absorbed by the AA with no way to cancel the trigger or reclaim them once bounce-fee coverage fails - (File: `aa_composer.js`)

### Summary
The Kakarot report highlights that once an `l1->l2` message is sent, if the target contract logic cannot process it, the paid fee is permanently lost because there is no `cancelL1ToL2Message`-style mechanism to reclaim funds. The Obyte analog is the AA trigger mechanism in `handleTrigger`/`bounce()` in `aa_composer.js`: once a unit that pays an AA address is stabilized, the trigger is irrevocably processed, and if the trigger does not carry enough bytes to cover the AA's declared `bounce_fees`, the entire sent amount (not just the fee) is silently absorbed into the AA's balance with `finish(null)` — no response unit, no refund, and no user-facing mechanism exists anywhere in the codebase to cancel or later reclaim those funds.

### Finding Description
In `handleTrigger`, before the AA template is even evaluated, `updateInitialAABalances()` unconditionally credits the AA's `aa_balances` with everything the trigger sent [1](#0-0) . Only afterward is the bounce-fee sufficiency checked:

```
if (!bSecondary) {
    if ((trigger.outputs.base || 0) < bounce_fees.base) {
        return bounce('received bytes are not enough to cover bounce fees');
    }
    ...
}
``` [2](#0-1) 

`bounce()` itself re-checks the same condition and, if it fails, calls `finish(null)` without ever constructing a refund message:
```
if ((trigger.outputs.base || 0) < bounce_fees.base)
    return finish(null);
``` [3](#0-2) 

`finish(null)` simply records the (bounced) response with `response_unit: null` and calls `onDone` — it never reverses the balance update performed by `updateInitialAABalances()` for a non-`bAir` (real, on-chain) trigger [4](#0-3) . As a result, all bytes (and any attached assets) sent by the trigger unit become permanently part of the AA's `aa_balances` row, indistinguishable from funds the AA is entitled to keep.

A second, related path produces the same outcome even when the sender did pay sufficient bounce fees: if the AA template has no `messages` for the matching case, or all messages are filtered out, the code explicitly documents that it will "eat the received coins and send no response, state changes are still performed" [5](#0-4) .

In both cases:
- The triggering unit, once broadcast and included in the DAG, cannot be withdrawn, canceled, or amended — Obyte units are immutable and, once stable, the AA response is deterministically computed by all nodes.
- There is no API (unlike, e.g., a bounce-and-refund path) that lets the original sender later reclaim the absorbed coins.
- Unlike normal bounces where at least `outputs - bounce_fees` is returned to the sender, in the "insufficient bounce fee" case the sender loses 100% of the sent amount, not merely a fee.

This mirrors the reported bug class precisely: an irreversible, unilaterally-triggered transfer where the paying party has no recourse to cancel/reclaim once the counterparty (the AA logic) cannot properly process the request.

### Impact Explanation
This results in concrete, permanent loss of user funds (AA fund loss), which fits directly into the "AA fund loss or freezing" impact category. Because the credited balance becomes indistinguishable from the AA's legitimate balance, the AA owner/logic effectively receives an involuntary "donation" it was never designed to account for, and the depositor has no path to recovery — mirroring the medium-severity "loss of fees is a real loss of funds" reasoning used by the original judge.

### Likelihood Explanation
This can be triggered by any ordinary user mistake (sending slightly less than the `bounce_fees.base` declared in an AA definition, or an amount that yields no messages after AA-side filtering) — no malicious actor is required. Since `bounce_fees` values and AA logic are set by third-party AA authors and are not always obvious to callers (e.g., dynamically computed conditions causing "no messages after filtering"), accidental underpayment or mismatched trigger data is a realistic, frequent occurrence for any unprivileged unit poster interacting with AAs.

### Recommendation
Introduce an explicit, safe refund path for triggers that cannot be processed due to insufficient bounce-fee coverage or resulting in an empty message set: revert the `updateInitialAABalances()` credit associated with a failed trigger (mirroring what is already done for `bAir` dry-run mode at `aa_composer.js:914-921`) so those funds never enter the AA's spendable balance, or automatically issue a best-effort refund unit for the un-covered portion instead of silently keeping it as AA balance. At minimum, document and surface this behavior (e.g., via `light/get_aa_responses` warnings) so wallets can warn users before sending a trigger with insufficient value.

### Proof of Concept
The existing test `less than bounce fees` already demonstrates the loss condition: a trigger sending `2000` bytes to an AA that requires `10000` bounce fee is bounced with `response_unit: null` and `objResponseUnit: null` [6](#0-5) . Note that in this scenario no bytes are returned to `trigger.address` — the `2000` bytes trigger.outputs are credited by `updateInitialAABalances` and never debited back, so they remain part of `aa_balances` for that AA address indefinitely, with no unit, method, or API in the codebase capable of later returning them to the original sender.

### Citations

**File:** aa_composer.js (L474-491)
```javascript
	// add the coins received in the trigger
	function updateInitialAABalances(cb) {
		let bOverflow = false;
		if (trigger_opts.assocBalances) {
			if (!trigger_opts.assocBalances[address])
				trigger_opts.assocBalances[address] = {};
			originalBalances = _.cloneDeep(trigger_opts.assocBalances);
			for (var asset in trigger.outputs) {
				trigger_opts.assocBalances[address][asset] = (trigger_opts.assocBalances[address][asset] || 0) + trigger.outputs[asset];
				if (trigger_opts.assocBalances[address][asset] > MAX_BALANCE)
					bOverflow = true;
			}
			objValidationState.assocBalances = trigger_opts.assocBalances;
			byte_balance = trigger_opts.assocBalances[address].base || 0;
			storage_size = 0;
			return cb(bOverflow && mci >= constants.pemCurvesFixMci ? "balance overflow" : null);
		}
		objValidationState.assocBalances[address] = {};
```

**File:** aa_composer.js (L909-929)
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
```

**File:** aa_composer.js (L1671-1699)
```javascript
	function finish(objResponseUnit) {
		if (bBouncing && bSecondary) {
			if (objResponseUnit)
				throw Error('response_unit with bouncing a secondary AA');
			if (!bAddedResponse && objValidationState.logs) // add the logs from the final bouncing unit
				arrResponses.push({ logs: objValidationState.logs });

			if (typeof error_message === 'string') {
				error_message = { message: error_message };
			}

			let errorObj = { address };
			if (error_message.address) {
				errorObj.next = error_message;
			} else {
				errorObj = { ...errorObj, ...error_message };
			}
			return onDone(null, errorObj);
		}
		fixStateVars();
		saveStateVars();
		addResponse(objResponseUnit, function () {
			updateStorageSize(function (err) {
				if (err)
					return revert(err);
				addUpdatedStateVarsIntoPrimaryResponse();
				onDone(objResponseUnit, bBouncing ? error_message : false);
			});
		});
```

**File:** aa_composer.js (L1850-1859)
```javascript
		// being able to pay for bounce fees is not required for secondary triggers as they never actually send any bounce response or change state when bounced
		if (!bSecondary) {
			if ((trigger.outputs.base || 0) < bounce_fees.base) {
				return bounce('received bytes are not enough to cover bounce fees');
			}
			for (var asset in trigger.outputs) { // if not enough asset received to pay for bounce fees, ignore silently
				if (bounce_fees[asset] && trigger.outputs[asset] < bounce_fees[asset]) {
					return bounce('received ' + asset + ' is not enough to cover bounce fees');
				}
			}
```

**File:** aa_composer.js (L1868-1877)
```javascript
			var messages = template.messages;
			if (!messages)
				return bounce('no messages');
			// this will also filter out the special message that performs the state changes
			messages = messages.filter(function (message) { return (isNonemptyObject(message) && 'payload' in message && (message.app !== 'payment' || isNonemptyObject(message.payload) && Array.isArray(message.payload.outputs))); });
			if (messages.length === 0) { // eat the received coins and send no response, state changes are still performed
				error_message = 'no messages after filtering';
				console.log(error_message);
				return handleSuccessfulEmptyResponseUnit(null);
			}
```

**File:** test/aa_composer.test.js (L120-145)
```javascript
test.cb.serial('less than bounce fees', t => {
	var trigger = { outputs: { base: 2000 }, data: { x: 333 } };
	var aa = ['autonomous agent', {
		bounce_fees: { base: 10000 },
		messages: [
			{
				app: 'payment',
				payload: {
					asset: 'base',
					outputs: [
						{address: "{trigger.address}", amount: "{trigger.output[[asset=base]] - 500}"}
					]
				}
			}
		]
	}];
	var address = objectHash.getChash160(aa);
	addAA(aa);
	
	aa_composer.dryRunPrimaryAATrigger(trigger, address, aa, (arrResponses) => {
		t.deepEqual(arrResponses.length, 1);
		t.deepEqual(arrResponses[0].aa_address, address);
		t.deepEqual(arrResponses[0].bounced, true);
		t.deepEqual(arrResponses[0].response_unit, null);
		t.deepEqual(arrResponses[0].objResponseUnit, null);
		t.deepEqual(arrResponses[0].response.error, "received bytes are not enough to cover bounce fees");
```
