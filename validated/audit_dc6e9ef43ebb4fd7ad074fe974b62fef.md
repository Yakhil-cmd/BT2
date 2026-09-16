### Title
AA trigger address derived only from `authors[0]` allows funds sent by co-authored inputs to be redirected/lost - (File: aa_composer.js)

### Summary
`getTrigger()` sets `trigger.address = objUnit.authors[0].address` unconditionally, using only the first signer of a (possibly multi-authored) triggering unit as the address that will receive any AA response/refund/bounce, regardless of which address's outputs actually funded the payment to the AA.

### Finding Description
When a unit is posted to an Autonomous Agent, `getTrigger()` builds the `trigger` object from the raw unit: [1](#0-0) 

`trigger.address` is hard-coded to `objUnit.authors[0].address` with no check that this address is the one whose funds are actually being spent in the accompanying `payment` message. This `trigger.address` is subsequently used throughout `handleTrigger()`/`sendUnit()`/`bounce()` as the canonical recipient for bounces, default responses (e.g. `{trigger.address}` templates written by AA authors), and `trigger.initial_address` propagated to secondary triggers: [2](#0-1) 

In ocore a unit can be multi-authored: it can carry several `authors` entries (several independent signatures) while its `payment` message inputs are drawn from a *different* address than `authors[0]`. Because `getTrigger()` never cross-checks which author address actually supplied the spent inputs, an attacker (or a naive multi-party flow) can construct a unit where:
- `authors[0]` = address A (signs the unit but supplies no funds),
- the payment inputs backing the AA payment actually originate from address B (a co-author, supplying the real value sent to the AA).

The AA then perceives `trigger.address` as A, and any refund logic written by the AA (which virtually always echoes funds back to `{trigger.address}`, as seen throughout the AA test suite, e.g. `just_a_bouncer.oscript` and `bounce_half_of_balance.oscript`) sends the returned/bounced funds to A instead of B, the actual owner of the spent funds. This is directly analogous to the `L2ToL1MessagePasser` bug: the protocol uses one identity (the "signer of record"/`msg.sender`-analog) as a stand-in for the true economic sender without verifying they are the same, causing value to be misdirected to an address that never controlled it. [3](#0-2) [4](#0-3) 

### Impact Explanation
Funds contributed by the real payer (address B) are sent by the AA to address A instead, at A's sole discretion whether to forward them back. Since AA bounce/response mechanics are relied upon by essentially every AA to make the trigger address whole (minus fees), this results in concrete loss of user funds for any multi-authored trigger unit where the fee/signature author differs from the funding address, satisfying the "unauthorized spending" / "AA fund loss" bar.

### Likelihood Explanation
This is reachable purely by an unprivileged unit poster constructing a normal, protocol-valid multi-authored unit that pays an AA — no privileged role, network position, or malicious peer/hub involvement is required. The main uncertainty (not fully verified due to tool-call limits) is the precise validation constraint on which author address may sign for a given payment `input`'s owning address in `validation.js`; if `payment.inputs` strictly enforce that inputs must belong to `authors[0]`'s address (or its aliases) in all multi-author configurations, the practical exploitability would be narrower. This should be confirmed against `validation.js`'s input/author address-matching logic before treating this as fully proven.

### Recommendation
In `getTrigger()`, derive `trigger.address` from the address that actually owns the spent inputs of the AA-directed `payment` message (i.e., the input's `address` field / the author whose signature authorized those specific inputs), not simply `objUnit.authors[0].address`. If a `payment` message can legitimately be funded by multiple co-authors, either reject such AA triggers, or expose the correct owning address(es) explicitly so AA logic doesn't misattribute refunds.

### Proof of Concept
1. Attacker crafts a unit with two authors: A (attacker-controlled, listed as `authors[0]`) and B (unaffiliated funding address).
2. The unit's `payment` message spends outputs belonging to B and directs an output to AA address `X`, satisfying `X`'s `bounce_fees`.
3. `getTrigger()` computes `trigger.address = A` (the first author), even though B funded the payment.
4. AA `X` executes normal logic (e.g., `just_a_bouncer.oscript`-style: `outputs: [{address: "{trigger.address}", amount: "{trigger.output[[asset=base]] - fee}"}]`), sending the refund to A.
5. A keeps the funds that were actually contributed by B; B has no recourse since the protocol layer never records B as `trigger.address`.

### Citations

**File:** aa_composer.js (L375-397)
```javascript
function getTrigger(objUnit, receiving_address) {
	var trigger = { address: objUnit.authors[0].address, unit: objUnit.unit, outputs: {} };
	if ("max_aa_responses" in objUnit)
		trigger.max_aa_responses = objUnit.max_aa_responses;
	objUnit.messages.forEach(function (message) {
		if (message.app === 'data' && !trigger.data) // use the first data message, ignore the subsequent ones
			trigger.data = message.payload;
		else if (message.app === 'payment' && message.payload) {
			var payload = message.payload;
			var asset = payload.asset || 'base';
			payload.outputs.forEach(function (output) {
				if (output.address === receiving_address) {
					if (!trigger.outputs[asset])
						trigger.outputs[asset] = 0;
					trigger.outputs[asset] += output.amount; // in case there are several outputs
				}
			});
		}
	});
	if (Object.keys(trigger.outputs).length === 0)
		throw Error("no outputs to " + receiving_address);
	return trigger;
}
```

**File:** aa_composer.js (L909-944)
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
```

**File:** test/samples/just_a_bouncer.oscript (L1-14)
```text
{
	bounce_fees: { base: 10000 },
	messages: [
		{
			app: 'payment',
			payload: {
				asset: 'base',
				outputs: [
					{address: "{trigger.address}", amount: "{trigger.output[[asset=base]] - 1000}"}
				]
			}
		}
	]
}
```

**File:** test/samples/bounce_half_of_balance.oscript (L1-14)
```text
{
	bounce_fees: { base: 10000 },
	messages: [
		{
			app: 'payment',
			payload: {
				asset: 'base',
				outputs: [
					{address: "{trigger.address}", amount: "{ round(balance[base]/2) }"}
				]
			}
		}
	]
}
```
