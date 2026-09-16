### Title
Fund loss on bounce when insufficient amount of one asset aborts refund of all other assets - (File: aa_composer.js)

### Summary
The `bounce()` function inside `handleTrigger` in `aa_composer.js` computes bounce (refund) payment messages by iterating over every asset present in `trigger.outputs`. If any single asset's received amount is smaller than the `bounce_fees` configured for that asset, the function immediately returns without sending any messages at all — discarding the refund messages already built for other assets (including base bytes) that were fully sufficient to cover their own bounce fee.

### Finding Description
`handleTrigger` computes `bounce_fees` from the AA template (`template.bounce_fees || {base: constants.MIN_BYTES_BOUNCE_FEE}`) [1](#0-0) . Before attempting the AA logic, it verifies the trigger carries at least the base bounce fee and, for each asset explicitly listed in `bounce_fees`, that the received amount for that asset is not smaller than its configured fee [2](#0-1) .

When the AA logic itself calls `bounce(error)` (e.g., because a state-update formula throws, or an oscript `bounce()` call fires), the refund logic in `bounce()` iterates `trigger.outputs` per asset:
```
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
``` [3](#0-2) 

The upfront guard only enforces `trigger.outputs.base >= bounce_fees.base` [4](#0-3) ; for non-base assets it only rejects if `bounce_fees[asset]` is explicitly set and the received amount is below it, and this rejection happens by calling `bounce()` again (already bouncing) or, on the initial pre-check, `return bounce(...)`. In that pre-check path, `bounce()` is invoked with the same trigger, so the same per-asset loop executes: the loop builds a `bounced_amount` message for `base` (since `trigger.outputs.base >= bounce_fees.base`), but then hits the insufficient custom asset and does `return finish(null)` — throwing away the already-built base-refund message. The result: `sendUnit` is never called, so **no bounce/refund unit is created at all**, and the sender's base bytes (which were sufficient to be refunded) are silently absorbed by the AA along with the insufficient custom-asset amount, with `finish(null)` returning no response unit to the network.

This mirrors the reported bug class: a partial insufficiency (one asset short of its "fee") causes total loss of funds that would otherwise have been refundable, rather than a partial/graceful settlement.

### Impact Explanation
Any unprivileged unit poster who triggers an AA with a multi-asset payment (base bytes plus a custom asset that the AA's `bounce_fees` also covers) can have their entire trigger payment consumed by the AA with zero refund and zero response unit, whenever the AA's logic bounces (validation failure, formula `bounce()`, insufficient AA balance, etc.). Legitimate senders lose both their custom-asset payment and their base bytes even though the base bytes alone were fully sufficient to be bounced back per the AA's own declared bounce-fee policy. This is a concrete, unauthorized loss of user funds at the AA layer, matching "Medium" severity impact criteria (asset loss under a specific but reachable condition), analogous to the L1LPTGateway finding where partial fee shortfall caused total loss of the transferred value.

### Likelihood Explanation
This requires only that (a) the AA's `bounce_fees` template define a fee for a non-base asset, and (b) an unprivileged trigger sender's outbound trigger includes that asset in an amount below the declared fee while sending base bytes above the base fee, and (c) the AA subsequently bounces (e.g., invalid trigger data, a formula that calls `bounce()`, or insufficient stored balance to satisfy the response). Such multi-asset AAs (e.g., token exchanges, wrapped-asset bridges) are common in the AA ecosystem, and users interacting with an unfamiliar AA can easily misestimate the correct amount for a secondary asset, making the likelihood non-trivial though not universal — similar to the "low but non-zero probability" characterization in the original finding.

### Recommendation
Change the semantics of `bounce()` so that an asset failing to meet its bounce fee does not abort refunds for other assets that did meet their fee. Options:
- Skip (rather than abort) the under-funded asset in the loop (e.g., `continue`, optionally keeping the shortfall balance for the AA) while still emitting bounce messages for assets that meet their fee, ensuring `sendUnit(messages)` still runs when at least the base fee is satisfied.
- Alternatively, enforce per-asset sufficiency for all bounce_fees-covered assets at the initial pre-check stage (before considering the trigger valid) rather than deferring the loss to a later bounce call, and reject/ignore only the deficient asset's refund instead of the whole unit.

### Proof of Concept
1. An AA is defined with:
```
bounce_fees: { base: 10000, ASSETXYZ: 5000 }
```
2. An unprivileged user sends a trigger unit to this AA containing:
   - a base-bytes payment output of 40000 (well above `bounce_fees.base`)
   - an `ASSETXYZ` payment output of 1000 (below `bounce_fees.ASSETXYZ`)
3. The AA's oscript logic determines the trigger is invalid for its intended purpose and calls `bounce("invalid request")`, or the formula itself throws, invoking `bounce()` in `handleTrigger` [5](#0-4) .
4. Inside `bounce()`, the loop first computes a valid `bounced_amount` message for `base` (40000 - 10000 = 30000), then reaches `ASSETXYZ`, finds `fee (5000) > amount (1000)`, and executes `return finish(null)` — discarding the already-built base refund message.
5. `sendUnit` is never invoked; no response unit is produced. The sender's full 40000 bytes and 1000 units of `ASSETXYZ` are consumed by the AA address with no refund, even though the base amount alone satisfied the AA's own declared bounce-fee requirement.

### Citations

**File:** aa_composer.js (L446-448)
```javascript
	var bounce_fees = template.bounce_fees || {base: constants.MIN_BYTES_BOUNCE_FEE};
	if (!bounce_fees.base)
		bounce_fees.base = constants.MIN_BYTES_BOUNCE_FEE;
```

**File:** aa_composer.js (L910-945)
```javascript
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
	}
```

**File:** aa_composer.js (L1851-1859)
```javascript
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
