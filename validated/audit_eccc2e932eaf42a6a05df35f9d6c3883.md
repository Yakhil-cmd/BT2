## Analysis

The external report's bug class is: a strict, all-or-nothing transfer mechanism (`safeTransferFrom`) causes value that should be returned to the sender to become permanently stuck when a partial/lenient path is not available. The closest reachable analog in `ocore` is in the AA (Autonomous Agent) **bounce** mechanism, which is triggered whenever a primary AA trigger fails (formula error, unmet business condition, `bounce()` call, etc.) and is meant to refund the sender's excess value above the AA's declared `bounce_fees`. This code is reachable by any unprivileged party who posts a trigger unit to an AA.

### Title
All-or-nothing AA bounce logic permanently forfeits all sent assets (including bytes) when only one asset's amount is below its declared `bounce_fees` - (File: `aa_composer.js`)

### Summary
When a primary AA trigger fails and `bounce()` is invoked, `aa_composer.js` attempts to build refund messages for every asset present in `trigger.outputs`. If *any single asset* sent along with the trigger has an amount smaller than the `bounce_fees` declared for that asset in the AA definition, the entire bounce refund process aborts via `return finish(null)`, discarding refund messages for **all** assets — including bytes that were sufficient to cover `bounce_fees.base`. As a result, the sender permanently loses everything sent in the trigger unit (not just the shortfall asset), and the AA silently absorbs it into its balance forever.

### Finding Description
The relevant code is: [1](#0-0) 

```js
if ((trigger.outputs.base || 0) < bounce_fees.base)
    return finish(null);
var messages = [];
for (var asset in trigger.outputs) {
    var amount = trigger.outputs[asset];
    var fee = bounce_fees[asset] || 0;
    if (fee > amount)
        return finish(null);          // <-- aborts ALL refunds, not just this asset's
    if (fee === amount)
        continue;
    var bounced_amount = amount - fee;
    messages.push({app: 'payment', payload: {asset: asset, outputs: [{address: trigger.address, amount: bounced_amount}]}});
}
if (messages.length === 0)
    return finish(null);
sendUnit(messages);
```

The loop iterates over every asset that was sent in `trigger.outputs`. As soon as it finds one asset where `fee > amount` (i.e., the fee declared in the AA's `bounce_fees` for that asset exceeds the amount actually sent), it calls `return finish(null)` — abandoning the whole bounce, including the bytes refund that would otherwise have been sent (since `trigger.outputs.base` already passed the earlier `bounce_fees.base` check on line 928). The AA still keeps the received funds via `updateInitialAABalances`, which credits `aa_balances` for all `trigger.outputs` unconditionally before `bounce()` is ever reached.

This mirrors the ERC721 report's root cause: a strict all-or-nothing check (`safeTransferFrom`'s receiver-interface requirement / here, the per-asset fee sufficiency check) causes the *entire* value transfer to be voided/trapped instead of gracefully handling only the problematic portion (e.g., forfeiting just the insufficient asset and still returning the bytes and any other sufficiently-fee'd assets).

`aa_addresses.js`'s `checkAAOutputs`/`MissingBounceFeesErrorMessage` is only a client-side, best-effort warning used when *composing* a unit locally — it does not prevent a manually or externally composed unit from reaching the network and triggering this loss: [2](#0-1) 

### Impact Explanation
Any unprivileged user who posts a trigger unit to an AA — sending bytes plus one or more assets — risks total, permanent loss of **all** value sent (not just the under-funded asset) whenever the AA bounces for any reason (a formula error, an unmet `if` condition, insufficient AA balance, `bounce()` calls in the AA's own logic, etc.), as long as at least one asset amount is below the AA's declared `bounce_fees` for that asset. Since AA authors are free to define `bounce_fees` for arbitrary assets, and bounce conditions can be triggered by ordinary usage mistakes or unmet AA preconditions (not just malicious input), this is a systemic fund-loss risk for any counterparty interacting with such AAs, not a hypothetical edge case.

### Likelihood Explanation
Likelihood is moderate-to-high: it requires no special privilege — only that (a) the AA declares `bounce_fees` for a non-base asset, (b) the sender's asset amount is below that fee while bytes exceed `bounce_fees.base`, and (c) the trigger bounces for any reason. AA authors routinely set asset bounce fees for AAs that consume specific tokens (see AA test fixtures using `bounce_fees` with multiple assets), and bounce conditions are common (state preconditions, formula errors). The client-side warning in `checkAAOutputs` reduces likelihood for wallets that use it, but does not eliminate it for AAs whose asset-fee requirements change after a unit was composed, for non-standard wallet clients, or for manually-crafted units.

### Recommendation
Change the bounce logic so that failing the fee-sufficiency check for one asset only forfeits that specific asset's shortfall amount, rather than aborting refund messages for all other assets/bytes that do satisfy their respective bounce fees. E.g., instead of `return finish(null)` on `fee > amount`, simply `continue` (forfeiting only that asset, since `amount <= fee` already means nothing would be refundable for it) while still allowing the loop to build refund messages for bytes and any other assets that are sufficiently funded.

### Proof of Concept
1. Deploy an AA with `bounce_fees: { base: 10000, "<ASSET_HASH>": 1000 }` and a message body whose `if` condition can fail for a legitimate reason (e.g., missing/insufficient AA balance for the response payment).
2. Trigger the AA with a unit sending `20000` bytes and `500` of `<ASSET_HASH>` (below the 1000 fee threshold), where the AA's condition causes `bounce()` to run.
3. Observe: `bounce()` enters the loop, hits `fee (1000) > amount (500)` for `<ASSET_HASH>`, and returns `finish(null)` immediately — no bytes are refunded despite `20000 > 10000`, and both the bytes and the asset remain permanently credited to the AA's balance with no refund unit produced. [3](#0-2)

### Citations

**File:** aa_composer.js (L909-945)
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
	}
```

**File:** aa_addresses.js (L138-155)
```javascript
		var arrMissingBounceFees = [];
		rows.forEach(function (row) {
			var arrDefinition = JSON.parse(row.definition);
			var bounce_fees = arrDefinition[1].bounce_fees;
			if (!bounce_fees)
				bounce_fees = { base: constants.MIN_BYTES_BOUNCE_FEE };
			if (!bounce_fees.base)
				bounce_fees.base = constants.MIN_BYTES_BOUNCE_FEE;
			for (var asset in bounce_fees) {
				var amount = assocAmounts[row.address][asset] || 0;
				if (amount < bounce_fees[asset])
					arrMissingBounceFees.push({ address: row.address, asset: asset, missing_amount: bounce_fees[asset] - amount, recommended_amount: bounce_fees[asset] });
			}
		});
		if (arrMissingBounceFees.length === 0)
			return handleResult();
		handleResult(new MissingBounceFeesErrorMessage({ error: "The amounts are less than bounce fees", missing_bounce_fees: arrMissingBounceFees }));
	});
```
