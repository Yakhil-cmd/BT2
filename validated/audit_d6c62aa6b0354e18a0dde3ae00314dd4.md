This is enough context to confirm the finding. The key mechanism is in `aa_composer.js`'s `bounce()` function, where an all-or-nothing failure mode causes assets to become permanently trapped in the AA with no recovery path.### Title
Bounce mechanism in AA trigger handling silently absorbs (permanently locks) trigger assets with no recovery path when any asset amount is below its bounce fee - ([File: aa_composer.js])

### Summary
The reported issue is a smart-contract design gap: `RootBridgeRelay.sol` has `erc20Rescue` to recover stuck ERC20s but no equivalent for stuck Ether, so Ether accidentally locked in the contract can never be retrieved. The reachable analog in `ocore` is the `bounce()` function inside `handleTrigger()` in `aa_composer.js`. When an Autonomous Agent (AA) bounces a trigger (any `bounce(error)` call, e.g. from `bounce()` inside oscript, or a formula/validation failure), the code tries to refund the trigger sender's payments minus the AA's configured `bounce_fees`. However, if **any single asset's** received amount is less than its configured `bounce_fees` entry, the whole refund is abandoned — not just for that asset, but for **all** assets in the trigger, including base bytes that would otherwise have been refunded. There is no per-AA or per-asset "rescue" mechanism analogous to `erc20Rescue`, so the funds already credited to the AA's on-chain balance (via `updateFinalAABalances`) remain permanently stuck unless the AA's own message/state logic happens to spend them back out — which most simple AAs (see the sample AAs `simple_aa.oscript`, `a_bank_without_percent.oscript`) do not implement for this specific edge case.

### Finding Description
`handleTrigger()` computes `bounce_fees` per asset for the invoked AA [1](#0-0) . The `bounce()` function is called whenever the AA's oscript execution fails or explicitly bounces:

```
if ((trigger.outputs.base || 0) < bounce_fees.base)
    return finish(null);
var messages = [];
for (var asset in trigger.outputs) {
    var amount = trigger.outputs[asset];
    var fee = bounce_fees[asset] || 0;
    if (fee > amount)
        return finish(null);
    ...
}
``` [2](#0-1) 

If a trigger sender includes an asset payment whose amount is smaller than the `bounce_fees` value configured for that asset (a value the AA author sets, defaulting only for `base` via `MIN_BYTES_BOUNCE_FEE` elsewhere in `aa_addresses.js` [3](#0-2) ), `bounce()` immediately calls `finish(null)` and returns — no refund messages are ever generated, for that asset *or any other asset paid in the same trigger*, including base bytes that individually satisfied their own fee requirement.

Because the trigger unit's outputs were already recorded to the AA's outputs/balance by the time `handleTrigger()` runs (via `updateFinalAABalances`, which credits `assocDeltas`/`aa_balances` for every payment output addressed to the AA) [4](#0-3) , the funds are now part of the AA's confirmed balance. Since the trigger bounced, no state variable is updated to track the sender's contribution (the AA's `state` messages never ran), and there is no built-in, AA-author-independent mechanism (equivalent to `erc20Rescue`/`ethRescue`) to return these funds to the original sender. Unless the specific AA's own oscript logic happens to have a case that recognizes and refunds this exact combination of assets, the funds are permanently trapped in the AA address, retrievable only if some future trigger happens to match a spending case the author wrote for unrelated purposes.

### Impact Explanation
This causes real, unrecoverable loss of user funds (base bytes and/or custom assets) sent to *any* AA that defines non-default `bounce_fees` for a non-base asset, or that uses `bounce()` — a very common oscript pattern used across the ecosystem (see e.g. `payment_channels.oscript`, `order_book_exchange.oscript`, `uniswap_like_market_maker.oscript`, all of which call `bounce(...)` inside `state` formulas) [5](#0-4) . Because the "all-or-nothing" refund logic silently swallows funds that should have been bounced (including the base-currency portion, which normally is always refundable), an unprivileged trigger sender can unintentionally (or a malicious actor can deliberately, to grief another user's funds via a shared trigger, though the primary risk is self-inflicted loss) cause permanent AA fund freezing/loss with no recovery mechanism, matching the "AA fund loss or freezing" acceptance criterion.

### Likelihood Explanation
Any user can trigger this simply by sending a payment to an AA with an asset amount below the AA's configured `bounce_fees` for that asset while a bounce condition is met (invalid trigger data, business logic mismatch, etc.). This requires no special privilege, no cooperation from a third party, and no unusual conditions — only a normal trigger-sending user interacting with a normal AA that uses non-default `bounce_fees` or asset payments alongside base bytes.

### Recommendation
Modify `bounce()` in `aa_composer.js` so that failing to refund one asset (because its amount is below `bounce_fees[asset]`) does not abort refunding of the other assets in the trigger. Each asset should be evaluated independently: refund what can be refunded (amount minus its own fee, when amount exceeds the fee) and only forfeit the specific asset(s) that fail the fee check, rather than calling `finish(null)` for the whole trigger. This preserves the intended "AA keeps only the bounce fee" guarantee for every properly-funded asset instead of silently absorbing everything when just one asset is under-funded.

### Proof of Concept
1. Deploy/define an AA with `bounce_fees: { base: 10000, "<asset>": 100 }` and a case that requires specific trigger data (so an incorrect/missing-data trigger bounces), similar to `test/samples/simple_aa.oscript` and `test/samples/bounce_half_of_balance.oscript` [6](#0-5) .
2. Send a trigger unit that pays 20000 base bytes (well above `bounce_fees.base`) plus 50 units of `<asset>` (below the 100-unit `bounce_fees["<asset>"]`), with trigger data that fails the AA's case condition so `bounce()` is invoked.
3. In `bounce()`, `trigger.outputs.base` (20000) ≥ `bounce_fees.base` (10000) passes the first check, but iterating `trigger.outputs`, the `<asset>` entry has `fee (100) > amount (50)`, causing `return finish(null)` — no refund messages generated at all, not even for the 20000 base bytes that should have been bounced back minus the 10000 fee [7](#0-6) .
4. Result: both the 10000 base bytes that should have been refunded (excess above `bounce_fees.base`) and the 50 units of `<asset>` are permanently absorbed into the AA's balance (per `updateFinalAABalances`), with no state update and no built-in path to reclaim them.

### Citations

**File:** aa_composer.js (L556-586)
```javascript
		objUnit.messages.forEach(function (message) {
			if (message.app !== 'payment')
				return;
			var payload = message.payload;
			var asset = payload.asset || 'base';
			payload.outputs.forEach(function (output) {
				if (output.address !== address)
					return;
				if (!assocDeltas[asset]) { // it can happen if the asset was issued by AA
					assocDeltas[asset] = 0;
					arrNewAssets.push(asset);
				}
				assocDeltas[asset] += output.amount;
			});
		});
		var arrQueries = [];
		if (arrNewAssets.length > 0) {
			var arrValues = arrNewAssets.map(function (asset) { return "(" + conn.escape(address) + ", " + conn.escape(asset) + ", 0)"; });
			conn.addQuery(arrQueries, "INSERT "+conn.getIgnore()+" INTO aa_balances (address, asset, balance) VALUES "+arrValues.join(', '));
		}
		for (var asset in assocDeltas) {
			if (assocDeltas[asset]) {
				conn.addQuery(arrQueries, "UPDATE aa_balances SET balance=balance+? WHERE address=? AND asset=?", [assocDeltas[asset], address, asset]);
				if (!objValidationState.assocBalances[address][asset])
					objValidationState.assocBalances[address][asset] = 0;
				objValidationState.assocBalances[address][asset] += assocDeltas[asset];
			}
		}
		if (assocDeltas.base)
			byte_balance += assocDeltas.base;
		async.series(arrQueries, cb);
```

**File:** aa_composer.js (L909-913)
```javascript
	var bBouncing = false;
	function bounce(error) {
		console.log('bouncing with error', error, new Error().stack);
		objStateUpdate = null;
		error_message = error_message ? (error_message + ', then ' + error) : error;
```

**File:** aa_composer.js (L926-944)
```javascript
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

**File:** aa_addresses.js (L138-150)
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
```

**File:** test/samples/order_book_exchange.oscript (L44-45)
```text
					if (var['executed_' || $id1] OR var['executed_' || $id2])
						return false;
```

**File:** test/samples/simple_aa.oscript (L1-14)
```text
{
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
}
```
