## Analysis

The Sherlock report describes a gas-griefing vector: a permissionless actor (a "keeper") submits a transaction to execute a user's pending limit order, but the order owner can front-run/cancel it at the last moment, causing the keeper's transaction to fail and waste its gas.

In `ocore`, the closest reachable analog is the **order-book Autonomous Agent (AA) pattern**, illustrated by the bundled reference implementation `test/samples/order_book_exchange.oscript`, combined with how `aa_composer.js` selects `cases` and consumes `bounce_fees` on failure.

### Title
Order-matching AA design pattern lets order owners grief third-party matchers/keepers, consuming their bounce fees for nothing - (File: test/samples/order_book_exchange.oscript, aa_composer.js)

### Summary
The order-book AA pattern lets any address (a "keeper"/relayer) submit a trigger unit carrying two off-chain-signed orders (`trigger.data.order1`, `trigger.data.order2`) to match them on-chain. Because the orders are just signed messages with no binding on-chain reservation, an order owner can invalidate their own order (e.g., by withdrawing their `sell_asset` balance) with a transaction that lands before the keeper's matching trigger. When the keeper's trigger is then processed, none of the AA's `cases` evaluate to true, the AA composer bounces the trigger, and the keeper's paid `bounce_fees` are non-refundable — an exact analog of the reported "gas grief keepers with limit orders" issue.

### Finding Description
`order_book_exchange.oscript` defines three cases: withdraw funds, execute two matched orders, and silently accept coins [1](#0-0) . The "execute orders" case requires that `$amount_left1 <= var[$sell_key1]` and `$amount_left2 <= var[$sell_key2]`, i.e. that the signing users still have enough balance recorded in AA state to honor the orders they signed [2](#0-1) .

Since the orders are only off-chain signatures (`is_valid_signed_package`) and not locked/reserved on-chain, the order owner retains full control of their AA-tracked balance until the match transaction actually lands. A malicious order owner can submit a `withdraw` trigger (case 1) that drains `var[$sell_key1]` for exactly enough to make a pending match invalid, timed to be processed on-chain just before a keeper's "execute orders" trigger for the same order.

When the keeper's trigger is then evaluated, `aa_composer.js`'s case-selection logic iterates `value.cases` and, if none of the `if` conditions evaluate true, returns an error `"neither case is true in " + name` [3](#0-2) . This error is passed up to `evaluateAA`'s callback and triggers `bounce(err)` [4](#0-3) . The `bounce()` function computes the response by subtracting `bounce_fees` from whatever the trigger sender attached and returns only the remainder — the `bounce_fees.base` (at least `constants.MIN_BYTES_BOUNCE_FEE`) is consumed and not refunded to the trigger sender [5](#0-4) .

Thus, the keeper who innocently tried to execute a still-apparently-valid, previously signed order loses real bytes (the AA's `bounce_fees`) whenever the order owner front-runs the match with a state-invalidating withdrawal — with no time-lock or reservation mechanism preventing this in the reference pattern.

### Impact Explanation
Every keeper/relayer attempt to execute a signed limit order in this AA design can be griefed by the order's own owner at will and repeatedly, at zero cost to the owner beyond the withdrawal transaction they wanted to send anyway. This discourages permissionless order execution (a core selling point of the order-book design, since it lets independent relayers match orders without needing the counterparty's live cooperation), and drains real byte-fees from third parties who try to keep the market functioning. This matches the Medium-severity classification of the original report: loss of funds (fees) for an unprivileged, well-intentioned actor, with no compensating mechanism.

### Likelihood Explanation
This requires a user to (a) sign a limit order for a matcher to later execute, and (b) submit a conflicting withdrawal transaction timed to land right before a keeper's execution transaction stabilizes. On Obyte, unstable units are processed once the underlying MCI stabilizes, giving the order owner a natural window to observe the pending keeper unit and race it with their own withdrawal before AA trigger execution occurs. Since any user can hold the withdraw and match-triggering transactions and choose when to broadcast them, and the AA imposes no delay/lock on signed orders, this is straightforward to reproduce whenever this reference pattern (or any similarly designed order-book AA lacking a reservation/lock mechanism) is used in production.

### Recommendation
The order-book AA pattern should reserve (lock) the `sell_asset` amount for a signed order once it is first referenced (e.g., recorded as "reserved" state keyed by the order hash) rather than re-checking the live spendable balance at match time, or it should require the order owner's withdraw case to explicitly account for/release amounts already reserved by outstanding signed orders. Alternatively, matched orders could be given a short-lived reservation created by a preceding "intent to match" trigger, with cancellation subject to a delay analogous to the time restraint recommended in the original report, so a third-party matcher's already-broadcast unit cannot be invalidated by a same-block front-run.

### Proof of Concept
1. UserA holds balance in AA state (`var['balance_A_assetX']`) and signs a limit order (`order1`) offering `assetX` for `assetY` at a given price, and shares it off-chain/to a keeper.
2. A keeper (unprivileged third party) constructs and broadcasts a trigger unit calling the "execute orders" case with `trigger.data.order1 = order1`, `trigger.data.order2 = <matching order2>`, paying `bounce_fees.base` in the trigger output as required by `handleTrigger` [6](#0-5) .
3. Before the keeper's unit stabilizes, UserA broadcasts a `withdraw` trigger (case 1) draining `var['balance_A_assetX']` below `order1.sell_amount` [7](#0-6) .
4. When both units are processed by `handleAATriggers`, the withdrawal executes first, reducing `var[$sell_key1]`.
5. The keeper's trigger is then evaluated: `$amount_left1 > var[$sell_key1]` is now true, the "execute orders" case's `if` returns false, and (with `trigger.data` non-empty) no case matches, producing `"neither case is true in messages"` [3](#0-2) .
6. `bounce()` fires, keeping `bounce_fees.base` from the keeper's attached bytes and returning only the remainder [8](#0-7) , so the keeper's transaction fails and its fee is lost — reproducing the reported gas-griefing pattern.

### Citations

**File:** test/samples/order_book_exchange.oscript (L1-26)
```text
{
	messages: {
		cases: [
			{ // withdraw funds
				if: `{
					$key = 'balance_'||trigger.address||'_'||trigger.data.asset;
					trigger.data.withdraw AND trigger.data.asset AND trigger.data.amount AND trigger.data.amount <= var[$key]
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
						}`
					}
				]
			},
```

**File:** test/samples/order_book_exchange.oscript (L51-62)
```text
					$amount_left1 = var['amount_left_' || $id1] otherwise $order1.sell_amount;
					$amount_left2 = var['amount_left_' || $id2] otherwise $order2.sell_amount;

					if ($amount_left1 > var[$sell_key1] OR $amount_left2 > var[$sell_key2])
						return false;

					$buy_amount1 = round($amount_left1 * $order1.price);
					if ($buy_amount1 > $amount_left2) // order1 is not the smaller one
						return false;
					$expected_buy_amount2 = round($buy_amount1 * $order2.price);
					if ($expected_buy_amount2 > $amount_left1) // user2 doesn't like the price, he gets less than expects
						return false;
```

**File:** aa_composer.js (L734-737)
```javascript
				},
				function (err) {
					if (!err)
						return cb({message: "neither case is true in " + name, xpath});
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

**File:** aa_composer.js (L1865-1867)
```javascript
		evaluateAA(arrDefinition, function (err) {
			if (err)
				return bounce(err);
```
