Based on my research, I found a concrete analog in the ocore codebase's order-matching AA template.### Title
Order-book exchange AA template executes signed off-chain orders without expiry validation, enabling stale-price fills under network congestion - ([File: test/samples/order_book_exchange.oscript])

### Summary
The `order_book_exchange.oscript` sample AA, shipped as a reference oscript-editor template in ocore, matches two off-chain signed orders (`trigger.data.order1`/`order2`) purely based on price/asset compatibility and a `sha256`-derived id, but explicitly defers expiry validation with a `// to do check expiry` comment [1](#0-0) . This mirrors the English-auction report's core bug class: a time-bounded competitive commitment (a bid, or here a signed price order) can be executed long after it should have lapsed because no expiry/deadline check gates settlement, and during network congestion no fresher, better-priced order or counter-transaction can be posted/confirmed in time to prevent the stale commitment from being filled.

### Finding Description
Orders are off-chain signed messages (`is_valid_signed_package`) carrying `sell_asset`, `buy_asset`, `sell_amount`, `price`, and `last_ball_unit`, verified and matched by the AA's `if` condition [2](#0-1) . Nothing in the logic checks that the order was signed recently or is still within a validity window before allowing it to be executed via `messages.cases` state updates [3](#0-2) . Because Obyte units must propagate and reach stability before AA responses are finalized, and the DAG can experience congestion/delayed confirmation just like Ethereum mempools, a signed order created under one market condition can sit unconfirmed or simply un-cancelled for an arbitrarily long time and later be submitted (by the original signer, a relayer, or anyone holding the signed package, since `is_valid_signed_package` only checks the signature validity, not freshness) and matched at a now-stale price with no requirement that a "fresher"/competitive counter-order exists. This is analogous to the English auction problem where, absent transaction processing during congestion, a very low/stale bid can be settled unopposed.

### Impact Explanation
If deployed as-is (it is explicitly documented as a template intended for developers to build real order-book AAs on), stale orders could be replayed at outdated prices, causing one counterparty to receive an unfavorable trade execution they did not intend to still be exposed to — a concrete fund-loss scenario for the AA's users (asset issuer/trigger-sender/private counterparty analog), consistent with the "AA fund loss" impact criterion. The severity depends on price volatility between order signing and eventual matching, but the AA has no expiry gate at all, so the risk window is unbounded.

### Likelihood Explanation
Likelihood is elevated because: (1) the comment itself acknowledges the missing check was never implemented, so any AA author copying this template inherits the vulnerability; (2) signed order packages, once created, remain valid indefinitely for replay via `trigger.data`, requiring no special privilege beyond being able to post a trigger unit; (3) network delays/congestion in unit propagation and stabilization are a normal, expected occurrence in ocore, not an edge case.

### Recommendation
Add an explicit expiry/staleness check in the matching `if` condition — e.g., require an `expiry_ts` or `last_ball_unit`-derived MCI bound signed as part of the order payload, and reject matches where `timestamp` (or current stable MCI) exceeds that bound, analogous to how `payment_channels.oscript` uses `close_start_ts` + `$close_timeout` for time-bounded state transitions [4](#0-3) . Any production AA derived from this template must not omit this check.

### Proof of Concept
1. Party A signs an order `order1 = {sell_asset: X, buy_asset: base, sell_amount: 100, price: 10, last_ball_unit: U1}` when market price is favorable, and shares/broadcasts the signed package (e.g., off-chain or as a data-only unit).
2. Market conditions change (price of X moves against A), and A does not (or cannot, due to congestion) revoke/cancel the order, since the contract provides no expiry field or cancellation-by-timestamp mechanism at all — only withdrawal of the already-deposited balance shown at lines [5](#0-4) , which does not invalidate outstanding signed order packages.
3. Days/weeks later, any actor holding the stale signed package pairs it with a fresh `order2` and submits a trigger `{order1, order2}` to the AA.
4. The `if` condition at lines 27-64 passes purely on signature validity and price-compatibility math, with no timestamp/MCI check, so the state-update messages execute the trade at A's stale, unfavorable price [3](#0-2) .

### Citations

**File:** test/samples/order_book_exchange.oscript (L4-25)
```text
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
```

**File:** test/samples/order_book_exchange.oscript (L27-49)
```text
			{ // execute orders, order1 must be smaller or the same as order2; order2 is partially filled
				if: `{
					$order1 = trigger.data.order1.signed_message;
					$order2 = trigger.data.order2.signed_message;
					if (!$order1.sell_asset OR !$order2.sell_asset)
						return false;
					if ($order1.sell_asset != $order2.buy_asset OR $order1.buy_asset != $order2.sell_asset)
						return false;

					// to do check expiry

					$sell_key1 = 'balance_' || $order1.address || '_' || $order1.sell_asset;
					$sell_key2 = 'balance_' || $order2.address || '_' || $order2.sell_asset;

					$id1 = sha256($order1.address || $order1.sell_asset || $order1.buy_asset || $order1.sell_amount || $order1.price || trigger.data.order1.last_ball_unit);
					$id2 = sha256($order2.address || $order2.sell_asset || $order2.buy_asset || $order2.sell_amount || $order2.price || trigger.data.order2.last_ball_unit);

					if (var['executed_' || $id1] OR var['executed_' || $id2])
						return false;

					if (!is_valid_signed_package(trigger.data.order1, $order1.address)
						OR !is_valid_signed_package(trigger.data.order2, $order2.address))
						return false;
```

**File:** test/samples/order_book_exchange.oscript (L66-98)
```text
				messages: [{
					app: 'state',
					state: `{
						$buy_key1 = 'balance_' || $order1.address || '_' || $order1.buy_asset;
						$buy_key2 = 'balance_' || $order2.address || '_' || $order2.buy_asset;
						$base_key1 = 'balance_' || $order1.address || '_base';
						$base_key2 = 'balance_' || $order2.address || '_base';

						var[$sell_key1] = var[$sell_key1] - $amount_left1;
						var[$sell_key2] = var[$sell_key2] - $buy_amount1;
						var[$buy_key1] = var[$buy_key1] + $buy_amount1;
						var[$buy_key2] = var[$buy_key2] + $amount_left1;

						$fee = 1000;
						var[$base_key1] = var[$base_key1] - $fee;
						var[$base_key2] = var[$base_key2] - $fee;
						if (var[$base_key1] < 0 OR var[$base_key2] < 0)
							bounce('not enough balance for fees');

						var['executed_' || $id1] = 1;
						$new_amount_left2 = $amount_left2 - $buy_amount1;
						if ($new_amount_left2)
							var['amount_left_' || $id2] = $new_amount_left2;
						else
							var['executed_' || $id2] = 1;

						// parsable response for transaction log
						response[$order1.address || '_' || $order1.sell_asset] = -$amount_left1;
						response[$order2.address || '_' || $order2.buy_asset] = $amount_left1;
						response[$order1.address || '_' || $order1.buy_asset] = $buy_amount1;
						response[$order2.address || '_' || $order2.sell_asset] = -$buy_amount1;
					}`
				}]
```

**File:** test/samples/payment_channels.oscript (L68-72)
```text
			{ // confirm closure
				if: `{ trigger.data.confirm AND var['close_initiated_by'] }`,
				init: `{
					if (!($bFromParties AND var['close_initiated_by'] != $party OR timestamp > var['close_start_ts'] + $close_timeout))
						bounce('too early');
```
