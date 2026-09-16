## Analog Finding [1](#0-0) 

### Title
Missing Expiration Check on Off-Chain Signed Orders Allows Execution of Stale Orders at Outdated Prices - (File: test/samples/order_book_exchange.oscript)

### Summary
The Order Book Exchange AA template accepts off-chain signed orders (`is_valid_signed_package`) and executes trades between them, but never checks whether a signed order has expired. The code even contains an explicit `// to do check expiry` marker acknowledging the missing check. This mirrors the external report's root cause: a message is signed off-chain and later submitted on-chain, but nothing in the signed payload or in on-chain validation ties it to a bounded validity window, so it remains executable indefinitely.

### Finding Description
Orders are represented as `signed_message` packages signed by the maker's address off-chain and later submitted as `trigger.data.order1`/`order2` by any unprivileged trigger sender. The AA derives a deterministic order id from the order fields and `last_ball_unit` [2](#0-1)  and verifies the signature with `is_valid_signed_package(trigger.data.order1, $order1.address)` [3](#0-2) , which internally calls `signed_message.validateSignedMessage` [4](#0-3) . That validation only checks that the referenced `last_ball_unit` is stable and not newer than the current MCI [5](#0-4)  — it performs no freshness/expiry enforcement, since any past stable ball remains permanently valid as a reference. The order-matching logic itself never inspects a timestamp/expiry field before executing a trade, despite the developer comment flagging this gap [6](#0-5) . There is also no on-chain cancellation case in the AA, so once an order is signed, an unprivileged counterparty can submit it as `order2` (or supply a fresh matching `order1`) at any future point, regardless of how much time has passed or how market conditions have changed.

### Impact Explanation
Because the maker's balance is custodied inside the AA (`var[$sell_key1]`), any signed order the maker ever produced — even one they intended as a one-off quote at a stale price — remains a standing, permanently executable liability until fully filled. An unprivileged AA trigger sender who has the maker's old signed order (e.g., leaked, cached, or previously shared during negotiation) can trigger execution at that stale price at an arbitrary later time, debiting the maker's AA balance and crediting the trigger sender, at a price the maker no longer intends to honor. This is a concrete AA fund loss for the order maker, reachable by any unprivileged party holding the stale signed package plus a matching counter-order.

### Likelihood Explanation
This is directly reachable by any unprivileged trigger sender who can construct or obtain a matching pair of signed orders and post them as an AA trigger — no special privileges, node control, or timing coordination with other network actors is required. The only prerequisite is that the maker's stale order (or a still-partially-filled `amount_left`) has not been consumed, and there is no mechanism (expiry or cancellation) to invalidate it. Given that the template explicitly flags the missing check as a "to do," any real-world deployment copying this sample inherits the flaw as-is.

### Recommendation
Add an explicit `expiry_ts` field to the signed order payload (`signed_message`), signed as part of the message, and reject execution when `timestamp > $order.expiry_ts`. Additionally, implement an on-chain cancellation mechanism (e.g., a `var['cancelled_' || $id]` flag settable only by the order's own address) so makers can revoke stale orders even before expiry, consistent with the underlying report's recommendation to bind signed off-chain authorizations to a bounded validity window rather than relying solely on state that may or may not still be considered "fresh."

### Proof of Concept
1. Maker A signs an order off-chain: sell 100 of asset X for asset Y at price 1.0, referencing `last_ball_unit = U1` (`is_valid_signed_package` will accept this as long as `U1` is stable).
2. Time passes; market price of X/Y moves significantly against A's stated price, and A never revokes or supersedes the order (no revocation mechanism exists).
3. An unprivileged user B, still holding A's originally signed order, submits an AA trigger with `order1 = A's stale signed order` and `order2` = B's own freshly signed matching order.
4. The AA's `is_valid_signed_package` checks pass (the ball is still stable), the `executed_$id1` flag was never set, and the trade executes at A's stale price [7](#0-6) , debiting A's AA-held balance at a price A no longer wants to honor.

### Citations

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

**File:** test/samples/order_book_exchange.oscript (L66-97)
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
```

**File:** formula/evaluation.js (L1693-1699)
```javascript
						signed_message.validateSignedMessage(conn, signedPackage, evaluated_address, mci, function (err, last_ball_mci) {
							if (err)
								return cb(false);
							if (last_ball_mci === null || last_ball_mci > mci)
								return cb(false);
							cb(true);
						});
```

**File:** signed_message.js (L193-196)
```javascript
	var bNetworkAware = ("last_ball_unit" in objSignedMessage);
	if (bNetworkAware && !ValidationUtils.isValidBase64(objSignedMessage.last_ball_unit, constants.HASH_LENGTH))
		return handleResult("invalid last_ball_unit");
	
```
