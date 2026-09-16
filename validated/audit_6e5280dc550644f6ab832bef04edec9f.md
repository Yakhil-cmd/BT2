This confirms the analog: `test/samples/order_book_exchange.oscript` demonstrates an AA-based on-chain order-book that verifies off-chain-signed limit orders via `is_valid_signed_package`, and the reference implementation itself contains a `// to do check expiry` comment (line 36) — showing that expiry/revocation of a signed order is not enforced by the `ocore` primitive but is left entirely to the AA author's oscript logic. The `is_valid_signed_package`/`validateSignedMessage` machinery (`formula/evaluation.js`, `signed_message.js`) only verifies cryptographic validity of the authors/authentifiers and (optionally) a `last_ball_unit` freshness bound; it has no concept of "cancel/revoke this specific signed message" and no built-in nonce/expiry enforcement.

### Title
Off-Chain Signed Orders Verified via `is_valid_signed_package` Have No On-Chain Revocation/Expiry Enforcement, Enabling Stale-Order and Contradictory-Order Execution - ([File: test/samples/order_book_exchange.oscript])

### Summary
`ocore`'s oscript primitive `is_valid_signed_package` (backed by `signed_message.validateSignedMessage`) lets an Autonomous Agent (AA) accept off-chain-signed messages as trigger data and treat them as authorized instructions from the signing address — the exact same "RFQ order" pattern described in the external report. The reference order-book AA shipped with `ocore` (`test/samples/order_book_exchange.oscript`) uses this primitive to implement a limit-order exchange where a market participant signs `{sell_asset, buy_asset, sell_amount, price, address}` off-chain and anyone can later post it as `trigger.data.orderN` to execute a trade. Critically, the sample contains the comment `// to do check expiry` at line 36, and even the primitives it relies on (`is_valid_signed_package`, `validateSignedMessage`) provide no protocol-level way for the signer to invalidate/cancel a specific previously-signed package before its natural conditions are met.

### Finding Description
`formula/evaluation.js` implements `is_valid_signed_package` by delegating to `signed_message.validateSignedMessage`, which only checks: that authors/authentifiers correctly satisfy the address definition, and optionally that `last_ball_unit` is stable and not newer than the evaluating `mci`. [1](#0-0) [2](#0-1) 

There is no concept of a revocation list, nonce registry, or "cancel hash X" mechanism anywhere in `signed_message.js` or `definition.js`'s handling of `is_valid_signed_package`/`is_valid_sig`. Any address-holder building an AA-based RFQ/limit-order system on top of this primitive (exactly as `ocore`'s own reference sample does) must implement expiry and de-duplication entirely in oscript state (`var['executed_' || $id]`), and even that only prevents *re-use* of the exact same order after execution — it does nothing to let the signer revoke the order *before* someone chooses to execute it. [3](#0-2) 

The sample's own explicit `// to do check expiry` marks that even time-based expiry was never implemented in the reference pattern that `ocore` ships and that developers are expected to copy/adapt when building AA-based exchanges. [4](#0-3) 

By contrast, `ocore`'s own payment-channel sample (`test/samples/payment_channels.oscript`) shows that safe usage of `is_valid_signed_package` requires the AA author to manually bind every signed message to a monotonically-incrementing `var['period']` so that older signed states are provably stale once a new period starts — this is a workaround pattern, not something enforced by the underlying primitive itself. [5](#0-4) 

### Impact Explanation
A user (order taker) can hold a validly signed RFQ/limit order from a market maker/liquidity address and post it as AA trigger data at any time the market conditions become favorable to the taker, since the AA and the underlying `is_valid_signed_package` primitive have no way to check "has the signer revoked this order?" Because there is no revocation mechanism, the signer (maker) has no way to immediately invalidate the order once market conditions move against them — they must wait for a self-implemented `expires` field (which the reference implementation doesn't even include) or rely on running out of balance. This grants the taker a "free option": they can wait to trigger the AA only when the trade is profitable to them and unprofitable to the maker, causing direct fund loss to the maker's AA balance. Additionally, since matching is done pairwise by whoever posts the trigger, a single user holding two contradictory signed orders from the same maker (e.g., buy X at price P1 and sell X at price P2 > P1) could execute both back-to-back for a risk-free arbitrage against the maker's AA-held balance.

### Likelihood Explanation
Likelihood is directly tied to adoption of this documented pattern: any developer building an on-chain order book, RFQ system, or other AA that accepts off-chain-signed instructions via `is_valid_signed_package` (following `ocore`'s own reference sample) inherits this gap by default, since the underlying primitive offers no revocation support to build on, and the shipped example doesn't even implement expiry.

### Recommendation
Add a protocol-level (or well-documented AA-library-level) revocation primitive for signed packages/messages, e.g. a getter or opcode such as `is_revoked_signed_package(hash)` that lets an AA check whether the signing address has broadcast an on-chain revocation for a specific `signed_message` hash (similar to how the `payment_channels.oscript` sample manually implements period-based staleness). At minimum, update the reference `order_book_exchange.oscript` sample to implement the marked-but-missing expiry check and to include a maker-controlled on-chain revocation registry (e.g., `var['revoked_' || $order_hash]`) that the maker can set via a dedicated trigger, checked before any match is executed.

### Proof of Concept
1. Market-maker address `M` signs an off-chain RFQ order via `signMessage()` (`signed_message.js`): `{sell_asset: A, buy_asset: B, sell_amount: 1000, price: 2, address: M}`, with no `expires` field enforced anywhere in the primitive.
2. Taker `T` receives this signed package but does not execute it immediately because the price is not currently favorable.
3. Market moves in `T`'s favor. `T` posts the old signed package as `trigger.data.order1` (paired with any counter-order satisfying the `if` condition) to the order-book AA.
4. The AA's `if` clause calls `is_valid_signed_package(trigger.data.order1, $order1.address)` (`test/samples/order_book_exchange.oscript` line 47-48), which only checks the signature/authentifiers are valid for `M` — it succeeds regardless of how much time has passed or whether `M` wanted to cancel.
5. Because `// to do check expiry` was never implemented and there is no revocation check, the trade executes at the stale price, transferring value from `M`'s AA balance (`var['balance_M_A']`) to `T`, even though `M` never had any way to invalidate the order once conditions turned unfavorable.

### Citations

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

**File:** signed_message.js (L255-303)
```javascript
	let last_ball_mci;
	let complexity = 0;
	async.eachSeries(
		authors,
		function (objAuthor, cb) {
			validateOrReadDefinition(objAuthor, function (arrAddressDefinition, _last_ball_mci, last_ball_timestamp) {
				last_ball_mci = _last_ball_mci;
				var objUnit = _.clone(objSignedMessage);
				objUnit.messages = []; // some ops need it
				try {
					var objValidationState = {
						unit_hash_to_sign: objectHash.getSignedPackageHashToSign(objSignedMessage),
						last_ball_mci: last_ball_mci,
						last_ball_timestamp: last_ball_timestamp,
						bNoReferences: !bNetworkAware,
						complexity,
						max_complexity,
					};
				}
				catch (e) {
					return cb("failed to calc unit_hash_to_sign: " + e);
				}
				try {
					// passing db as null
					Definition.validateAuthentifiers(
						conn, objAuthor.address, null, arrAddressDefinition, objUnit, objValidationState, objAuthor.authentifiers,
						function (err, res) {
							if (err) // error in address definition
								return cb(err);
							if (!res) // wrong signature or the like
								return cb("authentifier verification failed");
							complexity = objValidationState.complexity;
							cb();
						}
					);
				}
				catch (e) {
					console.log("exception while validating signed message:", e);
					return cb("exception while validating: " + e);
				}
			});
		},
		function (err) {
			if (err)
				return handleResult(err);
			handleResult(null, last_ball_mci);
		}
	);
}
```

**File:** test/samples/order_book_exchange.oscript (L27-65)
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

					true
				}`,
```

**File:** test/samples/payment_channels.oscript (L41-50)
```text
								if (trigger.data.sentByPeer.signed_message.channel != this_address)
									bounce('signed for another channel');
								if (trigger.data.sentByPeer.signed_message.period != var['period'])
									bounce('signed for a different period of this channel');
								if (!is_valid_signed_package(trigger.data.sentByPeer, $bFromB ? $addressA : $addressB))
									bounce('invalid signature by peer');
								$transferredFromPeer = trigger.data.sentByPeer.signed_message.amount_spent;
								if ($transferredFromPeer < 0)
									bounce('bad amount spent by peer: ' || $transferredFromPeer);
							}
```
