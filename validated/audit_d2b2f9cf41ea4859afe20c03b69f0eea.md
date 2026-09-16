I have enough context to produce a definitive analog finding based on the `is_valid_signed_package()` mechanism used by AA order-book style contracts, exemplified in the repository's own reference contract `test/samples/order_book_exchange.oscript`.

### Title
Off-chain signed order/price replay due to missing expiry (nonce) enforcement in `is_valid_signed_package()`-based AA order matching - (File: test/samples/order_book_exchange.oscript)

### Summary
The `is_valid_signed_package()` primitive (implemented in `formula/evaluation.js` and `signed_message.js`) lets an AA accept an off-chain-signed message (`signed_message`) as an authorization for on-chain state changes, verifying only the ECDSA signature, an optional `last_ball_unit` stability check, and a `version` field — it never enforces freshness/expiry of the signed content itself. The reference order-book AA `test/samples/order_book_exchange.oscript` uses this primitive to authorize trades based on a price that a user signed off-chain, but leaves price/order staleness protection as an explicit unimplemented `// to do check expiry` TODO. As a result, once a user signs a sell/buy order, that exact signature remains perpetually valid and can be matched (replayed) against the market at the originally signed price for as long as the user's tracked balance and the order's remaining `amount_left` allow — mirroring the reported Chainport issue where an off-chain-signed value (there: a fee; here: a trade price) can be reused indefinitely because no on-chain nonce/expiry check exists.

### Finding Description
`is_valid_signed_package()` is evaluated in `formula/evaluation.js` at the `case 'is_valid_signed_package'` branch [1](#0-0) . It forwards to `signed_message.validateSignedMessage()`, which validates the signature, author address, and optional `last_ball_unit` for stability, but performs no per-package uniqueness or time-based expiry validation of its own [2](#0-1) .

Any freshness/anti-replay logic is therefore fully delegated to the AA author, exactly as the original report describes for Chainport's offchain fee signing. The repository's own reference AA template for an order-book exchange demonstrates the risk concretely: it authorizes trades purely from `is_valid_signed_package(trigger.data.order1, $order1.address)` and a static `$id` derived from order parameters plus `last_ball_unit`, while explicitly noting the missing expiry check: [3](#0-2) 

The `$id1`/`$id2` values only prevent the same order object from being fully re-executed after it is marked `executed`, but a *partially filled* order (`var['amount_left_' || $id]`) remains matchable forever at the exact signed `price`, since there is no timestamp/expiry field checked against `timestamp` (available in AA formulas) [4](#0-3) .

### Impact Explanation
Because the signed order carries a fixed `price` with no expiry, and `is_valid_signed_package()` provides no built-in staleness check, any unprivileged AA trigger sender can continue to match (fill) a stale signed order at a now-unfavorable price for the original signer, for as long as the signer's tracked balance in `var[$sell_key]` covers it. This can drain a user's AA-tracked balance at an outdated price long after market conditions changed, causing fund loss to the order originator without their renewed consent — a direct parallel to the original report's concern about stale/replayed off-chain-approved values causing unintended asset movement.

### Likelihood Explanation
Any address can post an AA trigger, and the second half of a trade only requires possessing (or being handed) a previously broadcast signed order package — these are commonly shared for order matching. No special privilege is needed; the only barrier is the signer's residual on-chain balance being nonzero, which is a normal expected state for a resting order.

### Recommendation
`is_valid_signed_package()` / `validateSignedMessage()` should not be the sole enforcement point for freshness — but since ocore's own reference implementation omits this check where it explicitly acknowledges it is needed, it should either: (1) add a documented/standard `expiry_ts` (or nonce) field convention checked by `is_valid_signed_package`-consuming AAs, and update reference templates such as `order_book_exchange.oscript` to enforce it (`timestamp < $order.expiry_ts`), or (2) provide a built-in expiry/nonce parameter to `is_valid_signed_package()` itself so AA authors cannot forget the check as happened here.

### Proof of Concept
1. User A signs `order1 = {sell_asset, buy_asset, sell_amount, price, address: A, ...}` off-chain and shares it (e.g., in a UI) to advertise an offer.
2. The AA in `test/samples/order_book_exchange.oscript` computes `$id1` and stores `amount_left_$id1` after a partial fill from `order2`, but never checks any expiry field against `timestamp`.
3. Weeks later, market price of the pair changes drastically in A's disfavor, but A never cancelled or invalidated the old signed `order1` (no on-chain mechanism to do so exists in the template either).
4. Any third party posts a new AA trigger with a matching `order2` at the still-valid old `price`, and `is_valid_signed_package(trigger.data.order1, $order1.address)` returns `true` because the signature over the stale content is still cryptographically valid.
5. The trade executes at the stale price, moving funds out of A's tracked balance (`var[$sell_key1]`) at a price A would not agree to today, purely because the signed package has no built-in or enforced expiry.

### Citations

**File:** formula/evaluation.js (L1653-1673)
```javascript
			case 'is_valid_signed_package':
				if (!objValidationState.count_signed_packages)
					objValidationState.count_signed_packages = 0;
				if (objValidationState.count_signed_packages >= constants.MAX_SIGNED_PACKAGES_PER_AA_EVAL && bPostPemCurvesFix)
					return setFatalError("too many signed packages in evaluation", { arr }, false, cb);
				objValidationState.count_signed_packages++;
				var signed_package_expr = arr[1];
				var address_expr = arr[2];
				evaluate(address_expr, function (evaluated_address) {
					if (fatal_error)
						return cb(false);
					if (!ValidationUtils.isValidAddress(evaluated_address))
						return setFatalError("bad address in is_valid_signed_package: " + evaluated_address, { arr }, false, cb);
					evaluate(signed_package_expr, async function (signedPackage) {
						if (fatal_error)
							return cb(false);
						if (!(signedPackage instanceof wrappedObject))
							return cb(false);
						signedPackage = signedPackage.obj;
						if (ValidationUtils.hasFieldsExcept(signedPackage, ['signed_message', 'last_ball_unit', 'authors', 'version']))
							return cb(false);
```

**File:** signed_message.js (L117-145)
```javascript
function validateSignedMessage(conn, objSignedMessage, address, mci, handleResult) {
	if (!handleResult) {
		if (mci) { // validateSignedMessage(conn, objSignedMessage, address, handleResult)
			handleResult = mci;
			mci = undefined;
		}
		else { // validateSignedMessage(objSignedMessage, handleResult)
			handleResult = objSignedMessage;
			objSignedMessage = conn;
			conn = db;
		}
	}
	const max_complexity = (mci >= constants.pemCurvesFixMci) ? 10 : 0;
	if (!ValidationUtils.isNonemptyObject(objSignedMessage))
		return handleResult("signed message must be a non-empty object");
	if (ValidationUtils.hasFieldsExcept(objSignedMessage, ["signed_message", "authors", "last_ball_unit", "timestamp", "version"]))
		return handleResult("unknown fields");
	if (!('signed_message' in objSignedMessage))
		return handleResult("no signed message");
	if ("version" in objSignedMessage && constants.supported_versions.indexOf(objSignedMessage.version) === -1)
		return handleResult("unsupported version: " + JSON.stringify(objSignedMessage.version));
	var authors = objSignedMessage.authors;
	if (!ValidationUtils.isNonemptyArray(authors))
		return handleResult("no authors");
	if (!address && !ValidationUtils.isArrayOfLength(authors, 1))
		return handleResult("authors not an array of len 1");
	if (authors.length > constants.MAX_AUTHORS_PER_UNIT)
		return handleResult("too many authors");
	var prev_address = "";
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

**File:** test/samples/order_book_exchange.oscript (L51-65)
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

					true
				}`,
```
