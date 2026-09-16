### Title
Signed data packages verified via `is_valid_signed_package` carry no usable freshness/expiry information, enabling stale-price replay in AA triggers - (File: formula/evaluation.js, signed_message.js)

### Summary
The reported Symmetrical bug allows a liquidator to submit an old, validly-signed price and have it accepted because the contract checks the signature validity but never verifies that the signed data is recent. The analogous primitive in `ocore` is the `is_valid_signed_package()` oscript function, which AA authors use to verify off-chain signed data (e.g., signed orders/prices, as in the shipped `order_book_exchange.oscript` sample). This primitive strips out any `timestamp` field from the signed package before validating it, and the only network-anchored reference available (`last_ball_unit`) is not itself checked for recency by the platform, leaving AA authors with no simple built-in way to enforce that a signed price/order is fresh.

### Finding Description
`is_valid_signed_package` in `formula/evaluation.js` explicitly restricts the top-level fields of a signed package to `['signed_message', 'last_ball_unit', 'authors', 'version']`: [1](#0-0) 

Note that `timestamp` is *not* in this allow-list, even though `signed_message.js`'s own `validateSignedMessage()` explicitly supports a `timestamp` field on the signed message object: [2](#0-1) 

Consequently, any signed package containing a `timestamp` is rejected outright by `is_valid_signed_package` (`hasFieldsExcept` returns true → `cb(false)`), meaning this code path used by AAs provides no way for the signer to attest to *when* the message was created. The only network-anchoring field available is `last_ball_unit`, which is merely checked for existence/stability, not for recency relative to the current mci: [3](#0-2) 

`signed_message.validateSignedMessage` itself also performs no freshness check on `last_ball_timestamp` or any age bound — it only confirms the referenced unit exists and is on the main chain: [4](#0-3) 

The shipped `test/samples/order_book_exchange.oscript` — a canonical example AA pattern for building order-book/exchange logic — demonstrates exactly this gap. It accepts arbitrary counter-signed price orders (`trigger.data.order1`, `trigger.data.order2`) validated only via `is_valid_signed_package`, with a code comment openly acknowledging the missing check: [5](#0-4) 

Because the platform provides no first-class way to bind a signed price/order to a recency window (no timestamp field survives validation, and `last_ball_unit`'s mci is not compared against "now" by the framework), an AA author following this canonical pattern will, like the Symmetrical liquidation facet, accept a stale but validly-signed price/order indefinitely unless they manually implement mci-distance bookkeeping themselves (which the shipped example does not do).

### Impact Explanation
Any AA built on this canonical signed-order pattern (order books, exchanges, payment-channel-style price feeds using `is_valid_signed_package`) can be triggered with a validly-signed but stale price/order. Since exchange/settlement logic computes payouts directly from the signed price (`$order1.price`, `$order2.price` in the sample), an attacker holding an old signed order from a counterparty (whose intended price is now stale relative to market conditions) can force execution at the outdated price, causing the counterparty to receive fewer/more assets than intended — a direct case of unauthorized value transfer / fund loss for one of the trade participants, analogous to the payout distortion in the original Liquidation Facet report.

### Likelihood Explanation
Likelihood is high in practice: any unprivileged party who is a counterparty to (or intercepts) a previously signed order/price package can replay it as `trigger.data` to the AA at any later time, since neither the wallet-side `signMessage`/`validateSignedMessage` flow nor the `is_valid_signed_package` oscript primitive enforces a recency bound, and the officially shipped sample explicitly leaves the expiry check as a "to do" rather than implementing it.

### Recommendation
- Allow (and require, when present) a `timestamp` field to pass through `is_valid_signed_package`'s field allow-list in `formula/evaluation.js`, and expose it to oscript so AA authors can enforce `timestamp > (last_ball_timestamp - max_age)`.
- Alternatively/additionally, expose the mci of `last_ball_unit` to oscript evaluation results of `is_valid_signed_package` so AAs can compare it against the current mci and bound staleness (`mci - last_ball_mci <= N`).
- Update `test/samples/order_book_exchange.oscript` to implement the acknowledged "check expiry" TODO, since it is used as a canonical example for AA developers.

### Proof of Concept
1. Party A signs an order (via `signMessage`) offering asset X for asset Y at price P, including a `last_ball_unit` at some historical mci, per the pattern in `test/samples/order_book_exchange.oscript`.
2. Party A's intended price P becomes stale as market conditions change; Party A does not intend the order to still be executable.
3. Party B (or anyone who received the signed order) later submits it as `trigger.data.order1` to the deployed order-book AA.
4. `is_valid_signed_package` in `formula/evaluation.js` (lines 1653-1702) validates the signature and that `last_ball_unit` is a stable unit ≤ current mci — it performs no check that the order is "recent" (no timestamp survives, no mci-distance bound is enforced).
5. The AA executes the trade at the stale price P, transferring assets at an incorrect valuation, exactly mirroring the "outdated `setPrice`" impact from the original report. [6](#0-5)

### Citations

**File:** formula/evaluation.js (L1653-1702)
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
						if (signedPackage.version) {
							if (typeof signedPackage.version !== 'string')
								return cb(false);
							if (signedPackage.version === constants.versionWithoutTimestamp)
								return cb(false);
							const fVersion = parseFloat(signedPackage.version);
							const maxVersion = 4; // depends on mci in the future updates
							if (fVersion > maxVersion)
								return cb(false);
						}
						if (typeof signedPackage.last_ball_unit === 'string') {
							const [row] = await conn.query("SELECT main_chain_index, is_on_main_chain FROM units WHERE unit=?", [signedPackage.last_ball_unit]);
							if (!row || row.main_chain_index > mci || row.main_chain_index === null) // not existing or not stable last ball unit
								return cb(false);
							if (!row.is_on_main_chain && mci >= constants.pemCurvesFixMci) // last ball must be on the MC
								return cb(false);
							if (mci >= constants.pemCurvesFixMci && row.main_chain_index < constants.pemCurvesFixMci) // last ball unit is before the fix
								return setFatalError("last ball unit is before the PEM curves fix", { arr }, false, cb);
						}
						signed_message.validateSignedMessage(conn, signedPackage, evaluated_address, mci, function (err, last_ball_mci) {
							if (err)
								return cb(false);
							if (last_ball_mci === null || last_ball_mci > mci)
								return cb(false);
							cb(true);
						});
					});
				});
				break;
```

**File:** signed_message.js (L132-133)
```javascript
	if (ValidationUtils.hasFieldsExcept(objSignedMessage, ["signed_message", "authors", "last_ball_unit", "timestamp", "version"]))
		return handleResult("unknown fields");
```

**File:** signed_message.js (L193-219)
```javascript
	var bNetworkAware = ("last_ball_unit" in objSignedMessage);
	if (bNetworkAware && !ValidationUtils.isValidBase64(objSignedMessage.last_ball_unit, constants.HASH_LENGTH))
		return handleResult("invalid last_ball_unit");
	
	function validateOrReadDefinition(objAuthor, cb, bRetrying) {
		var bHasDefinition = ("definition" in objAuthor);
		if (bNetworkAware) {
			conn.query("SELECT main_chain_index, timestamp FROM units WHERE unit=?", [objSignedMessage.last_ball_unit], function (rows) {
				if (rows.length === 0) {
					var network = require('./network.js');
					if (!conf.bLight && !network.isCatchingUp() || bRetrying)
						return handleResult("last_ball_unit " + objSignedMessage.last_ball_unit + " not found");
					if (conf.bLight)
						network.requestHistoryFor([objSignedMessage.last_ball_unit], [objAuthor.address], function () {
							validateOrReadDefinition(objAuthor, cb, true);
						});
					else
						eventBus.once('catching_up_done', function () {
							// no retry flag, will retry multiple times until the catchup is over
							validateOrReadDefinition(objAuthor, cb);
						});
					return;
				}
				bRetrying = false;
				var last_ball_mci = rows[0].main_chain_index;
				var last_ball_timestamp = rows[0].timestamp;
				storage.readDefinitionByAddress(conn, objAuthor.address, last_ball_mci, {
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
