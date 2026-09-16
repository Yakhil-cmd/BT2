## Title
Signed messages / signed packages carry no protocol-enforced deadline, enabling stale-price execution in AA order/exchange patterns - (File: signed_message.js, formula/evaluation.js)

### Summary
The reported bug is that `LiquidationRow._performLiquidation()` swaps at an oracle-checked price but has no `deadline`, so a valid transaction can sit in the mempool and be executed later at a stale price. The equivalent gap exists in ocore's `signed_message`/`is_valid_signed_package` primitive, which underlies AA patterns such as order-book exchanges and payment channels: a counterparty can hold a validly signed price/order message indefinitely and post it whenever market conditions have changed, because the protocol never checks message freshness.

### Finding Description
`signMessage()`/`validateSignedMessage()` in `signed_message.js` build/verify a `signed_message` package whose allowed top-level fields are `["signed_message", "authors", "last_ball_unit", "timestamp", "version"]` [1](#0-0) . The `timestamp` field is accepted into the schema but is never read or validated anywhere in `validateSignedMessage` — only `last_ball_unit` is resolved to a `last_ball_mci`/`last_ball_timestamp` that is used purely to select the address's definition at the time of signing, not to bound how long the package remains valid [2](#0-1) .

The only formula primitive an AA can use to verify such a package, `is_valid_signed_package`, likewise checks only that `last_ball_unit` exists, is stable, and is on the main chain (i.e., that the message was *created* at or before some point) — it enforces no upper bound / expiry on when the package may be redeemed [3](#0-2) .

This is exploited by the documented AA design pattern for signed off-chain orders, e.g. `order_book_exchange.oscript`, where two counterparties exchange `signed_message` packages containing a `price`, and the AA trusts `is_valid_signed_package` plus the caller-supplied price fields to execute a trade — the sample code even flags the missing check with a `// to do check expiry` comment [4](#0-3) . Because neither the protocol-level `signed_message` validation nor the `is_valid_signed_package` primitive supplies any notion of a deadline, an AA author has no reliable, protocol-guaranteed field to check against `timestamp`/`mci` at execution time; any expiry logic must be manually reconstructed from data embedded in the signed payload itself (e.g. `last_ball_unit`), which only anchors the *start* of validity, not an end.

### Impact Explanation
Any AA that authorizes fund movement based on a `signed_message`/`is_valid_signed_package` verified order or quote (order books, OTC swaps, payment-channel closes, prosaic/arbiter contract acceptances) can be forced to execute against a stale, no-longer-fair price or state, because the signer has no protocol-enforced way to invalidate an old signature after a deadline. A counterparty can wait for favorable price movement and then post the old signed order, causing the original signer's AA-held funds to be transferred at an unfavorable, outdated rate — a direct AA fund loss analogous to the stale-swap fund loss in the reported finding.

### Likelihood Explanation
Any unprivileged AA trigger sender who possesses a previously signed package from a counterparty can replay it at will, since `is_valid_signed_package`/`validateSignedMessage` place no expiry constraint on it. The precondition (an off-chain signed order/quote exchanged between two parties, as recommended by ocore's own reference AA patterns) is a normal, encouraged usage pattern, not an edge case.

### Recommendation
Add an enforced deadline mechanism to the signed-message primitive itself: extend `validateSignedMessage` (`signed_message.js`) and `is_valid_signed_package` (`formula/evaluation.js`) to optionally require and check an `expiry_mci`/`expiry_timestamp` field against `objValidationState.last_ball_mci`/`last_ball_timestamp` at verification time, so AA authors can rely on a protocol-guaranteed deadline rather than re-implementing (and potentially forgetting, as in the shipped `order_book_exchange.oscript` sample) their own expiry logic.

### Proof of Concept
1. Alice and Bob build an order-book AA following the shipped `order_book_exchange.oscript` pattern [5](#0-4) .
2. Alice signs an order (`signed_message`) offering to sell asset X for asset Y at today's price using `signMessage()` [6](#0-5) .
3. Bob does not execute it immediately; he waits until the market price of X/Y has moved significantly in his favor.
4. Bob posts `trigger.data.order1 = <Alice's old signed order>` together with his own matching order to the AA.
5. The AA calls `is_valid_signed_package(trigger.data.order1, order1.address)`, which only validates `last_ball_unit` stability/mci, not any expiry, so the stale order passes verification [3](#0-2) .
6. The trade executes at Alice's stale price, and Alice's AA-held balance is drained at an unfavorable rate that she never would have agreed to at execution time.

### Citations

**File:** signed_message.js (L28-112)
```javascript
function signMessage(message, from_address, signer, bNetworkAware, handleResult){
	if (typeof bNetworkAware === 'function') {
		handleResult = bNetworkAware;
		bNetworkAware = false;
	}
	var objAuthor = {
		address: from_address,
		authentifiers: {}
	};
	var objUnit = {
		version: constants.version,
		signed_message: message,
		authors: [objAuthor]
	};
	
	function setDefinitionAndLastBallUnit(cb) {
		if (bNetworkAware) {
			composer.composeAuthorsAndMciForAddresses(db, [from_address], signer, function (err, authors, last_ball_unit) {
				if (err)
					return handleResult(err);
				objUnit.authors = authors;
				objUnit.last_ball_unit = last_ball_unit;
				cb();
			});
		}
		else {
			signer.readDefinition(db, from_address, function (err, arrDefinition) {
				if (err)
					throw Error("signMessage: can't read definition: " + err);
				objAuthor.definition = arrDefinition;
				cb();
			});
		}
	}

	var assocSigningPaths = {};
	signer.readSigningPaths(db, from_address, function(assocLengthsBySigningPaths){
		var arrSigningPaths = Object.keys(assocLengthsBySigningPaths);
		assocSigningPaths[from_address] = arrSigningPaths;
		for (var j=0; j<arrSigningPaths.length; j++)
			objAuthor.authentifiers[arrSigningPaths[j]] = repeatString("-", assocLengthsBySigningPaths[arrSigningPaths[j]]);
		setDefinitionAndLastBallUnit(function(){
			var text_to_sign = objectHash.getSignedPackageHashToSign(objUnit);
			async.each(
				objUnit.authors,
				function(author, cb2){
					var address = author.address;
					async.each( // different keys sign in parallel (if multisig)
						assocSigningPaths[address],
						function(path, cb3){
							if (signer.sign){
								signer.sign(objUnit, {}, address, path, function(err, signature){
									if (err)
										return cb3(err);
									// it can't be accidentally confused with real signature as there are no [ and ] in base64 alphabet
									if (signature === '[refused]')
										return cb3('one of the cosigners refused to sign');
									author.authentifiers[path] = signature;
									cb3();
								});
							}
							else{
								signer.readPrivateKey(address, path, function(err, privKey){
									if (err)
										return cb3(err);
									author.authentifiers[path] = ecdsaSig.sign(text_to_sign, privKey);
									cb3();
								});
							}
						},
						function(err){
							cb2(err);
						}
					);
				},
				function(err){
					if (err)
						return handleResult(err);
					console.log(require('util').inspect(objUnit, {depth:null}));
					handleResult(null, objUnit);
				}
			);
		});
	});
}
```

**File:** signed_message.js (L132-133)
```javascript
	if (ValidationUtils.hasFieldsExcept(objSignedMessage, ["signed_message", "authors", "last_ball_unit", "timestamp", "version"]))
		return handleResult("unknown fields");
```

**File:** signed_message.js (L193-253)
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
					ifDefinitionNotFound: function (definition_chash) { // first use of the definition_chash (in particular, of the address, when definition_chash=address)
						if (!bHasDefinition) {
							if (!conf.bLight || bRetrying)
								return handleResult("definition expected but not provided");
							var network = require('./network.js');
							return network.requestHistoryFor([], [objAuthor.address], function () {
								validateOrReadDefinition(objAuthor, cb, true);
							});
						}
						if (objectHash.getChash160(objAuthor.definition) !== definition_chash)
							return handleResult("wrong definition: "+objectHash.getChash160(objAuthor.definition) +"!=="+ definition_chash);
						cb(objAuthor.definition, last_ball_mci, last_ball_timestamp);
					},
					ifFound: function (arrAddressDefinition) {
						if (bHasDefinition)
							return handleResult("should not include definition");
						cb(arrAddressDefinition, last_ball_mci, last_ball_timestamp);
					}
				});
			});
		}
		else {
			if (!bHasDefinition)
				return handleResult("no definition");
			try {
				if (objectHash.getChash160(objAuthor.definition) !== objAuthor.address)
					return handleResult("wrong definition: " + objectHash.getChash160(objAuthor.definition) + "!==" + objAuthor.address);
			} catch (e) {
				return handleResult("failed to calc address definition hash: " + e);
			}
			// no last_ball_unit of its own; before the fix, always behave as before (-1) to keep old units re-evaluating the same way
			cb(objAuthor.definition, (mci >= constants.pemCurvesFixMci) ? mci : -1, 0);
		}
	}
```

**File:** formula/evaluation.js (L1684-1699)
```javascript
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
```

**File:** test/samples/order_book_exchange.oscript (L1-65)
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
